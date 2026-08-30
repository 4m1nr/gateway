// Package edit rewrites gateway.toml in place.
//
// gateway.toml is the single source of truth and it is also a file a person
// reads and edits, so it keeps its comments and its layout. Nothing here
// re-serialises the whole document: entries this tool owns are edited
// textually, and everything else in the file is left exactly as written.
package edit

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
)

// An entry is found by its header and read key by key, rather than by matching
// the exact block this package writes.
//
// The strict pattern was a format assumption, not a design: any [[client]] is
// a client the gateway enforces, however it is spaced or ordered. Entries
// written by hand — or by an older version — were invisible to the dashboard
// and to `gw client list` while the firewall applied them, and adding one that
// already existed appended a second entry for the same address instead of
// replacing it, which config.Load then rejected as a duplicate.
var (
	// The header of an array-of-tables entry, with an optional trailing comment.
	clientHeader = regexp.MustCompile(`(?m)^\[\[client\]\][ \t]*(?:#.*)?$`)
	// Where the entry ends: the next table header at column 0.
	nextTable = regexp.MustCompile(`(?m)^\[`)
	// key = "value", tolerating any spacing and a trailing comment.
	clientKey = regexp.MustCompile(
		`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_-]*)[ \t]*=[ \t]*"([^"]*)"[ \t]*(?:#.*)?$`)
)

// Client is one per-address policy override.
type Client struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Policy string `json:"policy"`
	// Editable reports whether this entry can be rewritten from here. False
	// when the block holds something this package does not model, since
	// rewriting it in the canonical three-key form would drop that silently.
	// Such an entry is still listed: the gateway enforces it either way, and a
	// client list that hides a live override is worse than a read-only row.
	Editable bool `json:"editable"`
}

// block is one [[client]] entry and its extent in the file.
type block struct {
	start, end int // byte offsets: the whole entry, header included
	client     Client
}

// Clients returns every [[client]] entry, sorted by address.
func Clients(path string) ([]Client, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseClients(string(text)), nil
}

func parseClients(text string) []Client {
	blocks := clientBlocks(text)
	out := make([]Client, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, b.client)
	}
	sort.Slice(out, func(i, j int) bool {
		a, errA := netip.ParseAddr(out[i].IP)
		b, errB := netip.ParseAddr(out[j].IP)
		if errA != nil || errB != nil {
			return out[i].IP < out[j].IP
		}
		return a.Less(b)
	})
	return out
}

// clientBlocks finds every [[client]] entry in file order.
func clientBlocks(text string) []block {
	var out []block
	for _, loc := range clientHeader.FindAllStringIndex(text, -1) {
		start, bodyAt := loc[0], loc[1]
		end := len(text)
		// The entry runs to the next table header, which is the next line
		// starting with "[" — the header just matched is excluded by searching
		// from after it.
		if rel := nextTable.FindStringIndex(text[bodyAt:]); rel != nil {
			end = bodyAt + rel[0]
		}

		c := Client{Editable: true}
		body := text[bodyAt:end]
		for _, kv := range clientKey.FindAllStringSubmatch(body, -1) {
			switch kv[1] {
			case "ip":
				c.IP = kv[2]
			case "name":
				c.Name = kv[2]
			case "policy":
				c.Policy = kv[2]
			default:
				// A key with meaning this package does not know. Listing the
				// entry is right; rewriting it is not.
				c.Editable = false
			}
		}
		// Anything that is not blank, a comment, or a quoted key = value: an
		// unquoted value, a nested table, a multi-line string. Same reasoning.
		for _, line := range strings.Split(body, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if !clientKey.MatchString(line) {
				c.Editable = false
			}
		}
		if c.IP == "" {
			continue // not a client entry we can identify at all
		}
		out = append(out, block{start: start, end: end, client: c})
	}
	return out
}

// findClient returns the entry for an address, if the file has one.
func findClient(text, ip string) (block, bool) {
	for _, b := range clientBlocks(text) {
		if b.client.IP == ip {
			return b, true
		}
	}
	return block{}, false
}

// format renders an entry in the canonical form.
func format(c Client) string {
	return fmt.Sprintf("[[client]]\nip     = %q\nname   = %q\npolicy = %q\n",
		c.IP, c.Name, c.Policy)
}

// AddClient adds or replaces a client, and reports the policy it replaced.
func AddClient(path string, c Client) (replaced string, err error) {
	if _, err := netip.ParseAddr(c.IP); err != nil {
		return "", fmt.Errorf("%q is not a valid IP address", c.IP)
	}
	if strings.ContainsAny(c.Name, `"`+"\n") {
		return "", fmt.Errorf("a client name cannot contain a quote or a newline")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := string(raw)

	if b, found := findClient(text, c.IP); found {
		if !b.client.Editable {
			return "", fmt.Errorf("%s is already listed in %s in a form this tool "+
				"does not rewrite — it holds settings beyond ip, name and policy. "+
				"Edit that entry in the file instead; rewriting it from here would "+
				"drop them", c.IP, path)
		}
		// Replaced in place rather than moved to the end: the entry keeps its
		// position, and the comment above it goes on describing the device it
		// was written for.
		replaced = b.client.Policy
		text = text[:b.start] + format(c) + text[b.end:]
		return replaced, writeFile(path, text)
	}

	text = strings.TrimRight(text, "\n") + "\n\n" + format(c)
	return "", writeFile(path, text)
}

// RemoveClient deletes a client. Removing one that is not listed is an error:
// silently succeeding would make a typo look like it worked.
func RemoveClient(path, ip string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)
	b, found := findClient(text, ip)
	if !found {
		return fmt.Errorf("%s is not in %s", ip, path)
	}
	if !b.client.Editable {
		return fmt.Errorf("%s is listed in %s in a form this tool does not "+
			"rewrite — it holds settings beyond ip, name and policy. Remove that "+
			"entry in the file instead", ip, path)
	}
	// Take the blank line the entry left behind with it, so repeated add and
	// remove cycles do not slowly space the file out.
	end := b.end
	for end < len(text) && text[end] == '\n' {
		end++
	}
	if end > b.end && b.start > 0 {
		end = b.end + 1
	}
	return writeFile(path, text[:b.start]+text[end:])
}

// writeFile replaces the config through a temp file in the same directory.
//
// gateway.toml is the only description of the gateway that survives a rebuild.
// Truncating it and failing mid-write — a full disk, a killed process — would
// leave the box with no config at all, so the replacement is atomic.
func writeFile(path, text string) error {
	dir, base := splitDir(path)
	tmp, err := os.CreateTemp(dir, "."+base+".gw-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Preserve the existing permissions; a fresh temp file is 0600 and
	// gateway.toml is normally group-readable in the checkout.
	if st, err := os.Stat(path); err == nil {
		if err := os.Chmod(name, st.Mode().Perm()); err != nil {
			return err
		}
	}
	return os.Rename(name, path)
}

func splitDir(path string) (dir, base string) {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return ".", path
	}
	return path[:i], path[i+1:]
}
