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

// clientBlock matches one [[client]] entry as this package writes them.
//
// [\w-] rather than \w for the policy: profile names may contain hyphens, and
// \w silently fails to match them — which once made profile clients invisible
// to list and rm, and made add duplicate an entry instead of replacing it.
var clientBlock = regexp.MustCompile(
	`\n?\[\[client\]\]\nip     = "(?P<ip>[^"]+)"\nname   = "(?P<name>[^"]*)"\n` +
		`policy = "(?P<policy>[\w-]+)"\n`)

// Client is one per-address policy override.
type Client struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Policy string `json:"policy"`
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
	var out []Client
	for _, m := range clientBlock.FindAllStringSubmatch(text, -1) {
		out = append(out, Client{IP: m[1], Name: m[2], Policy: m[3]})
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

	for _, loc := range clientBlock.FindAllStringSubmatchIndex(text, -1) {
		ip := text[loc[2]:loc[3]]
		if ip != c.IP {
			continue
		}
		replaced = text[loc[6]:loc[7]]
		text = text[:loc[0]] + text[loc[1]:]
		break
	}

	text = strings.TrimRight(text, "\n") + fmt.Sprintf(
		"\n\n[[client]]\nip     = %q\nname   = %q\npolicy = %q\n", c.IP, c.Name, c.Policy)
	return replaced, writeFile(path, text)
}

// RemoveClient deletes a client. Removing one that is not listed is an error:
// silently succeeding would make a typo look like it worked.
func RemoveClient(path, ip string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)
	for _, loc := range clientBlock.FindAllStringSubmatchIndex(text, -1) {
		if text[loc[2]:loc[3]] != ip {
			continue
		}
		return writeFile(path, text[:loc[0]]+text[loc[1]:])
	}
	return fmt.Errorf("%s is not in %s", ip, path)
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
