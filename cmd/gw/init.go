package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/am1nr/gateway/internal/jsonx"
	"github.com/am1nr/gateway/internal/share"
)

// detected is a best-effort read of the current network setup, used as defaults
// so the interview is mostly pressing enter.
type detected struct {
	WANIf    string
	Router   string
	LANCidr  string
	StaticIP string
	Prefix   int
}

var defaultRouteRE = regexp.MustCompile(`default via (\S+) dev (\S+)`)

func detect() detected {
	d := detected{WANIf: "eth0", Prefix: 24}

	if out, err := exec.Command("ip", "-4", "route", "show", "default").Output(); err == nil {
		if m := defaultRouteRE.FindStringSubmatch(string(out)); m != nil {
			d.Router, d.WANIf = m[1], m[2]
		}
	}

	iface, err := net.InterfaceByName(d.WANIf)
	if err != nil {
		return d
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return d
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		d.StaticIP = ipnet.IP.String()
		d.Prefix = ones
		if prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", d.StaticIP, ones)); err == nil {
			d.LANCidr = prefix.Masked().String()
		}
		break
	}
	return d
}

// cmdInit builds gateway.toml by interview.
//
// It parses a share link rather than asking anyone to transcribe XHTTP
// parameters by hand, which is where these setups usually go wrong.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)
	ask := func(prompt, def string) string {
		suffix := ""
		if def != "" {
			suffix = " [" + def + "]"
		}
		fmt.Printf("%s%s: ", prompt, suffix)
		line, err := in.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			return def
		}
		if v := strings.TrimSpace(line); v != "" {
			return v
		}
		return def
	}

	if _, err := os.Stat(f.paths.Config); err == nil {
		if ask(fmt.Sprintf("%s exists. Overwrite? (yes/no)", f.paths.Config), "no") != "yes" {
			fmt.Println("keeping the existing config")
			return nil
		}
	}

	d := detect()
	fmt.Println("\n-- network --")
	fmt.Println("Detected from the running system; correct anything that's wrong.")
	fmt.Println()
	wanIf := ask("interface facing the router", d.WANIf)
	lan := ask("LAN CIDR", orDefault(d.LANCidr, "192.168.1.0/24"))
	router := ask("router IP", orDefault(d.Router, "192.168.1.1"))
	staticIP := ask("static IP for this box (must be OUTSIDE the router's DHCP pool)", d.StaticIP)

	lanPrefix, err := netip.ParsePrefix(lan)
	if err != nil {
		return fmt.Errorf("%q is not a valid CIDR", lan)
	}
	// Caught here rather than at the first apply: a static IP outside the LAN
	// produces a box that cannot reach its own router, and the error at that
	// point says nothing about this answer.
	if addr, err := netip.ParseAddr(staticIP); err != nil {
		return fmt.Errorf("%q is not a valid IP address", staticIP)
	} else if !lanPrefix.Masked().Contains(addr) {
		return fmt.Errorf("the static IP %s is not inside %s", staticIP, lan)
	}
	if _, err := netip.ParseAddr(router); err != nil {
		return fmt.Errorf("%q is not a valid IP address", router)
	}

	fmt.Println("\n-- xray --")
	fmt.Println("Paste the share link from your server (vless://, vmess://, trojan:// or ss://).")
	fmt.Println()
	var parsed *share.Result
	for parsed == nil {
		link := ask("share link", "")
		if link == "" {
			return fmt.Errorf("aborted")
		}
		result, err := share.Parse(link)
		if err != nil {
			fmt.Printf("  %v\n", err)
			continue
		}
		parsed = result
	}
	fmt.Printf("  parsed: %s %s:%d\n", parsed.Protocol, parsed.Address, parsed.Port)

	resolved := ask("pin the server's IP? (removes the boot-time DNS dependency; blank to skip)", "")
	if resolved != "" {
		if _, err := netip.ParseAddr(resolved); err != nil {
			return fmt.Errorf("%q is not a valid IP address", resolved)
		}
	}

	fmt.Println("\n-- misc --")
	tz := ask("timezone", "Asia/Tehran")

	// The outbound is written as its own JSON file; gateway.toml only points at
	// it. Everything downstream treats that file as opaque.
	obDir := filepath.Join(f.paths.Repo, "outbounds")
	if err := os.MkdirAll(obDir, 0o755); err != nil {
		return err
	}
	obPath := filepath.Join(obDir, "main.json")
	write := true
	if _, err := os.Stat(obPath); err == nil {
		write = ask(fmt.Sprintf("%s exists. Overwrite?", obPath), "yes") == "yes"
	}
	if write {
		body, err := jsonx.EncodeIndented(parsed.Outbound)
		if err != nil {
			return err
		}
		// 0600 before any content lands in it: this file holds the credentials
		// that reach the server.
		fh, err := os.OpenFile(obPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := fh.Write(body); err != nil {
			fh.Close()
			return err
		}
		fh.Close()
		if err := os.Chmod(obPath, 0o600); err != nil {
			return err
		}
		fmt.Printf("\nwrote %s (0600 — it holds your credentials)\n", obPath)
	} else {
		fmt.Printf("keeping %s\n", obPath)
	}

	template, err := os.ReadFile(filepath.Join(f.paths.Repo, "gateway.example.toml"))
	if err != nil {
		return fmt.Errorf("reading the example config: %w", err)
	}
	out, err := fillTemplate(string(template), map[string]string{
		`wan_if     = "eth0"`:              fmt.Sprintf("wan_if     = %q", wanIf),
		`lan_cidr   = "192.168.1.0/24"`:    fmt.Sprintf("lan_cidr   = %q", lanPrefix.Masked().String()),
		`router     = "192.168.1.1"`:       fmt.Sprintf("router     = %q", router),
		`static_ip  = "192.168.1.2"`:       fmt.Sprintf("static_ip  = %q", staticIP),
		`prefix_len = 24`:                  fmt.Sprintf("prefix_len = %d", lanPrefix.Bits()),
		`timezone         = "Asia/Tehran"`: fmt.Sprintf("timezone         = %q", tz),
		`server_ip = ""`:                   fmt.Sprintf("server_ip = %q", resolved),
	})
	if err != nil {
		return err
	}

	// The example ships two illustrative clients; they are almost certainly not
	// this LAN's devices, and leaving them in means the first apply installs
	// policy for addresses nobody has.
	out = exampleClientRE.ReplaceAllString(out, "")

	if err := os.WriteFile(f.paths.Config, []byte(out), 0o644); err != nil {
		return err
	}
	fmt.Printf("\nwrote %s\n", f.paths.Config)
	fmt.Println("Next:")
	fmt.Println("  gw client add <ip> <name> proxy   # for each device that opts in")
	fmt.Println("  sudo scripts/00-bootstrap.sh")
	return nil
}

var exampleClientRE = regexp.MustCompile(
	`\[\[client\]\]\nip     = "192\.168\.1\.\d+"\nname   = "[^"]+"\npolicy = "[\w-]+"\n\n?`)

// fillTemplate replaces each anchor exactly once, and refuses to continue if one
// is missing.
//
// The Python warned and carried on, which produces a config that looks written
// but still carries an example value — a static IP of 192.168.1.2 on a LAN that
// is not 192.168.1.0/24 is a box that never comes up, and nothing says why.
func fillTemplate(template string, subs map[string]string) (string, error) {
	var missing []string
	for old := range subs {
		if !strings.Contains(template, old) {
			missing = append(missing, old)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("gateway.example.toml no longer contains these lines, so "+
			"the generated config would keep example values:\n  %s",
			strings.Join(missing, "\n  "))
	}
	for old, new := range subs {
		template = strings.Replace(template, old, new, 1)
	}
	return template, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
