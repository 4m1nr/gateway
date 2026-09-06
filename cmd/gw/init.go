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
	// LANIf is a second wired card, when the box has one. Its presence is what
	// makes the two-armed question worth asking at all.
	LANIf string
}

var defaultRouteRE = regexp.MustCompile(`default via (\S+) dev (\S+)`)

// virtualIf matches interfaces that are never a card in a wall: tunnels this
// gateway creates itself, container bridges, wireless. Offering one of these as
// "the LAN side" would produce a box that comes up on nothing.
var virtualIf = regexp.MustCompile(`^(lo|tailscale|docker|veth|br-|virbr|wg|tun|tap|wl)`)

func detect() detected {
	d := detected{WANIf: "eth0", Prefix: 24}

	if out, err := exec.Command("ip", "-4", "route", "show", "default").Output(); err == nil {
		if m := defaultRouteRE.FindStringSubmatch(string(out)); m != nil {
			d.Router, d.WANIf = m[1], m[2]
		}
	}
	d.LANIf = otherWiredIf(d.WANIf)

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

// otherWiredIf returns the first real card that is not the uplink, or "".
func otherWiredIf(wan string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Name == wan || virtualIf.MatchString(iface.Name) {
			continue
		}
		return iface.Name
	}
	return ""
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

	// Only asked when there is a second card to answer with. On a thin client
	// with one NIC the question has no true answer and asking it invites a yes.
	twoArm := false
	if d.LANIf != "" {
		fmt.Printf("This box has more than one network card (%s, %s).\n", d.WANIf, d.LANIf)
		fmt.Println("Two-armed means one card faces the office LAN and one faces the")
		fmt.Println("internet, and every device on the LAN goes through this box whether")
		fmt.Println("it opts in or not. One-armed means the box sits beside the router on")
		fmt.Println("a single segment and devices opt in by pointing at it.")
		fmt.Println()
		twoArm = ask("two-armed setup? (yes/no)", "no") == "yes"
	}

	answers := netAnswers{}
	var err error
	if twoArm {
		err = askTwoArm(ask, d, &answers)
	} else {
		err = askOneArm(ask, d, &answers)
	}
	if err != nil {
		return err
	}
	lanPrefix := answers.LANPrefix

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
	subs := map[string]string{
		`wan_if     = "eth0"`:              fmt.Sprintf("wan_if     = %q", answers.WANIf),
		`lan_cidr   = "192.168.1.0/24"`:    fmt.Sprintf("lan_cidr   = %q", lanPrefix.Masked().String()),
		`static_ip  = "192.168.1.2"`:       fmt.Sprintf("static_ip  = %q", answers.StaticIP),
		`prefix_len = 24`:                  fmt.Sprintf("prefix_len = %d", lanPrefix.Bits()),
		`timezone         = "Asia/Tehran"`: fmt.Sprintf("timezone         = %q", tz),
		`server_ip = ""`:                   fmt.Sprintf("server_ip = %q", resolved),
	}
	// The two-armed keys ship commented out, so writing them is uncommenting
	// them. Anything not named here keeps the example's own explanation of what
	// it would do, which is the point of generating from that file.
	if answers.LANIf != "" {
		subs[`#lan_if     = "eth1"`] = fmt.Sprintf("lan_if     = %q", answers.LANIf)
	}
	if answers.WANDHCP {
		subs[`#wan_dhcp   = true`] = "wan_dhcp   = true"
		// The lease carries the gateway, and naming one as well is rejected.
		subs[`router     = "192.168.1.1"`] = "# router comes from the DHCP lease on wan_if"
	} else {
		subs[`router     = "192.168.1.1"`] = fmt.Sprintf("router     = %q", answers.Router)
		if answers.LANIf != "" {
			subs[`#wan_ip          = "10.0.0.2"`] = fmt.Sprintf("wan_ip          = %q", answers.WANIP)
			subs[`#wan_prefix_len  = 24`] = fmt.Sprintf("wan_prefix_len  = %d", answers.WANPrefix)
		}
	}

	out, err := fillTemplate(string(template), subs)
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

// netAnswers is what the network half of the interview produced, in the shape
// gateway.toml wants it.
type netAnswers struct {
	WANIf     string
	LANIf     string // empty single-armed
	LANPrefix netip.Prefix
	StaticIP  string
	Router    string
	WANDHCP   bool
	WANIP     string
	WANPrefix int
}

// asker is the interview's prompt, threaded through so these read as questions
// rather than as I/O.
type asker func(prompt, def string) string

// askOneArm is the original interview: one card, one segment, the box beside
// the router.
func askOneArm(ask asker, d detected, out *netAnswers) error {
	out.WANIf = ask("interface facing the router", d.WANIf)
	lan := ask("LAN CIDR", orDefault(d.LANCidr, "192.168.1.0/24"))
	out.Router = ask("router IP", orDefault(d.Router, "192.168.1.1"))
	out.StaticIP = ask("static IP for this box (must be OUTSIDE the router's DHCP pool)", d.StaticIP)

	prefix, err := netip.ParsePrefix(lan)
	if err != nil {
		return fmt.Errorf("%q is not a valid CIDR", lan)
	}
	out.LANPrefix = prefix
	// Caught here rather than at the first apply: a static IP outside the LAN
	// produces a box that cannot reach its own router, and the error at that
	// point says nothing about this answer.
	if err := insideLAN(out.StaticIP, "static IP", prefix); err != nil {
		return err
	}
	if err := insideLAN(out.Router, "router IP", prefix); err != nil {
		return err
	}
	return nil
}

// askTwoArm is the office setup: a card on each side, the box between them.
//
// The static IP means something different here and the prompts say so — it
// becomes the LAN's gateway rather than one more address on it, so .1 is the
// natural answer where .2 was before.
func askTwoArm(ask asker, d detected, out *netAnswers) error {
	out.WANIf = ask("interface facing the internet", d.WANIf)
	out.LANIf = ask("interface facing the office LAN", d.LANIf)
	if out.LANIf == out.WANIf {
		return fmt.Errorf("both sides cannot be %s — a two-armed gateway needs two cards", out.LANIf)
	}

	fmt.Println()
	fmt.Println("The LAN side. This box becomes the gateway for it, so whatever")
	fmt.Println("serves DHCP there has to hand out the address below as BOTH the")
	fmt.Println("gateway and the DNS server.")
	lan := ask("LAN CIDR", "192.168.10.0/24")
	prefix, err := netip.ParsePrefix(lan)
	if err != nil {
		return fmt.Errorf("%q is not a valid CIDR", lan)
	}
	out.LANPrefix = prefix
	out.StaticIP = ask("this box's address on the LAN (its gateway)",
		firstHost(prefix))
	if err := insideLAN(out.StaticIP, "the LAN address", prefix); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("The internet side.")
	out.WANDHCP = ask("take the uplink address from DHCP? (yes/no)", "yes") == "yes"
	if out.WANDHCP {
		return nil
	}
	out.WANIP = ask("this box's address on the uplink", orDefault(d.StaticIP, "10.0.0.2"))
	wan, err := netip.ParseAddr(out.WANIP)
	if err != nil {
		return fmt.Errorf("%q is not a valid IP address", out.WANIP)
	}
	out.WANPrefix = 24
	if _, err := fmt.Sscanf(ask("uplink prefix length", "24"), "%d", &out.WANPrefix); err != nil {
		return fmt.Errorf("the uplink prefix length must be a number")
	}
	out.Router = ask("the upstream router (this box's default gateway)",
		orDefault(d.Router, "10.0.0.1"))
	router, err := netip.ParseAddr(out.Router)
	if err != nil {
		return fmt.Errorf("%q is not a valid IP address", out.Router)
	}
	uplink := netip.PrefixFrom(wan, out.WANPrefix).Masked()
	if !uplink.IsValid() {
		return fmt.Errorf("%d is not a valid prefix length for %s", out.WANPrefix, out.WANIP)
	}
	if !uplink.Contains(router) {
		return fmt.Errorf("the router %s is not inside the uplink network %s",
			out.Router, uplink)
	}
	if prefix.Masked().Contains(uplink.Addr()) || uplink.Contains(prefix.Masked().Addr()) {
		return fmt.Errorf("the LAN %s and the uplink %s overlap — "+
			"the two sides have to be different networks", prefix.Masked(), uplink)
	}
	return nil
}

// insideLAN rejects an address that is not on the segment it was given for.
func insideLAN(value, label string, prefix netip.Prefix) error {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("%q is not a valid IP address", value)
	}
	if !prefix.Masked().Contains(addr) {
		return fmt.Errorf("%s %s is not inside %s", label, value, prefix.Masked())
	}
	return nil
}

// firstHost suggests x.x.x.1 for a network, which is where a gateway
// conventionally lives.
func firstHost(prefix netip.Prefix) string {
	addr := prefix.Masked().Addr().Next()
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
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
