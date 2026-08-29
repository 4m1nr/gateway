package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/am1nr/gateway/internal/jsonx"
)

// placeholderUUID is what outbounds/main.example.json ships with. An outbound
// still carrying it has not been filled in, and the tunnel would fail at
// handshake time with an error that says nothing about the real cause.
const placeholderUUID = "00000000-0000-0000-0000-000000000000"

// Outbound is a complete Xray outbound object plus what the gateway derived
// from it. The JSON is used verbatim; the gateway owns exactly two fields
// inside it, and both are enforced here rather than trusted.
type Outbound struct {
	Tag string
	// Object is the Xray outbound, with the gateway's two fields applied.
	Object *jsonx.Object
	// Address is the server hostname or IP, for DNS pinning. Empty when the
	// outbound's shape is one this code does not recognise; the config can
	// name it explicitly with server_domain.
	Address string
	// ResolvedIP pins Address in Xray's DNS hosts map, so the tunnel never
	// depends on a DNS lookup to come up.
	ResolvedIP string
	// Origin is the file path or config key the JSON came from, for errors.
	Origin string
}

// outboundAddress makes a best-effort guess at the server address, for DNS
// pinning only. It covers the shapes Xray actually uses — vnext for
// vless/vmess, servers for trojan/shadowsocks/socks. Anything else returns
// empty, and the config can name the host explicitly with server_domain.
func outboundAddress(ob *jsonx.Object) string {
	settings, ok := ob.GetObject("settings")
	if !ok {
		return ""
	}
	for _, key := range []string{"vnext", "servers"} {
		entries, ok := settings.GetArray(key)
		if !ok || len(entries) == 0 {
			continue
		}
		first, ok := entries[0].(*jsonx.Object)
		if !ok {
			continue
		}
		if addr, ok := first.GetString("address"); ok && addr != "" {
			return addr
		}
	}
	return ""
}

// loadOutbound reads a complete Xray outbound object, verbatim.
//
// The gateway does not model protocols or transports — whatever Xray supports,
// you can paste. What it does own, and always applies, is the part that makes
// the outbound safe to use here:
//
//	tag           routing rules reference it, so the gateway assigns it
//	sockopt.mark  the loop guard; without it the box routes its own tunnel
//	              traffic back into the tunnel and wedges
func (c *Config) loadOutbound(spec map[string]any, where, tag string) (*Outbound, error) {
	inline := str(spec, "json", "")
	path := str(spec, "file", "")
	if (inline != "") == (path != "") {
		return nil, errf("%s: set exactly one of `file` (path to a .json outbound) "+
			"or `json` (the outbound inline)", where)
	}

	var text, origin string
	if path != "" {
		src := path
		if !filepath.IsAbs(src) {
			src = filepath.Join(filepath.Dir(c.Path), path)
		}
		src, err := filepath.Abs(src)
		if err != nil {
			return nil, errf("%s.file: %v", where, err)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, errf("%s.file: %v", where, err)
		}
		text, origin = string(data), src
	} else {
		text, origin = inline, where+".json"
	}

	ob, err := jsonx.DecodeObject([]byte(text))
	if err != nil {
		// Distinguish "not JSON at all" from "JSON, but not one object": a list
		// is the common paste mistake and deserves its own sentence.
		if strings.Contains(err.Error(), "expected a JSON object") {
			return nil, errf("%s: expected a single outbound object "+
				`(starting with {"protocol": ...}), not a list or bare value`, origin)
		}
		return nil, errf("%s: not valid JSON — %v", origin, err)
	}

	if strings.Contains(text, placeholderUUID) {
		return nil, errf("%s still contains the placeholder UUID from the example "+
			"outbound. Put your real server details in it.", origin)
	}
	if _, ok := ob.GetString("protocol"); !ok {
		return nil, errf(`%s: outbound has no "protocol" field`, origin)
	}
	if ob.Has("outbounds") || ob.Has("inbounds") {
		return nil, errf("%s: this looks like a whole Xray config. Use just one "+
			`entry from its "outbounds" array.`, origin)
	}

	if existing, ok := ob.GetString("tag"); ok && existing != tag {
		// Not fatal, but silently renaming would be worse: routing rules
		// generated elsewhere reference the tag we assign.
		fmt.Fprintf(os.Stderr, "note: %s has tag %q; the gateway uses %q\n", origin, existing, tag)
	}
	ob.Set("tag", tag)

	stream, err := ob.EnsureObject("streamSettings")
	if err != nil {
		return nil, errf("%s: streamSettings must be an object", origin)
	}
	sock, err := stream.EnsureObject("sockopt")
	if err != nil {
		return nil, errf("%s: streamSettings.sockopt must be an object", origin)
	}

	// A mark that disagrees with the firewall is rejected rather than silently
	// overwritten. This is the highest-consequence check in the config: an
	// outbound whose packets are not exempt from TPROXY makes Xray re-capture
	// its own traffic, and the box deadlocks the moment interception is on.
	if raw, ok := sock.Get("mark"); ok {
		mark, err := asInt(raw)
		if err != nil {
			return nil, errf("%s: sockopt.mark must be an integer", origin)
		}
		if mark != c.OutboundMark {
			return nil, errf("%s: sockopt.mark is %d, but the firewall "+
				"exempts %d. A different mark means Xray's own "+
				"packets get re-captured by TPROXY and the gateway deadlocks. "+
				"Remove it, or change xray.outbound_mark to match.",
				origin, mark, c.OutboundMark)
		}
	}
	sock.Set("mark", json.Number(fmt.Sprint(c.OutboundMark)))

	domainStrategy := "UseIP"
	if c.IPv6Mode == "off" {
		domainStrategy = "UseIPv4"
	}
	sock.SetDefault("domainStrategy", domainStrategy)

	// Performance knobs, only if the outbound has not set them itself — a
	// pasted outbound stays authoritative about its own transport.
	if c.TCPCongestion != "" {
		sock.SetDefault("tcpcongestion", c.TCPCongestion)
	}
	if c.TCPNoDelay {
		sock.SetDefault("tcpNoDelay", true)
	}

	serverIP := strings.TrimSpace(str(spec, "server_ip", ""))
	if serverIP != "" {
		if _, err := netip.ParseAddr(serverIP); err != nil {
			return nil, errf("%s.server_ip: %q is not a valid IP address", where, serverIP)
		}
	}

	address := str(spec, "server_domain", "")
	if address == "" {
		address = outboundAddress(ob)
	}

	return &Outbound{
		Tag:        tag,
		Object:     ob,
		Address:    address,
		ResolvedIP: serverIP,
		Origin:     origin,
	}, nil
}

// asInt accepts the numeric shapes JSON can produce for an integer field.
func asInt(v any) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil || f != float64(int64(f)) {
				return 0, fmt.Errorf("not an integer: %s", n)
			}
			return int(int64(f)), nil
		}
		return int(i), nil
	case int64:
		return int(n), nil
	case int:
		return n, nil
	}
	return 0, fmt.Errorf("not a number")
}
