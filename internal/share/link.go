// Package share turns a proxy share link into a complete Xray outbound object.
//
// The gateway does not model protocols or transports — an outbound is whatever
// Xray accepts, pasted verbatim. This package exists only so that setting one
// up is still a one-paste operation: it reads the link formats people actually
// receive and writes the JSON they would otherwise transcribe by hand, which is
// where these setups usually go wrong.
package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/am1nr/gateway/internal/jsonx"
)

// Result is a parsed link.
type Result struct {
	// Outbound is the Xray outbound object, without a tag: the gateway assigns
	// that, because routing rules reference it.
	Outbound *jsonx.Object
	// Name is the link's fragment, the label the provider gave it.
	Name string
	// Protocol is vless, vmess, trojan or shadowsocks.
	Protocol string
	// Address and Port are the server, surfaced so the caller can offer to pin
	// the address without re-parsing the JSON.
	Address string
	Port    int
}

// Parse reads any supported share link.
func Parse(link string) (*Result, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, fmt.Errorf("that does not look like a share link — expected one " +
			"of vless://, vmess://, trojan:// or ss://")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "trojan":
		return parseTrojan(link)
	case "ss":
		return parseShadowsocks(link)
	}
	return nil, fmt.Errorf("unsupported link type %q — expected vless, vmess, trojan or ss", scheme)
}

// ---------------------------------------------------------------- vless ----

func parseVLESS(link string) (*Result, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("could not parse the link: %w", err)
	}
	id := ""
	if u.User != nil {
		id = u.User.Username()
	}
	if id == "" {
		return nil, fmt.Errorf("the link has no UUID before the @")
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return nil, err
	}
	q := query(u)

	user := obj("id", id, "encryption", def(q["encryption"], "none"))
	// XTLS flow control, only meaningful on a raw TCP transport with Reality or
	// TLS. Carried through when present rather than interpreted.
	if flow := q["flow"]; flow != "" {
		user.Set("flow", flow)
	}

	out := obj(
		"protocol", "vless",
		"settings", obj("vnext", []any{obj(
			"address", host,
			"port", json.Number(strconv.Itoa(port)),
			"users", []any{user},
		)}),
		"streamSettings", streamSettings(q, host),
	)
	return &Result{Outbound: out, Name: fragment(u), Protocol: "vless", Address: host, Port: port}, nil
}

// ---------------------------------------------------------------- vmess ----

// vmessLink is the v2rayN base64-JSON format. Numeric fields arrive as either
// strings or numbers depending on which client produced the link, so they are
// decoded loosely and normalised here.
type vmessLink struct {
	V    any `json:"v"`
	PS   any `json:"ps"`
	Add  any `json:"add"`
	Port any `json:"port"`
	ID   any `json:"id"`
	Aid  any `json:"aid"`
	Scy  any `json:"scy"`
	Net  any `json:"net"`
	Type any `json:"type"`
	Host any `json:"host"`
	Path any `json:"path"`
	TLS  any `json:"tls"`
	SNI  any `json:"sni"`
	ALPN any `json:"alpn"`
	FP   any `json:"fp"`
}

func parseVMess(link string) (*Result, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	raw, err := decodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("the part after vmess:// is not valid base64: %w", err)
	}
	var v vmessLink
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("the link does not contain a v2rayN JSON payload: %w", err)
	}

	host := loose(v.Add)
	if host == "" {
		return nil, fmt.Errorf("the link has no server address")
	}
	port, err := strconv.Atoi(def(loose(v.Port), "443"))
	if err != nil {
		return nil, fmt.Errorf("port %q is not a number", loose(v.Port))
	}
	id := loose(v.ID)
	if id == "" {
		return nil, fmt.Errorf("the link has no UUID")
	}
	alterID, _ := strconv.Atoi(def(loose(v.Aid), "0"))

	// The vmess link format carries transport settings under different names
	// than a URL query does. Translating here keeps streamSettings one
	// implementation rather than two that drift.
	q := map[string]string{
		"type":       def(loose(v.Net), "tcp"),
		"security":   def(loose(v.TLS), "none"),
		"host":       loose(v.Host),
		"path":       loose(v.Path),
		"sni":        loose(v.SNI),
		"alpn":       loose(v.ALPN),
		"fp":         loose(v.FP),
		"headerType": loose(v.Type),
	}
	if q["security"] == "" {
		q["security"] = "none"
	}
	// grpc links put the service name in `path`.
	if q["type"] == "grpc" && q["path"] != "" {
		q["serviceName"] = q["path"]
	}

	out := obj(
		"protocol", "vmess",
		"settings", obj("vnext", []any{obj(
			"address", host,
			"port", json.Number(strconv.Itoa(port)),
			"users", []any{obj(
				"id", id,
				"alterId", json.Number(strconv.Itoa(alterID)),
				"security", def(loose(v.Scy), "auto"),
			)},
		)}),
		"streamSettings", streamSettings(q, host),
	)
	return &Result{Outbound: out, Name: loose(v.PS), Protocol: "vmess", Address: host, Port: port}, nil
}

// --------------------------------------------------------------- trojan ----

func parseTrojan(link string) (*Result, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("could not parse the link: %w", err)
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("the link has no password before the @")
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return nil, err
	}
	q := query(u)
	// Trojan is TLS by default; a link that omits `security` still means TLS.
	if q["security"] == "" {
		q["security"] = "tls"
	}

	out := obj(
		"protocol", "trojan",
		"settings", obj("servers", []any{obj(
			"address", host,
			"port", json.Number(strconv.Itoa(port)),
			"password", password,
		)}),
		"streamSettings", streamSettings(q, host),
	)
	return &Result{Outbound: out, Name: fragment(u), Protocol: "trojan", Address: host, Port: port}, nil
}

// ---------------------------------------------------------- shadowsocks ----

func parseShadowsocks(link string) (*Result, error) {
	rest := strings.TrimPrefix(link, "ss://")
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.QueryUnescape(rest[i+1:])
		rest = rest[:i]
	}
	// Query parameters (plugin, etc.) are not carried: the gateway would have
	// to model them, and the whole point is that it does not.
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}

	var method, password, host string
	var port int

	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		// SIP002: ss://base64(method:password)@host:port
		creds, err := decodeBase64(rest[:at])
		if err != nil {
			// Some clients leave the userinfo unencoded.
			decoded, uerr := url.QueryUnescape(rest[:at])
			if uerr != nil {
				return nil, fmt.Errorf("could not read the credentials: %w", err)
			}
			creds = []byte(decoded)
		}
		var ok bool
		method, password, ok = strings.Cut(string(creds), ":")
		if !ok {
			return nil, fmt.Errorf("credentials are not in method:password form")
		}
		var perr error
		host, port, perr = splitHostPort(rest[at+1:], 8388)
		if perr != nil {
			return nil, perr
		}
	} else {
		// Legacy: ss://base64(method:password@host:port)
		decoded, err := decodeBase64(rest)
		if err != nil {
			return nil, fmt.Errorf("the part after ss:// is not valid base64: %w", err)
		}
		creds, hostport, ok := strings.Cut(string(decoded), "@")
		if !ok {
			return nil, fmt.Errorf("the decoded link is not method:password@host:port")
		}
		method, password, ok = strings.Cut(creds, ":")
		if !ok {
			return nil, fmt.Errorf("credentials are not in method:password form")
		}
		host, port, err = splitHostPort(hostport, 8388)
		if err != nil {
			return nil, err
		}
	}

	out := obj(
		"protocol", "shadowsocks",
		"settings", obj("servers", []any{obj(
			"address", host,
			"port", json.Number(strconv.Itoa(port)),
			"method", method,
			"password", password,
		)}),
	)
	return &Result{Outbound: out, Name: name, Protocol: "shadowsocks", Address: host, Port: port}, nil
}

// -------------------------------------------------------- streamSettings ----

// streamSettings builds the transport section from a link's query parameters.
//
// Every transport Xray supports is handled the same way: read the parameters
// that transport uses, and leave the rest alone. Nothing here validates against
// a list of "supported" transports, because the gateway supports whatever Xray
// does.
func streamSettings(q map[string]string, host string) *jsonx.Object {
	network := def(q["type"], "tcp")
	security := q["security"]
	if security == "" || security == "none" {
		security = "none"
	}

	stream := obj("network", network, "security", security)

	switch network {
	case "ws":
		ws := obj("path", def(q["path"], "/"))
		if h := def(q["host"], ""); h != "" {
			ws.Set("headers", obj("Host", h))
		}
		stream.Set("wsSettings", ws)
	case "xhttp", "splithttp":
		// Normalised: splithttp was renamed to xhttp upstream, and links in the
		// wild still carry the old name.
		stream.Set("network", "xhttp")
		x := obj(
			"host", def(q["host"], host),
			"path", def(q["path"], "/"),
			"mode", def(q["mode"], "auto"),
		)
		if p := q["xPaddingBytes"]; p != "" {
			x.Set("xPaddingBytes", p)
		}
		stream.Set("xhttpSettings", x)
	case "httpupgrade":
		up := obj("path", def(q["path"], "/"))
		if h := def(q["host"], ""); h != "" {
			up.Set("host", h)
		}
		stream.Set("httpupgradeSettings", up)
	case "grpc":
		g := obj("serviceName", def(q["serviceName"], q["path"]))
		if q["mode"] == "multi" {
			g.Set("multiMode", true)
		}
		if a := q["authority"]; a != "" {
			g.Set("authority", a)
		}
		stream.Set("grpcSettings", g)
	case "h2", "http":
		stream.Set("network", "http")
		h := obj("path", def(q["path"], "/"))
		if hv := def(q["host"], ""); hv != "" {
			h.Set("host", splitCSV(hv))
		}
		stream.Set("httpSettings", h)
	case "kcp", "mkcp":
		stream.Set("network", "kcp")
		k := obj("header", obj("type", def(q["headerType"], "none")))
		if seed := q["seed"]; seed != "" {
			k.Set("seed", seed)
		}
		stream.Set("kcpSettings", k)
	case "tcp":
		// An HTTP-disguised TCP transport carries its parameters the same way a
		// real HTTP one does.
		if q["headerType"] == "http" {
			req := obj("path", []any{def(q["path"], "/")})
			if hv := def(q["host"], ""); hv != "" {
				req.Set("headers", obj("Host", splitCSV(hv)))
			}
			stream.Set("tcpSettings", obj("header", obj("type", "http", "request", req)))
		}
	}

	switch security {
	case "tls":
		tls := obj("serverName", def(q["sni"], host))
		if fp := q["fp"]; fp != "" {
			tls.Set("fingerprint", fp)
		}
		if alpn := q["alpn"]; alpn != "" {
			tls.Set("alpn", splitCSV(alpn))
		}
		// allowInsecure is deliberately not carried from the link. A share link
		// asking to skip certificate verification is either a mistake or an
		// attack, and this gateway's whole job is to be the trustworthy hop.
		tls.Set("allowInsecure", false)
		stream.Set("tlsSettings", tls)
	case "reality":
		r := obj("serverName", def(q["sni"], host))
		if fp := q["fp"]; fp != "" {
			r.Set("fingerprint", fp)
		}
		if pbk := q["pbk"]; pbk != "" {
			r.Set("publicKey", pbk)
		}
		if sid := q["sid"]; sid != "" {
			r.Set("shortId", sid)
		}
		r.Set("spiderX", def(q["spx"], "/"))
		stream.Set("realitySettings", r)
	}
	return stream
}

// -------------------------------------------------------------- helpers ----

func obj(kv ...any) *jsonx.Object {
	o := jsonx.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

func query(u *url.URL) map[string]string {
	out := map[string]string{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func fragment(u *url.URL) string {
	if name, err := url.QueryUnescape(u.Fragment); err == nil {
		return name
	}
	return u.Fragment
}

func hostPort(u *url.URL, fallback int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("the link has no server address")
	}
	port := fallback
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("port %q is not valid", p)
		}
		port = n
	}
	return host, port, nil
}

func splitHostPort(s string, fallback int) (string, int, error) {
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return s, fallback, nil
	}
	n, err := strconv.Atoi(portStr)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("port %q is not valid", portStr)
	}
	return host, n, nil
}

// decodeBase64 accepts every variant these links appear in: standard or
// URL-safe alphabet, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

func def(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func splitCSV(s string) []any {
	var out []any
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	if out == nil {
		return []any{}
	}
	return out
}

// loose reads a JSON field that may be a string or a number.
func loose(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}
