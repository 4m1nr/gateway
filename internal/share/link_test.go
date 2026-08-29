package share

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/jsonx"
)

// mustParse parses and re-encodes so assertions run on the JSON Xray receives.
func mustParse(t *testing.T, link string) (*Result, string) {
	t.Helper()
	res, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	raw, err := json.Marshal(res.Outbound)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return res, string(raw)
}

func get(t *testing.T, o *jsonx.Object, path ...string) any {
	t.Helper()
	var cur any = o
	for _, key := range path {
		obj, ok := cur.(*jsonx.Object)
		if !ok {
			t.Fatalf("%v is not an object at %q", path, key)
		}
		v, ok := obj.Get(key)
		if !ok {
			t.Fatalf("no %q in %v", key, path)
		}
		cur = v
	}
	return cur
}

// The XHTTP link is the one this gateway was built around: getting a parameter
// wrong here is the classic way these setups fail, with a tunnel that connects
// and then carries nothing.
func TestVLESSOverXHTTP(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443" +
		"?type=xhttp&security=tls&path=%2Fxhttp&host=cdn.example.com&mode=auto" +
		"&sni=example.com&alpn=h2%2Chttp%2F1.1&fp=chrome#my%20server"
	res, raw := mustParse(t, link)

	if res.Protocol != "vless" || res.Address != "example.com" || res.Port != 443 {
		t.Errorf("got %+v", res)
	}
	if res.Name != "my server" {
		t.Errorf("name is %q, want %q", res.Name, "my server")
	}
	if got := get(t, res.Outbound, "streamSettings", "network"); got != "xhttp" {
		t.Errorf("network is %v", got)
	}
	if got := get(t, res.Outbound, "streamSettings", "xhttpSettings", "path"); got != "/xhttp" {
		t.Errorf("path is %v — a percent-encoded path was not decoded", got)
	}
	if got := get(t, res.Outbound, "streamSettings", "xhttpSettings", "host"); got != "cdn.example.com" {
		t.Errorf("host is %v", got)
	}
	if got := get(t, res.Outbound, "streamSettings", "tlsSettings", "serverName"); got != "example.com" {
		t.Errorf("serverName is %v", got)
	}
	// Ports must be numbers. A quoted port is a config Xray rejects.
	if !strings.Contains(raw, `"port":443`) {
		t.Errorf("port is not a JSON number:\n%s", raw)
	}
}

// splithttp was renamed to xhttp upstream, and links in the wild still carry
// the old name. Passing it through unchanged produces a transport Xray does not
// know.
func TestSplithttpIsNormalisedToXhttp(t *testing.T) {
	res, _ := mustParse(t, "vless://id@example.com:443?type=splithttp&security=tls&path=/x")
	if got := get(t, res.Outbound, "streamSettings", "network"); got != "xhttp" {
		t.Errorf("network is %v, want xhttp", got)
	}
	if _, ok := res.Outbound.GetObject("streamSettings"); !ok {
		t.Fatal("no streamSettings")
	}
}

func TestVLESSReality(t *testing.T) {
	link := "vless://id@example.com:443?type=tcp&security=reality&sni=www.microsoft.com" +
		"&pbk=PUBLICKEY&sid=abcd&fp=chrome&flow=xtls-rprx-vision#reality"
	res, _ := mustParse(t, link)

	r := get(t, res.Outbound, "streamSettings", "realitySettings")
	robj := r.(*jsonx.Object)
	for key, want := range map[string]string{
		"serverName": "www.microsoft.com",
		"publicKey":  "PUBLICKEY",
		"shortId":    "abcd",
		"spiderX":    "/",
	} {
		if got, _ := robj.GetString(key); got != want {
			t.Errorf("reality %s is %q, want %q", key, got, want)
		}
	}
	// XTLS flow is carried on the user, not the transport.
	users := get(t, res.Outbound, "settings", "vnext").([]any)[0].(*jsonx.Object)
	u := mustGetArray(t, users, "users")[0].(*jsonx.Object)
	if flow, _ := u.GetString("flow"); flow != "xtls-rprx-vision" {
		t.Errorf("flow is %q", flow)
	}
}

func TestVMessBase64JSON(t *testing.T) {
	payload := `{"v":"2","ps":"tokyo","add":"example.com","port":"8443","id":"UUID",` +
		`"aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com",` +
		`"path":"/ws","tls":"tls","sni":"example.com"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	res, raw := mustParse(t, link)

	if res.Protocol != "vmess" || res.Name != "tokyo" || res.Port != 8443 {
		t.Errorf("got %+v", res)
	}
	if got := get(t, res.Outbound, "streamSettings", "wsSettings", "path"); got != "/ws" {
		t.Errorf("ws path is %v", got)
	}
	if got := get(t, res.Outbound, "streamSettings", "wsSettings", "headers", "Host"); got != "cdn.example.com" {
		t.Errorf("ws Host header is %v", got)
	}
	// A string port in the link must still become a JSON number, and alterId
	// must be a number too.
	if !strings.Contains(raw, `"port":8443`) || !strings.Contains(raw, `"alterId":0`) {
		t.Errorf("numeric fields are quoted:\n%s", raw)
	}
}

// Different clients emit numbers as JSON numbers or as strings. Both must work.
func TestVMessAcceptsNumericFields(t *testing.T) {
	payload := `{"ps":"x","add":"example.com","port":443,"id":"UUID","aid":0,"net":"tcp","tls":""}`
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(payload))
	res, raw := mustParse(t, link)
	if res.Port != 443 {
		t.Errorf("port is %d", res.Port)
	}
	if !strings.Contains(raw, `"security":"none"`) {
		t.Errorf("an empty tls field should mean no transport security:\n%s", raw)
	}
}

// Trojan is TLS by default. A link that omits `security` still means TLS, and
// defaulting it to none would produce a tunnel that fails at handshake.
func TestTrojanDefaultsToTLS(t *testing.T) {
	res, _ := mustParse(t, "trojan://sekrit@example.com:443#home")
	if got := get(t, res.Outbound, "streamSettings", "security"); got != "tls" {
		t.Errorf("security is %v, want tls", got)
	}
	servers := mustGetArray(t, mustObject(t, res.Outbound, "settings"), "servers")
	s := servers[0].(*jsonx.Object)
	if pw, _ := s.GetString("password"); pw != "sekrit" {
		t.Errorf("password is %q", pw)
	}
}

func TestShadowsocksSIP002(t *testing.T) {
	creds := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:hunter2"))
	res, _ := mustParse(t, "ss://"+creds+"@example.com:8388#tokyo")
	if res.Protocol != "shadowsocks" || res.Name != "tokyo" || res.Port != 8388 {
		t.Errorf("got %+v", res)
	}
	s := mustGetArray(t, mustObject(t, res.Outbound, "settings"), "servers")[0].(*jsonx.Object)
	if m, _ := s.GetString("method"); m != "aes-256-gcm" {
		t.Errorf("method is %q", m)
	}
	if p, _ := s.GetString("password"); p != "hunter2" {
		t.Errorf("password is %q", p)
	}
}

func TestShadowsocksLegacyFormat(t *testing.T) {
	whole := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@example.com:8388"))
	res, _ := mustParse(t, "ss://"+whole+"#legacy")
	if res.Address != "example.com" || res.Port != 8388 {
		t.Errorf("got %+v", res)
	}
}

// A share link asking to skip certificate verification is either a mistake or
// an attack, and this gateway's whole job is to be the trustworthy hop.
func TestAllowInsecureIsNeverCarriedFromALink(t *testing.T) {
	_, raw := mustParse(t, "vless://id@example.com:443?type=tcp&security=tls&allowInsecure=1")
	if strings.Contains(raw, `"allowInsecure":true`) {
		t.Errorf("the link's allowInsecure was honoured:\n%s", raw)
	}
	if !strings.Contains(raw, `"allowInsecure":false`) {
		t.Errorf("allowInsecure should be pinned false:\n%s", raw)
	}
}

// The parser must not produce an outbound the config loader will reject: it
// needs a protocol, and it must NOT carry a tag, because the gateway assigns
// that and routing rules reference it.
func TestOutboundShapeIsAcceptable(t *testing.T) {
	for _, link := range []string{
		"vless://id@example.com:443?type=xhttp&security=tls&path=/x",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"e.com","port":"443","id":"u","net":"tcp"}`)),
		"trojan://pw@example.com:443",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@example.com:8388",
	} {
		res, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if proto, ok := res.Outbound.GetString("protocol"); !ok || proto == "" {
			t.Errorf("%s produced an outbound with no protocol", link)
		}
		if res.Outbound.Has("tag") {
			t.Errorf("%s produced an outbound carrying a tag; the gateway assigns that", link)
		}
		if res.Outbound.Has("outbounds") || res.Outbound.Has("inbounds") {
			t.Errorf("%s produced a whole config rather than one outbound", link)
		}
	}
}

func TestRejectsNonsense(t *testing.T) {
	for _, link := range []string{
		"", "not a link", "http://example.com",
		"vless://@example.com:443", "vmess://!!!notbase64!!!",
		"trojan://example.com", "vless://id@:443",
	} {
		if _, err := Parse(link); err == nil {
			t.Errorf("%q was accepted", link)
		}
	}
}

func mustObject(t *testing.T, o *jsonx.Object, key string) *jsonx.Object {
	t.Helper()
	child, ok := o.GetObject(key)
	if !ok {
		t.Fatalf("no object at %q", key)
	}
	return child
}

func mustGetArray(t *testing.T, o *jsonx.Object, key string) []any {
	t.Helper()
	arr, ok := o.GetArray(key)
	if !ok {
		t.Fatalf("no array at %q", key)
	}
	return arr
}
