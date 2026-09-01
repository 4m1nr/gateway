package adguard

import (
	"crypto/sha256"
	"fmt"
)

// clientUIDNamespace is a fixed, arbitrary namespace for ClientUID. Its only
// requirement is that it never changes: it is what makes a client's identity
// survive across restarts, across `gw apply`, and across a rebuild of the box.
var clientUIDNamespace = [16]byte{
	0x9c, 0x4b, 0x1e, 0x2a, 0x7d, 0x6f, 0x4a, 0x18,
	0x9e, 0x3c, 0x5b, 0x0d, 0x8f, 0x21, 0x64, 0xc7,
}

// ClientUID is a stable AdGuard client identifier derived from the address.
//
// AdGuard requires a uid on every persistent client and mints a fresh random
// one for any entry that arrives without it, so an entry merged in without a
// uid gets a new identity on every restart — and the uid is what AdGuard keys
// a client's own settings to. Deriving it from the address instead keeps the
// identity, because the address is what the entry means.
//
// Being derived also makes it a marker: an entry whose uid is ClientUID of its
// own address is one this gateway created, which is how reconcile tells its own
// leftovers from a client somebody added in the web UI.
//
// The result is a version 8 UUID; RFC 9562 reserves that version for exactly
// this, an identifier whose bits are vendor-defined rather than random or
// time-based.
func ClientUID(ip string) string {
	h := sha256.New()
	h.Write(clientUIDNamespace[:])
	h.Write([]byte(ip))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x80 // version 8
	u[8] = u[8]&0x3f | 0x80 // RFC 9562 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// reconcileClients rewrites the persistent client list in overlay so that a
// client AdGuard already has keeps what the web UI set on it.
//
// Every other list here is replaced wholesale, and for this one that is the
// wrong answer. A client's blocked services, its own upstreams, safe search,
// its tags — everything a person configures against a device — lives in the
// same list entry as the name and address the gateway owns, so replacing the
// list throws all of it away on every apply.
//
// The list is therefore joined rather than replaced, along one line: the
// gateway is the source of truth for a client's IDENTITY — its uid, its name
// and the address it is keyed to, all of which come from gateway.toml — and
// AdGuard is the source of truth for every other field on an entry it already
// had. The full entry the gateway renders is only used to CREATE a client
// AdGuard does not know yet.
//
// One consequence worth knowing: the filtering opt-out a `direct` policy
// implies is part of that seed, so changing a client's policy later does not
// reach back and flip the toggle on a client somebody has since edited. That is
// the same trade as everywhere else here — once a person has touched a setting
// in the web UI, it is theirs.
func reconcileClients(current, overlay map[string]any) {
	desired, ok := persistentList(overlay)
	if !ok {
		return
	}
	existing, _ := persistentList(current)

	// Index what AdGuard has by uid and by every address on it. First entry
	// wins: a config with two clients on one address is one AdGuard refuses to
	// start on, and picking a side here would only hide that.
	byUID, byIP := map[string]int{}, map[string]int{}
	for i, e := range existing {
		if uid, _ := e["uid"].(string); uid != "" {
			if _, dup := byUID[uid]; !dup {
				byUID[uid] = i
			}
		}
		for _, id := range stringList(e["ids"]) {
			if _, dup := byIP[id]; !dup {
				byIP[id] = i
			}
		}
	}

	taken := make([]bool, len(existing))
	out := make([]any, 0, len(desired)+len(existing))

	for _, want := range desired {
		uid, _ := want["uid"].(string)
		ip := firstString(want["ids"])

		// By uid first, then by address. The second lookup is what adopts an
		// entry somebody added by hand for a device that is now in
		// gateway.toml: without it the merge would append a second entry for
		// the same address, and AdGuard refuses to start on that.
		at, found := byUID[uid]
		if !found {
			at, found = byIP[ip]
		}
		if !found || taken[at] {
			out = append(out, want)
			continue
		}
		taken[at] = true

		merged := cloneMap(existing[at])
		merged["uid"] = uid
		merged["name"] = want["name"]
		// Union, not replacement: a person who added this device's MAC address
		// alongside its IP was adding a way to recognise it, not replacing the
		// one the gateway enforces policy on.
		merged["ids"] = withID(merged["ids"], ip)
		out = append(out, merged)
	}

	// Whatever is left. An entry this gateway created — recognisable because
	// its uid is derived from its own address — is a client that has since been
	// removed from gateway.toml, so it goes with it. Anything else is somebody
	// else's entry and stays.
	for i, e := range existing {
		if taken[i] || isGatewayClient(e) {
			continue
		}
		out = append(out, e)
	}

	clients, _ := asMap(overlay["clients"])
	clients["persistent"] = out
}

// isGatewayClient reports whether an entry was created by this gateway.
func isGatewayClient(entry map[string]any) bool {
	uid, _ := entry["uid"].(string)
	if uid == "" {
		return false
	}
	for _, id := range stringList(entry["ids"]) {
		if ClientUID(id) == uid {
			return true
		}
	}
	return false
}

// persistentList reads clients.persistent as a list of entries.
func persistentList(m map[string]any) (out []map[string]any, ok bool) {
	clients, ok := asMap(m["clients"])
	if !ok {
		return nil, false
	}
	raw, ok := clients["persistent"].([]any)
	if !ok {
		return nil, false
	}
	for _, e := range raw {
		if entry, ok := asMap(e); ok {
			out = append(out, entry)
		}
	}
	return out, true
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// stringList normalises the ids field, which YAML decodes as []any.
func stringList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func firstString(v any) string {
	if list := stringList(v); len(list) > 0 {
		return list[0]
	}
	return ""
}

// withID returns ids with want present, keeping the existing order.
func withID(ids any, want string) []any {
	out := []any{}
	for _, id := range stringList(ids) {
		out = append(out, id)
		if id == want {
			want = ""
		}
	}
	if want != "" {
		out = append(out, want)
	}
	return out
}
