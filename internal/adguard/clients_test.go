package adguard

import (
	"testing"
)

// gwClient is the entry the gateway renders for a client in gateway.toml.
func gwClient(ip, name string, filtered bool) map[string]any {
	return map[string]any{
		"name":                        name,
		"ids":                         []any{ip},
		"tags":                        []any{},
		"uid":                         ClientUID(ip),
		"use_global_settings":         filtered,
		"use_global_blocked_services": true,
		"filtering_enabled":           filtered,
		"upstreams":                   []any{},
	}
}

func overlayWith(entries ...map[string]any) map[string]any {
	list := make([]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	return map[string]any{"clients": map[string]any{"persistent": list}}
}

func persistentAfter(t *testing.T, current, overlay map[string]any) []map[string]any {
	t.Helper()
	reconcileClients(current, overlay)
	out, ok := persistentList(overlay)
	if !ok {
		t.Fatal("the overlay lost its clients.persistent list")
	}
	return out
}

func byName(t *testing.T, list []map[string]any, name string) map[string]any {
	t.Helper()
	for _, e := range list {
		if e["name"] == name {
			return e
		}
	}
	t.Fatalf("no client named %q survived the merge", name)
	return nil
}

// The point of the whole exercise: what a person sets against a device in the
// AdGuard web UI has to survive `gw apply`. Those settings live in the same
// list entry as the name and address the gateway owns, so a wholesale replace
// throws them away every time.
func TestEditsMadeInAdGuardSurviveAMerge(t *testing.T) {
	current := overlayWith(map[string]any{
		"name":                        "tv",
		"ids":                         []any{"192.168.1.60"},
		"uid":                         ClientUID("192.168.1.60"),
		"tags":                        []any{"device_tv"},
		"use_global_blocked_services": false,
		"blocked_services":            map[string]any{"ids": []any{"youtube", "tiktok"}},
		"upstreams":                   []any{"9.9.9.9"},
		"safebrowsing_enabled":        true,
		"ignore_statistics":           true,
	})

	got := byName(t, persistentAfter(t, current, overlayWith(
		gwClient("192.168.1.60", "tv", false))), "tv")

	blocked, _ := asMap(got["blocked_services"])
	if ids, _ := blocked["ids"].([]any); len(ids) != 2 {
		t.Errorf("blocked services were lost: %v", got["blocked_services"])
	}
	if got["use_global_blocked_services"] != false {
		t.Error("the blocked-services opt-out was reset")
	}
	if ups, _ := got["upstreams"].([]any); len(ups) != 1 || ups[0] != "9.9.9.9" {
		t.Errorf("the client's own upstreams were lost: %v", got["upstreams"])
	}
	if tags, _ := got["tags"].([]any); len(tags) != 1 || tags[0] != "device_tv" {
		t.Errorf("tags were lost: %v", got["tags"])
	}
	if got["safebrowsing_enabled"] != true || got["ignore_statistics"] != true {
		t.Error("per-client toggles were reset to the rendered defaults")
	}
}

// Identity is the half the gateway does own: gateway.toml decides what a client
// is called and which address it is keyed to.
func TestTheGatewayStillOwnsClientIdentity(t *testing.T) {
	current := overlayWith(map[string]any{
		"name":      "old-name",
		"ids":       []any{"192.168.1.60", "aa:bb:cc:dd:ee:ff"},
		"uid":       ClientUID("192.168.1.60"),
		"upstreams": []any{"9.9.9.9"},
	})

	got := byName(t, persistentAfter(t, current, overlayWith(
		gwClient("192.168.1.60", "living-room-tv", false))), "living-room-tv")

	if got["uid"] != ClientUID("192.168.1.60") {
		t.Errorf("uid is %v, want the derived one", got["uid"])
	}
	// The extra identifier is a way to recognise the device, not a replacement
	// for the address policy is enforced on.
	ids := stringList(got["ids"])
	if len(ids) != 2 || ids[0] != "192.168.1.60" || ids[1] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ids are %v, want the address plus the MAC somebody added", ids)
	}
}

// A client AdGuard has never seen is created from the rendered entry, opt-out
// and all.
func TestANewClientIsCreatedInFull(t *testing.T) {
	got := byName(t, persistentAfter(t, overlayWith(), overlayWith(
		gwClient("192.168.1.60", "tv", false))), "tv")

	if got["filtering_enabled"] != false || got["use_global_settings"] != false {
		t.Errorf("a new direct client was not seeded with the filtering opt-out: %v", got)
	}
}

// An entry somebody added by hand for a device that is now in gateway.toml has
// to be adopted, not duplicated: AdGuard refuses to start when two clients
// share an address, and that takes the LAN's DNS with it.
func TestAHandMadeEntryForTheSameAddressIsAdopted(t *testing.T) {
	current := overlayWith(map[string]any{
		"name":      "the tv",
		"ids":       []any{"192.168.1.60"},
		"uid":       "11111111-2222-3333-4444-555555555555",
		"upstreams": []any{"9.9.9.9"},
	})

	got := persistentAfter(t, current, overlayWith(gwClient("192.168.1.60", "tv", false)))
	if len(got) != 1 {
		t.Fatalf("got %d clients, want 1 — a second entry for the same address "+
			"stops AdGuard from starting: %v", len(got), got)
	}
	if ups, _ := got[0]["upstreams"].([]any); len(ups) != 1 {
		t.Error("adopting the entry dropped what was set on it")
	}
}

// A client somebody added in the web UI and the gateway knows nothing about is
// not the gateway's to delete.
func TestAClientTheGatewayDoesNotManageIsLeftAlone(t *testing.T) {
	current := overlayWith(map[string]any{
		"name": "guest-laptop",
		"ids":  []any{"192.168.1.150"},
		"uid":  "11111111-2222-3333-4444-555555555555",
	})

	got := persistentAfter(t, current, overlayWith(gwClient("192.168.1.60", "tv", true)))
	if len(got) != 2 {
		t.Fatalf("got %d clients, want 2: %v", len(got), got)
	}
	byName(t, got, "guest-laptop")
}

// Removing a [[client]] from gateway.toml has to remove it from AdGuard too, or
// the list only ever grows. A gateway entry is recognisable because its uid is
// derived from its own address.
func TestAClientRemovedFromTheConfigIsRemovedFromAdGuard(t *testing.T) {
	current := overlayWith(
		gwClient("192.168.1.60", "tv", false),
		gwClient("192.168.1.99", "iot-plug", true),
	)

	got := persistentAfter(t, current, overlayWith(gwClient("192.168.1.60", "tv", false)))
	if len(got) != 1 || got[0]["name"] != "tv" {
		t.Errorf("got %v, want only tv", got)
	}
}

// Applying twice with nothing changed must produce the same list, or every
// apply is a diff in AdGuard's config and a restart nobody asked for.
func TestMergingTwiceIsStable(t *testing.T) {
	overlay := func() map[string]any {
		return overlayWith(
			gwClient("192.168.1.60", "tv", false),
			gwClient("192.168.1.99", "iot-plug", true),
		)
	}
	once := overlay()
	reconcileClients(overlayWith(), once)
	twice := overlay()
	reconcileClients(once, twice)

	first, _ := persistentList(once)
	second, _ := persistentList(twice)
	if len(first) != len(second) {
		t.Fatalf("the list changed size on a second apply: %d then %d", len(first), len(second))
	}
	for i := range first {
		if first[i]["uid"] != second[i]["uid"] || first[i]["name"] != second[i]["name"] {
			t.Errorf("entry %d changed on a second apply:\n %v\n %v", i, first[i], second[i])
		}
	}
}
