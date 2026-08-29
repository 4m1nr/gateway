// Package adguard merges the gateway's settings into AdGuardHome.yaml.
//
// AdGuard owns its own configuration file — it rewrites and schema-migrates it
// — so the gateway does not template it wholesale. It emits the keys it cares
// about and merges them in, which leaves anything set through the AdGuard web
// UI intact across `gw apply`.
package adguard

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Merge applies overrides to the YAML file at path, keeping a backup.
//
// Maps are merged recursively; lists are replaced wholesale. A half-merged
// upstream list is worse than either version — it would mix the old resolvers
// with the new, and the result is a set nobody chose.
func Merge(path string, overrides map[string]any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist yet — start AdGuard Home once, "+
				"complete the setup wizard, then re-run `gw apply`", path)
		}
		return err
	}

	var current map[string]any
	if err := yaml.Unmarshal(raw, &current); err != nil {
		return fmt.Errorf("%s is not valid YAML: %w", path, err)
	}
	if current == nil {
		current = map[string]any{}
	}

	// The backup is written before anything changes. AdGuard's config holds the
	// admin password hash, which this tool never sets and must never lose.
	if err := os.WriteFile(path+".bak", raw, 0o600); err != nil {
		return fmt.Errorf("writing the backup: %w", err)
	}

	merged := deepMerge(current, overrides)
	out, err := yaml.Marshal(merged)
	if err != nil {
		return err
	}

	// Written through a temp file: a truncated AdGuardHome.yaml is a resolver
	// that will not start, and DNS failing takes the LAN down even when the
	// tunnel is fine.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".AdGuardHome.yaml.gw-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
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
	// Match whatever AdGuard had; it is normally 0600 because of that hash.
	if st, err := os.Stat(path); err == nil {
		if err := os.Chmod(tmp.Name(), st.Mode().Perm()); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

// deepMerge merges overlay into base, recursing into maps and replacing
// everything else.
func deepMerge(base, overlay map[string]any) map[string]any {
	for k, v := range overlay {
		newMap, newIsMap := asMap(v)
		oldMap, oldIsMap := asMap(base[k])
		if newIsMap && oldIsMap {
			base[k] = deepMerge(oldMap, newMap)
			continue
		}
		base[k] = v
	}
	return base
}

// asMap normalises the two map shapes YAML decoding can produce.
func asMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = val
		}
		return out, true
	}
	return nil, false
}
