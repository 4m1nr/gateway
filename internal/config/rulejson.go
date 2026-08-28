package config

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/am1nr/gateway/internal/jsonx"
)

// tomlToJSON converts a value decoded from TOML into one the ordered JSON
// encoder renders the way Python's json.dumps would.
//
// TOML integers arrive as int64 and become json.Number so a port written as 22
// is emitted as 22 rather than going through float64. Nested tables have no
// recorded key order, so their keys are sorted for determinism.
func tomlToJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := jsonx.NewObject()
		for _, k := range keys {
			out.Set(k, tomlToJSON(t[k]))
		}
		return out
	case []map[string]any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = tomlToJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = tomlToJSON(item)
		}
		return out
	case int64:
		return json.Number(strconv.FormatInt(t, 10))
	case int:
		return json.Number(strconv.Itoa(t))
	}
	return v
}
