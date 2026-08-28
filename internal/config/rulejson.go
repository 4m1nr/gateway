package config

import (
	"encoding/json"
	"fmt"

	"github.com/am1nr/gateway/internal/jsonx"
)

// decodeRuleJSON parses a raw `json = """..."""` custom routing rule.
//
// The result is a plain map because the rule is merged with TOML-sourced keys
// and re-marshalled as part of the routing array, where Xray does not care
// about key order. Numbers stay json.Number so a port written as 443 is emitted
// as 443.
func decodeRuleJSON(text string) (map[string]any, error) {
	v, err := jsonx.Decode([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("not valid JSON — %w", err)
	}
	obj, ok := v.(*jsonx.Object)
	if !ok {
		return nil, fmt.Errorf("must be a single rule object")
	}
	out := make(map[string]any, obj.Len())
	for _, k := range obj.Keys() {
		val, _ := obj.Get(k)
		out[k] = plain(val)
	}
	return out, nil
}

// plain converts ordered objects back to maps. Routing rules are re-marshalled
// by the renderer alongside TOML-sourced rules, which are plain maps already.
func plain(v any) any {
	switch t := v.(type) {
	case *jsonx.Object:
		m := make(map[string]any, t.Len())
		for _, k := range t.Keys() {
			val, _ := t.Get(k)
			m[k] = plain(val)
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = plain(item)
		}
		return out
	case json.Number:
		return t
	}
	return v
}
