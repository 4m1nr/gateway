package config

import "fmt"

// Accessors over the decoded TOML tree.
//
// gateway.toml is read into map[string]any rather than a struct so that the
// validation reads the way the file does: every lookup can name the exact key
// path it wanted and say what it expected. A struct decoder would report
// "cannot unmarshal string into int" with no idea which table it was in.

func table(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return map[string]any{}
	}
	t, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return t
}

// need returns the value at key, or an error naming the table it was missing from.
func need(m map[string]any, key, where string) (any, error) {
	v, ok := m[key]
	if !ok {
		return nil, errf("[%s] is missing required key '%s'", where, key)
	}
	return v, nil
}

func needString(m map[string]any, key, where string) (string, error) {
	v, err := need(m, key, where)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", errf("%s.%s must be a string, not %s", where, key, kindOf(v))
	}
	return s, nil
}

func str(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return def
}

// integer accepts TOML integers only. A float here is a typo (port = 8088.0),
// not a value to silently truncate.
func integer(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	i, ok := v.(int64)
	if !ok {
		return 0, errf("%s must be an integer, not %s", key, kindOf(v))
	}
	return int(i), nil
}

func boolean(m map[string]any, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, errf("%s must be true or false, not %s", key, kindOf(v))
	}
	return b, nil
}

// strings returns a list of strings, or def when the key is absent. A single
// bare string is NOT accepted as a one-element list: TOML distinguishes them,
// and quietly accepting both hides a typo in a list that matters.
func stringList(m map[string]any, key string, def []string) ([]string, error) {
	v, ok := m[key]
	if !ok {
		return append([]string(nil), def...), nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, errf("%s must be a list of strings, not %s", key, kindOf(v))
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, errf("%s[%d] must be a string, not %s", key, i, kindOf(it))
		}
		out = append(out, s)
	}
	return out, nil
}

// tables returns an array-of-tables ([[client]], [[profile]], ...). An empty
// result covers both "absent" and "present but empty", which is what every
// caller wants.
func tables(m map[string]any, key string) ([]map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	items, ok := v.([]map[string]any)
	if ok {
		return items, nil
	}
	anys, ok := v.([]any)
	if !ok {
		return nil, errf("[[%s]] must be a list of tables, not %s", key, kindOf(v))
	}
	out := make([]map[string]any, 0, len(anys))
	for i, it := range anys {
		t, ok := it.(map[string]any)
		if !ok {
			return nil, errf("%s[%d] must be a table, not %s", key, i, kindOf(it))
		}
		out = append(out, t)
	}
	return out, nil
}

func kindOf(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case int64:
		return "an integer"
	case float64:
		return "a float"
	case bool:
		return "a boolean"
	case []any, []map[string]any:
		return "a list"
	case map[string]any:
		return "a table"
	case nil:
		return "nothing"
	}
	return fmt.Sprintf("%T", v)
}
