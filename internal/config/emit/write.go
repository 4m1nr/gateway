package emit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// write renders one section.
func (s section) write(b *strings.Builder, doc Document, written map[string]bool) error {
	// A dotted name is a nested table: xray.outbound lives inside xray.
	value, ok := lookup(doc, s.name)
	if !ok {
		return nil
	}

	if s.array {
		entries, ok := asTables(value)
		if !ok || len(entries) == 0 {
			written[s.name] = true
			return nil
		}
		for i, item := range entries {
			b.WriteString("\n")
			b.WriteString(comment(s.doc))
			b.WriteString("[[" + s.name + "]]\n")
			// Only the first entry carries the prose. Repeating the section's
			// explanation and every key's note on each of a dozen clients
			// buries the entries themselves, which are the thing being read.
			if err := s.writeKeys(b, item, s.name, i == 0); err != nil {
				return err
			}
			s.doc = ""
		}
		written[s.name] = true
		return nil
	}

	table, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	b.WriteString("\n")
	b.WriteString(comment(s.doc))
	b.WriteString("[" + s.name + "]\n")
	if err := s.writeKeys(b, table, s.name, true); err != nil {
		return err
	}
	written[s.name] = true
	return nil
}

// writeKeys emits the documented keys in order, then anything else the table
// holds — an unrecognised key is preserved, never dropped.
func (s section) writeKeys(b *strings.Builder, table map[string]any, path string, withDocs bool) error {
	seen := map[string]bool{}

	for _, e := range s.keys {
		value, ok := table[e.key]
		if !ok {
			continue
		}
		seen[e.key] = true
		// A sub-table is emitted as its own section later; skip it here so it
		// does not appear twice.
		if isTableLike(value) {
			continue
		}
		if withDocs && e.doc != "" {
			b.WriteString(indentComment(e.doc, ""))
		}
		rendered, err := renderValue(value)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", path, e.key, err)
		}
		fmt.Fprintf(b, "%s = %s\n", e.key, rendered)
	}

	var extra []string
	for key, value := range table {
		if seen[key] || isTableLike(value) {
			continue
		}
		extra = append(extra, key)
	}
	sort.Strings(extra)
	for _, key := range extra {
		rendered, err := renderValue(table[key])
		if err != nil {
			return fmt.Errorf("%s.%s: %w", path, key, err)
		}
		fmt.Fprintf(b, "%s = %s\n", key, rendered)
	}

	// Nested tables, after the scalars, so the parent's own settings read first.
	return writeNested(b, table, path, s.keys)
}

// writeNested emits sub-tables the layout did not name explicitly — a profile's
// [[profile.route]] entries, or an inline table someone added.
func writeNested(b *strings.Builder, table map[string]any, path string, known []entry) error {
	var names []string
	for key, value := range table {
		if isTableLike(value) {
			names = append(names, key)
		}
	}
	sort.Strings(names)

	for _, key := range names {
		full := path + "." + key
		// Named sections are emitted by the layout at their own position.
		if isLayoutSection(full) {
			continue
		}
		value := table[key]
		if entries, ok := asTables(value); ok {
			for _, item := range entries {
				b.WriteString("\n  [[" + full + "]]\n")
				if err := writeIndentedTable(b, item, full); err != nil {
					return err
				}
			}
			continue
		}
		if sub, ok := value.(map[string]any); ok {
			b.WriteString("\n  [" + full + "]\n")
			if err := writeIndentedTable(b, sub, full); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeIndentedTable emits a nested table's keys, indented so the nesting is
// visible — profile routes read as belonging to their profile.
func writeIndentedTable(b *strings.Builder, table map[string]any, path string) error {
	var keys []string
	for key := range table {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	width := 0
	for _, key := range keys {
		if !isTableLike(table[key]) && len(key) > width {
			width = len(key)
		}
	}
	for _, key := range keys {
		value := table[key]
		if isTableLike(value) {
			continue
		}
		rendered, err := renderValue(value)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", path, key, err)
		}
		fmt.Fprintf(b, "  %-*s = %s\n", width, key, rendered)
	}
	return nil
}

// writeRemainder emits top-level tables the layout knows nothing about, so a
// setting from a future version survives a rewrite by an older binary.
func writeRemainder(b *strings.Builder, doc Document, written map[string]bool) error {
	var names []string
	for key := range doc {
		if written[key] || isLayoutSection(key) {
			continue
		}
		names = append(names, key)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}

	// Bare scalars at the document root have to come before any table header,
	// or TOML reads them as belonging to the last table.
	var scalars []string
	var tables []string
	for _, name := range names {
		if isTableLike(doc[name]) {
			tables = append(tables, name)
		} else {
			scalars = append(scalars, name)
		}
	}

	if len(scalars) > 0 {
		return fmt.Errorf("cannot rewrite this config: it has top-level keys (%s) "+
			"that must sit above every table, and rewriting would move them into "+
			"one. Move them into a section by hand first", strings.Join(scalars, ", "))
	}

	b.WriteString("\n# Settings this version of gw does not recognise. They are kept as they\n")
	b.WriteString("# were found, because dropping them would silently delete a setting.\n")
	for _, name := range tables {
		value := doc[name]
		if entries, ok := asTables(value); ok {
			for _, item := range entries {
				b.WriteString("\n[[" + name + "]]\n")
				if err := writeIndentedTable(b, item, name); err != nil {
					return err
				}
			}
			continue
		}
		if table, ok := value.(map[string]any); ok {
			b.WriteString("\n[" + name + "]\n")
			if err := writeIndentedTable(b, table, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// -------------------------------------------------------------- rendering --

// renderValue writes one TOML value.
func renderValue(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return renderString(t), nil
	case bool:
		return strconv.FormatBool(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case int:
		return strconv.Itoa(t), nil
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	case time.Time:
		return t.Format(time.RFC3339), nil
	case []any:
		return renderArray(t)
	case []map[string]any:
		return "", fmt.Errorf("an array of tables cannot be written inline")
	case map[string]any:
		return "", fmt.Errorf("a table cannot be written inline")
	case nil:
		return `""`, nil
	}
	return "", fmt.Errorf("cannot render %T", v)
}

// renderString picks the quoting a value needs.
//
// A multi-line value becomes a LITERAL string — the single-quoted kind. The
// double-quoted kind processes escapes, so a bash line continuation would be
// collapsed and a \n would become a real newline, quietly rewriting a job
// script between what was saved and what runs.
func renderString(s string) string {
	if strings.Contains(s, "\n") {
		if !strings.Contains(s, "'''") {
			return "'''\n" + strings.TrimRight(s, "\n") + "\n'''"
		}
		// A literal string cannot hold ''', so fall back to the escaped form
		// and accept that escapes are processed — the alternative is a file
		// that does not parse.
		return strconv.Quote(s)
	}
	if !strings.ContainsAny(s, `"\`) {
		return `"` + s + `"`
	}
	return strconv.Quote(s)
}

func renderArray(items []any) (string, error) {
	if len(items) == 0 {
		return "[]", nil
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		rendered, err := renderValue(item)
		if err != nil {
			return "", err
		}
		parts = append(parts, rendered)
	}
	inline := "[" + strings.Join(parts, ", ") + "]"
	// Long lists go one per line: an upstream list that wraps in a terminal is
	// unreadable exactly when someone is checking it.
	if len(inline) <= 76 {
		return inline, nil
	}
	return "[\n  " + strings.Join(parts, ",\n  ") + ",\n]", nil
}

// ---------------------------------------------------------------- helpers --

func comment(text string) string {
	if text == "" {
		return ""
	}
	return indentComment(text, "")
}

func indentComment(text, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			b.WriteString(prefix + "#\n")
			continue
		}
		b.WriteString(prefix + "# " + line + "\n")
	}
	return b.String()
}

// lookup resolves a dotted section name.
func lookup(doc Document, name string) (any, bool) {
	parts := strings.Split(name, ".")
	var current any = map[string]any(doc)
	for _, part := range parts {
		table, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = table[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// asTables normalises the two shapes an array of tables decodes into.
func asTables(v any) ([]map[string]any, bool) {
	switch t := v.(type) {
	case []map[string]any:
		return t, true
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			table, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, table)
		}
		return out, len(out) > 0
	}
	return nil, false
}

func isTableLike(v any) bool {
	if _, ok := v.(map[string]any); ok {
		return true
	}
	_, ok := asTables(v)
	return ok
}

func isLayoutSection(name string) bool {
	for _, s := range layout {
		if s.name == name {
			return true
		}
	}
	return false
}
