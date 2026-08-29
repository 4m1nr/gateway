package action

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/config/emit"
)

// readDocument decodes gateway.toml without validating it.
//
// Deliberately separate from config.Load: the dashboard has to be able to show
// and repair a config that does not currently load, and a loader that refuses
// to parse it is no help at all when that is the problem.
func (h Handler) readDocument() (emit.Document, error) {
	raw, err := os.ReadFile(h.Config)
	if err != nil {
		return nil, err
	}
	var doc emit.Document
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid TOML: %w", h.Config, err)
	}
	return doc, nil
}

// configRead returns the whole config as JSON, plus whether it currently loads.
func (h Handler) configRead() Response {
	doc, err := h.readDocument()
	if err != nil {
		return fail("%v", err)
	}
	data := map[string]any{"config": doc}

	// The validation error is data, not a failure: the dashboard shows the
	// config alongside what is wrong with it, which is the only way to fix it
	// from there.
	if _, err := config.Load(h.Config); err != nil {
		data["config_error"] = err.Error()
	} else {
		data["config_error"] = ""
	}

	raw, err := os.ReadFile(h.Config)
	if err == nil {
		data["toml"] = string(raw)
	}
	return ok(data)
}

// configWrite replaces one top-level section and saves.
//
// Section-at-a-time rather than the whole document: two people with the
// dashboard open would otherwise overwrite each other's unrelated edits, and a
// bug in one page could not corrupt a section it never touched.
func (h Handler) configWrite(req Request) Response {
	if req.Section == "" {
		return fail("no section was named")
	}
	if !editableSections[req.Section] {
		return fail("%q is not a section the dashboard may write", req.Section)
	}

	var value any
	if err := json.Unmarshal([]byte(req.JSON), &value); err != nil {
		return fail("the section is not valid JSON: %v", err)
	}

	doc, err := h.readDocument()
	if err != nil {
		return fail("%v", err)
	}

	previous, existed := doc[req.Section]
	if value == nil {
		delete(doc, req.Section)
	} else {
		doc[req.Section] = normalise(value)
	}

	if err := h.saveDocument(doc); err != nil {
		// Put it back in memory; the file was not written.
		if existed {
			doc[req.Section] = previous
		}
		return fail("%v", err)
	}
	return Response{
		OK:           true,
		Message:      req.Section + " saved",
		PendingApply: true,
	}
}

// saveDocument validates and writes.
//
// The order is the point. The candidate is written to a temporary file and
// loaded from there, so a config that would not load never replaces the one
// that does — the dashboard cannot save a change that stops the gateway
// starting, and it says why instead.
func (h Handler) saveDocument(doc emit.Document) error {
	body, err := emit.Emit(doc)
	if err != nil {
		return fmt.Errorf("could not write the config: %w", err)
	}

	dir := filepath.Dir(h.Config)
	tmp, err := os.CreateTemp(dir, ".gateway.toml.candidate-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if _, err := config.Load(tmp.Name()); err != nil {
		return fmt.Errorf("that change would leave the config invalid, so it was "+
			"not saved:\n%w", err)
	}

	// Keep the previous file. A whole-file rewrite is the one operation where
	// having yesterday's config matters, and it costs nothing.
	if current, err := os.ReadFile(h.Config); err == nil {
		_ = os.WriteFile(h.Config+".bak", current, 0o600)
	}

	if st, err := os.Stat(h.Config); err == nil {
		if err := os.Chmod(tmp.Name(), st.Mode().Perm()); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), h.Config)
}

// editableSections is what the dashboard may write. A whitelist, because this
// runs as root and "replace any section named by an HTTP request" would include
// ones whose meaning the UI does not model.
var editableSections = map[string]bool{
	"net":         true,
	"ipv6":        true,
	"policy":      true,
	"client":      true,
	"xray":        true,
	"upstream":    true,
	"profile":     true,
	"route":       true,
	"routing":     true,
	"dns":         true,
	"tailscale":   true,
	"web":         true,
	"health":      true,
	"performance": true,
	"geodata":     true,
	"bootstrap":   true,
	"system":      true,
	"job":         true,
}

// normalise converts JSON's number type back into the shapes TOML expects.
//
// encoding/json decodes every number as float64, and writing 53.0 where a port
// belongs produces a config that does not load — or worse, one that does and
// means something else.
func normalise(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalise(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = normalise(item)
		}
		return out
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	}
	return v
}

// configBackup returns the previous config, so a bad save can be read back.
func (h Handler) configBackup() Response {
	raw, err := os.ReadFile(h.Config + ".bak")
	if err != nil {
		return fail("there is no previous config to restore")
	}
	info, _ := os.Stat(h.Config + ".bak")
	saved := ""
	if info != nil {
		saved = info.ModTime().Format(time.RFC3339)
	}
	return ok(map[string]any{"toml": string(raw), "saved_at": saved})
}
