// Package jsonx decodes JSON while preserving object key order.
//
// The gateway takes Xray outbounds verbatim: whatever the user pastes is what
// Xray gets, minus two fields the gateway owns. encoding/json into
// map[string]any would break that promise twice over — it sorts keys on the way
// out, so a pasted outbound comes back reordered, and it decodes every number
// to float64, so `"port": 443` re-marshals as `443` only by luck and a large
// uint64 loses precision outright.
//
// Object keeps insertion order and holds numbers as json.Number, so decode →
// mutate two fields → encode returns the original text with the original
// formatting, which is what both the config renderer and the dashboard's JSON
// editor need.
package jsonx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Object is a JSON object that remembers the order its keys arrived in.
type Object struct {
	keys []string
	vals map[string]any
}

func NewObject() *Object {
	return &Object{vals: map[string]any{}}
}

func (o *Object) Len() int { return len(o.keys) }

// Keys returns the key order. The returned slice is a copy.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

func (o *Object) Get(key string) (any, bool) {
	if o == nil || o.vals == nil {
		return nil, false
	}
	v, ok := o.vals[key]
	return v, ok
}

func (o *Object) Has(key string) bool {
	_, ok := o.Get(key)
	return ok
}

// Set replaces an existing key in place, or appends a new one at the end.
func (o *Object) Set(key string, val any) {
	if o.vals == nil {
		o.vals = map[string]any{}
	}
	if _, exists := o.vals[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = val
}

// SetDefault sets key only if it is absent, and reports whether it did.
func (o *Object) SetDefault(key string, val any) bool {
	if o.Has(key) {
		return false
	}
	o.Set(key, val)
	return true
}

func (o *Object) Delete(key string) {
	if o == nil || o.vals == nil {
		return
	}
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// GetString returns the value at key when it is a string.
func (o *Object) GetString(key string) (string, bool) {
	v, ok := o.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetObject returns the value at key when it is an object.
func (o *Object) GetObject(key string) (*Object, bool) {
	v, ok := o.Get(key)
	if !ok {
		return nil, false
	}
	obj, ok := v.(*Object)
	return obj, ok
}

// Object at key, creating an empty one if absent. Returns an error if the key
// exists and holds something that is not an object — callers report that as a
// config error naming the field.
func (o *Object) EnsureObject(key string) (*Object, error) {
	v, ok := o.Get(key)
	if !ok {
		child := NewObject()
		o.Set(key, child)
		return child, nil
	}
	child, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return child, nil
}

// GetArray returns the value at key when it is an array.
func (o *Object) GetArray(key string) ([]any, bool) {
	v, ok := o.Get(key)
	if !ok {
		return nil, false
	}
	a, ok := v.([]any)
	return a, ok
}

// GetNumber returns the value at key when it is a number.
func (o *Object) GetNumber(key string) (json.Number, bool) {
	v, ok := o.Get(key)
	if !ok {
		return "", false
	}
	n, ok := v.(json.Number)
	return n, ok
}

// ---------------------------------------------------------------- decoding --

// Decode parses JSON into ordered values. Objects become *Object, arrays
// []any, numbers json.Number, and the rest map to their Go equivalents.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	// Reject trailing content, the way json.Unmarshal does. Two concatenated
	// objects in an outbound file is a paste accident, not a config.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing data after the JSON value")
	}
	return v, nil
}

// DecodeObject parses JSON that must be a single object.
func DecodeObject(data []byte) (*Object, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return obj, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeFrom(dec, tok)
}

func decodeFrom(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return decodeObject(dec)
		case '[':
			return decodeArray(dec)
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return tok, nil
	}
}

func decodeObject(dec *json.Decoder) (*Object, error) {
	obj := NewObject()
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return obj, nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("object key is not a string")
		}
		val, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		// A duplicate key keeps its original position and takes the later
		// value, which is what every JSON parser in the chain does.
		obj.Set(key, val)
	}
}

func decodeArray(dec *json.Decoder) ([]any, error) {
	// Non-nil so an empty array marshals as [] rather than null.
	out := []any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); ok && d == ']' {
			return out, nil
		}
		val, err := decodeFrom(dec, tok)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
}

// ---------------------------------------------------------------- encoding --

// MarshalJSON writes the object with its keys in their original order.
func (o *Object) MarshalJSON() ([]byte, error) {
	if o == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		val, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(val)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *Object) UnmarshalJSON(data []byte) error {
	parsed, err := DecodeObject(data)
	if err != nil {
		return err
	}
	o.keys, o.vals = parsed.keys, parsed.vals
	return nil
}
