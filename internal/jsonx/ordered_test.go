package jsonx

import (
	"encoding/json"
	"testing"
)

// The whole point of this package: decode → encode returns what went in.
func TestRoundTripPreservesOrderAndNumbers(t *testing.T) {
	in := `{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,` +
		`"users":[{"id":"abc","encryption":"none","level":0}]}]},` +
		`"streamSettings":{"network":"xhttp","security":"tls"}}`
	obj, err := DecodeObject([]byte(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != in {
		t.Errorf("round trip changed the document:\n in: %s\nout: %s", in, out)
	}
}

// float64 decoding would render 443 as 443 but 10000000000000001 as 1e+16.
func TestLargeIntegersSurvive(t *testing.T) {
	in := `{"id":10000000000000001,"ratio":0.5000,"port":443}`
	obj, err := DecodeObject([]byte(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, _ := json.Marshal(obj)
	if string(out) != in {
		t.Errorf("number formatting changed:\n in: %s\nout: %s", in, out)
	}
}

// Mutating two fields must not disturb the rest, and a new key lands at the end.
func TestSetKeepsPositionAndAppends(t *testing.T) {
	obj, err := DecodeObject([]byte(`{"protocol":"vless","tag":"old","settings":{}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	obj.Set("tag", "proxy")
	obj.Set("streamSettings", NewObject())
	out, _ := json.Marshal(obj)
	want := `{"protocol":"vless","tag":"proxy","settings":{},"streamSettings":{}}`
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
}

func TestEnsureObjectCreatesAndRejectsWrongType(t *testing.T) {
	obj := NewObject()
	child, err := obj.EnsureObject("streamSettings")
	if err != nil {
		t.Fatalf("EnsureObject on empty: %v", err)
	}
	child.Set("network", "tcp")
	if out, _ := json.Marshal(obj); string(out) != `{"streamSettings":{"network":"tcp"}}` {
		t.Errorf("unexpected: %s", out)
	}

	bad, _ := DecodeObject([]byte(`{"streamSettings":"tcp"}`))
	if _, err := bad.EnsureObject("streamSettings"); err == nil {
		t.Error("expected an error when the key holds a string, got none")
	}
}

func TestDeleteKeepsRemainingOrder(t *testing.T) {
	obj, _ := DecodeObject([]byte(`{"a":1,"b":2,"c":3}`))
	obj.Delete("b")
	if out, _ := json.Marshal(obj); string(out) != `{"a":1,"c":3}` {
		t.Errorf("unexpected: %s", out)
	}
}

func TestRejectsTrailingData(t *testing.T) {
	if _, err := Decode([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("expected an error for two concatenated objects, got none")
	}
}

func TestEmptyArrayMarshalsAsArray(t *testing.T) {
	obj, _ := DecodeObject([]byte(`{"alpn":[]}`))
	if out, _ := json.Marshal(obj); string(out) != `{"alpn":[]}` {
		t.Errorf("got %s, want {\"alpn\":[]}", out)
	}
}
