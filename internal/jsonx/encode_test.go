package jsonx

import "testing"

// The Xray config is compared byte-for-byte against output frozen from the
// Python renderer, so indentation, HTML escaping and the trailing newline all
// have to match json.dumps(indent=2) + "\n" exactly.
func TestEncodeIndentedMatchesPythonJSONDumps(t *testing.T) {
	in := `{"log":{"loglevel":"warning"},"nested":{"a":[1,2,{"b":"x<y&z"}],"empty":{},"list":[]},"n":443}`
	obj, err := DecodeObject([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeIndented(obj)
	if err != nil {
		t.Fatal(err)
	}
	// Captured from: python3 -c 'import json; print(json.dumps(d, indent=2))'
	want := `{
  "log": {
    "loglevel": "warning"
  },
  "nested": {
    "a": [
      1,
      2,
      {
        "b": "x<y&z"
      }
    ],
    "empty": {},
    "list": []
  },
  "n": 443
}
`
	if string(got) != want {
		t.Errorf("output differs from json.dumps(indent=2):\ngot:\n%s\nwant:\n%s", got, want)
	}
}
