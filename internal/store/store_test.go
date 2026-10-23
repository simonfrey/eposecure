package store

import (
	"encoding/json"
	"testing"
)

func TestJSONBStripsNUL(t *testing.T) {
	raw := map[string]string{"response": "+PONG\x00\x01", "literal": `C:\u0000`}
	b := jsonb(raw)
	var back map[string]string
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("invalid JSON %s: %v", b, err)
	}
	if back["response"] != "+PONG\uFFFD\x01" {
		t.Errorf("response = %q", back["response"])
	}
	if back["literal"] != `C:\u0000` {
		t.Errorf("escaped backslash changed: %q", back["literal"])
	}
}
