package config

import "testing"

func TestParseExpandsEnvAfterYAML(t *testing.T) {
	// A JSON key with quotes, colons and newlines must survive untouched.
	key := `{"type": "service_account", "private_key": "-----BEGIN\nabc\n-----END"}` // #nosec G101 -- fake test key
	t.Setenv("SA_KEY", key)
	t.Setenv("ORG", "123456")

	c, err := Parse([]byte(`
discovery:
  - use: cloudlist
    providers:
      - provider: gcp
        gcp_service_account_key: ${SA_KEY}
        organization_id: ${ORG}
scanners:
  - use: naabu
    rate: 100
exclude: [10.0.0.0/8]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Discovery) != 1 || c.Discovery[0].Use != "cloudlist" {
		t.Fatalf("bad discovery: %+v", c.Discovery)
	}
	var opts struct {
		Providers []map[string]string `yaml:"providers"`
	}
	if err := c.Discovery[0].Options.Decode(&opts); err != nil {
		t.Fatal(err)
	}
	if got := opts.Providers[0]["gcp_service_account_key"]; got != key {
		t.Fatalf("key mangled: %q", got)
	}
	if got := opts.Providers[0]["organization_id"]; got != "123456" {
		t.Fatalf("org id: %q", got)
	}

	var naabu struct {
		Rate int `yaml:"rate"`
	}
	if err := c.Scanners[0].Options.Decode(&naabu); err != nil || naabu.Rate != 100 {
		t.Fatalf("naabu options: %+v %v", naabu, err)
	}
	if _, ok := c.Scanners[0].Options["use"]; ok {
		t.Fatal("'use' leaked into options")
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"missing env": "discovery:\n  - use: x\n    key: ${SURELY_NOT_SET_42}\n",
		"missing use": "discovery:\n  - targets: [a]\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
