// Package config loads config.yaml. Every module gets its own options block;
// ${VAR} references in any value are expanded from the environment.
package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config is the parsed config file.
type Config struct {
	Discovery []Module `yaml:"discovery"`
	Scanners  []Module `yaml:"scanners"`
	Exclude   []string `yaml:"exclude"` // IPs, CIDRs or hostnames never to scan
}

// Module is one entry of the discovery or scanners list.
type Module struct {
	Use     string
	Options Options
}

// Options is a module's own config block, everything except "use".
type Options map[string]any

// Decode fills v (a struct with yaml tags) from the options.
func (o Options) Decode(v any) error {
	b, err := yaml.Marshal(o)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

func (m *Module) UnmarshalYAML(n *yaml.Node) error {
	if err := n.Decode(&m.Options); err != nil {
		return err
	}
	m.Use, _ = m.Options["use"].(string)
	delete(m.Options, "use")
	if m.Use == "" {
		return fmt.Errorf("line %d: module entry needs a 'use' key", n.Line)
	}
	return nil
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator chooses the config path
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses config bytes, expanding ${VAR} after YAML parsing so that
// values like JSON service account keys never need YAML escaping.
func Parse(b []byte) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	if err := expand(&root); err != nil {
		return nil, err
	}
	var c Config
	if err := root.Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

var envRef = regexp.MustCompile(`\$\{(\w+)\}`)

func expand(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var missing string
		n.Value = envRef.ReplaceAllStringFunc(n.Value, func(ref string) string {
			name := envRef.FindStringSubmatch(ref)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = name
			}
			return v
		})
		if missing != "" {
			return fmt.Errorf("line %d: environment variable %s is not set", n.Line, missing)
		}
	}
	for _, c := range n.Content {
		if err := expand(c); err != nil {
			return err
		}
	}
	return nil
}
