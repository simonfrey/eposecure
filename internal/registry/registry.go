// Package registry defines the module interfaces and maps config names to
// implementations. Adding a module: write the package, add one line below.
package registry

import (
	"context"
	"fmt"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/discovery/cloudlist"
	"github.com/simonfrey/exposure-scanner/internal/discovery/dns"
	"github.com/simonfrey/exposure-scanner/internal/discovery/gcpassetsearch"
	"github.com/simonfrey/exposure-scanner/internal/discovery/staticlist"
	"github.com/simonfrey/exposure-scanner/internal/model"
	"github.com/simonfrey/exposure-scanner/internal/scanners/cvelookup"
	"github.com/simonfrey/exposure-scanner/internal/scanners/exploitintel"
	"github.com/simonfrey/exposure-scanner/internal/scanners/httpx"
	"github.com/simonfrey/exposure-scanner/internal/scanners/naabu"
	"github.com/simonfrey/exposure-scanner/internal/scanners/nuclei"
)

// Discoverer lists public-facing assets from one source.
type Discoverer interface {
	Name() string
	Discover(ctx context.Context) ([]model.Asset, error)
}

// Scanner reads targets, endpoints and findings from the context and adds its own.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, sc *model.ScanContext) error
}

var discoverers = map[string]func(config.Options) (Discoverer, error){
	"static_list":      adapt[Discoverer](staticlist.New),
	"cloudlist":        adapt[Discoverer](cloudlist.New),
	"gcp_asset_search": adapt[Discoverer](gcpassetsearch.New),
	"dns":              adapt[Discoverer](dns.New),
}

var scanners = map[string]func(config.Options) (Scanner, error){
	"naabu":         adapt[Scanner](naabu.New),
	"httpx":         adapt[Scanner](httpx.New),
	"nuclei":        adapt[Scanner](nuclei.New),
	"cve_lookup":    adapt[Scanner](cvelookup.New),
	"exploit_intel": adapt[Scanner](exploitintel.New),
}

// Discoverers builds the configured discovery modules in order.
func Discoverers(mods []config.Module) ([]Discoverer, error) { return build(discoverers, mods) }

// Scanners builds the configured scanners in order.
func Scanners(mods []config.Module) ([]Scanner, error) { return build(scanners, mods) }

func build[T any](known map[string]func(config.Options) (T, error), mods []config.Module) ([]T, error) {
	out := make([]T, 0, len(mods))
	for _, m := range mods {
		ctor, ok := known[m.Use]
		if !ok {
			return nil, fmt.Errorf("unknown module %q", m.Use)
		}
		v, err := ctor(m.Options)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.Use, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// adapt turns a constructor returning a concrete type into one returning the interface.
func adapt[I any, T any](ctor func(config.Options) (T, error)) func(config.Options) (I, error) {
	return func(o config.Options) (I, error) {
		v, err := ctor(o)
		if err != nil {
			var zero I
			return zero, err
		}
		return any(v).(I), nil
	}
}
