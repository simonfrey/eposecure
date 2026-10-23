// Package staticlist turns a fixed list of IPs and hostnames from the config into assets.
package staticlist

import (
	"context"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type StaticList struct {
	Targets []string `yaml:"targets"`
}

func New(o config.Options) (*StaticList, error) {
	s := &StaticList{}
	return s, o.Decode(s)
}

func (s *StaticList) Name() string { return "static_list" }

func (s *StaticList) Discover(context.Context) ([]model.Asset, error) {
	assets := make([]model.Asset, 0, len(s.Targets))
	for _, t := range s.Targets {
		assets = append(assets, model.Asset{Provider: "static", Kind: "target", Name: t, Target: t})
	}
	return assets, nil
}
