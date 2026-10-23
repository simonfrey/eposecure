// Package gcpassetsearch finds every public IP and service URL in a GCP
// organization with a Cloud Asset Inventory search. It overlaps with
// cloudlist on purpose: targets are deduplicated, and anything cloudlist
// does not cover (Cloud SQL, forwarding rules, reserved addresses) is caught.
package gcpassetsearch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type AssetSearch struct {
	OrganizationID    string   `yaml:"organization_id"`
	ServiceAccountKey string   `yaml:"service_account_key"`
	AssetTypes        []string `yaml:"asset_types"`
}

func New(o config.Options) (*AssetSearch, error) {
	s := &AssetSearch{AssetTypes: defaultTypes}
	if err := o.Decode(s); err != nil {
		return nil, err
	}
	if s.OrganizationID == "" || s.ServiceAccountKey == "" {
		return nil, fmt.Errorf("gcp_asset_search: organization_id and service_account_key are required")
	}
	return s, nil
}

// defaultTypes are the resource types that can hold a public address or URL.
// VM instances are left to cloudlist: their metadata can contain unrelated URLs.
var defaultTypes = []string{
	"compute.googleapis.com/Address",
	"compute.googleapis.com/GlobalAddress",
	"compute.googleapis.com/ForwardingRule",
	"compute.googleapis.com/GlobalForwardingRule",
	"container.googleapis.com/Cluster",
	"sqladmin.googleapis.com/Instance",
	"run.googleapis.com/Service",
	"cloudfunctions.googleapis.com/Function",
	"appengine.googleapis.com/Application",
}

func (s *AssetSearch) Name() string { return "gcp_asset_search" }

func (s *AssetSearch) Discover(ctx context.Context) ([]model.Asset, error) {
	client, err := asset.NewClient(ctx, option.WithAuthCredentialsJSON(option.ServiceAccount, []byte(s.ServiceAccountKey)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	it := client.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope:      "organizations/" + s.OrganizationID,
		AssetTypes: s.AssetTypes,
		ReadMask:   &fieldmaskpb.FieldMask{Paths: []string{"*"}}, // include versioned resources
	})
	var assets []model.Asset
	for {
		r, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return assets, nil
		}
		if err != nil {
			return nil, err
		}
		targets := map[string]bool{}
		collectTargets(structpb.NewStructValue(r.GetAdditionalAttributes()), targets)
		for _, v := range r.GetVersionedResources() {
			collectTargets(structpb.NewStructValue(v.GetResource()), targets)
		}
		for t := range targets {
			assets = append(assets, model.Asset{
				Provider: "gcp",
				Account:  strings.TrimPrefix(r.GetProject(), "projects/"),
				Kind:     r.GetAssetType(),
				Name:     r.GetName(),
				Target:   t,
			})
		}
	}
}

// collectTargets walks any resource JSON and keeps every public IP and the
// host of every URL on a Google serving domain (Cloud Run, Functions, App
// Engine, Firebase). Other URLs are never targets: they may belong to third
// parties. This works for every asset type without per-type schemas.
func collectTargets(v *structpb.Value, out map[string]bool) {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		s := k.StringValue
		if ip, err := netip.ParseAddr(s); err == nil && isPublic(ip) {
			out[ip.String()] = true
		}
		if u, err := url.Parse(s); err == nil && u.Scheme == "https" && googleHosted(u.Hostname()) {
			out[strings.ToLower(u.Hostname())] = true
		}
	case *structpb.Value_StructValue:
		for _, f := range k.StructValue.GetFields() {
			collectTargets(f, out)
		}
	case *structpb.Value_ListValue:
		for _, e := range k.ListValue.GetValues() {
			collectTargets(e, out)
		}
	}
}

// servingDomains host customer services, so their names are the org's endpoints.
var servingDomains = []string{".run.app", ".cloudfunctions.net", ".appspot.com", ".web.app", ".firebaseapp.com"}

func googleHosted(host string) bool {
	host = strings.ToLower(host)
	return slices.ContainsFunc(servingDomains, func(d string) bool { return strings.HasSuffix(host, d) })
}

func isPublic(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.Is4In6()
}
