// Package gcpassetsearch fills gaps in cloudlist's GCP coverage (e.g. Cloud SQL)
// with a Cloud Asset Inventory search across the whole organization.
package gcpassetsearch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	s := &AssetSearch{AssetTypes: []string{"sqladmin.googleapis.com/Instance"}}
	if err := o.Decode(s); err != nil {
		return nil, err
	}
	if s.OrganizationID == "" || s.ServiceAccountKey == "" {
		return nil, fmt.Errorf("gcp_asset_search: organization_id and service_account_key are required")
	}
	return s, nil
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
		ips := map[string]bool{}
		collectPublicIPs(structpb.NewStructValue(r.GetAdditionalAttributes()), ips)
		for _, v := range r.GetVersionedResources() {
			collectPublicIPs(structpb.NewStructValue(v.GetResource()), ips)
		}
		for ip := range ips {
			assets = append(assets, model.Asset{
				Provider: "gcp",
				Account:  strings.TrimPrefix(r.GetProject(), "projects/"),
				Kind:     r.GetAssetType(),
				Name:     r.GetName(),
				Target:   ip,
			})
		}
	}
}

// collectPublicIPs walks any resource JSON and keeps every string that is a
// public IP. This works for every asset type without per-type schemas.
func collectPublicIPs(v *structpb.Value, out map[string]bool) {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		if ip, err := netip.ParseAddr(k.StringValue); err == nil && isPublic(ip) {
			out[ip.String()] = true
		}
	case *structpb.Value_StructValue:
		for _, f := range k.StructValue.GetFields() {
			collectPublicIPs(f, out)
		}
	case *structpb.Value_ListValue:
		for _, e := range k.ListValue.GetValues() {
			collectPublicIPs(e, out)
		}
	}
}

func isPublic(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.Is4In6()
}
