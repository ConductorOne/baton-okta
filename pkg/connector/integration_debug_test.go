package connector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
)

var (
	batonApiToken = os.Getenv("BATON_API_TOKEN")
	batonDomain   = os.Getenv("BATON_DOMAIN")
	ctxTest       = context.Background()
)

func TestSyncRoles(t *testing.T) {
	var (
		token = "{}"
		empty = ""
	)
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	r := &roleResourceType{
		resourceType: resourceTypeRole,
		client:       cliTest.client,
	}

	for token != empty {
		res, tk, _, err := r.List(ctxTest, &v2.ResourceId{}, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		require.NotNil(t, res)
		token = tk
	}
}

func TestUserResourceTypeList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &userResourceType{
		resourceType: resourceTypeUser,
		client:       cliTest.client,
	}
	res, _, _, err := o.List(ctxTest, &v2.ResourceId{}, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, res)

	oktaUsers, resp, err := o.client.User.ListAssignedRolesForUser(ctxTest, "00ujp5a9z0rMTsPRW697", nil)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, oktaUsers)
}

func TestRoleResourceTypeGrants(t *testing.T) {
	var (
		empty = ""
		token = "{}"
	)
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	resource := &roleResourceType{
		resourceType: resourceTypeRole,
		domain:       batonDomain,
		apiToken:     batonApiToken,
		client:       cliTest.client,
	}
	rs, err := getRoleResourceForTesting(ctxTest, "READ_ONLY_ADMIN", "test", "")
	require.Nil(t, err)

	for token != empty {
		grants, tk, _, err := resource.Grants(ctxTest, rs, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		require.NotNil(t, grants)
		token = tk
	}
}

func TestRoleResourceTypeGrant(t *testing.T) {
	var roleEntitlement string
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	// --grant-entitlement role:READ_ONLY_ADMIN:assigned
	grantEntitlement := "role:READ_ONLY_ADMIN:assigned"
	// --grant-principal-type user
	grantPrincipalType := "user"
	// --grant-principal "00ujp5a9z0rMTsPRW697"
	grantPrincipal := "00ujp5a9z0rMTsPRW697"
	_, data, err := parseEntitlementID(grantEntitlement)
	require.Nil(t, err)
	require.NotNil(t, data)

	roleEntitlement = data[2]
	resource, err := getRoleResourceForTesting(ctxTest, data[1], "Read-Only Administrator", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, grantPrincipalType, roleEntitlement)
	r := &roleResourceType{
		resourceType: resourceTypeRole,
		client:       cliTest.client,
	}
	_, err = r.Grant(ctxTest, &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeUser.Id,
			Resource:     grantPrincipal,
		},
	}, entitlement)
	require.Nil(t, err)
}

func TestResourcSetRevoke(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	// resource-set:iamkuwy3gqcfNexfQ697:bindings:custom-role:cr0kuwv5507zJCtSy697
	principalID := &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: "cr0kuwv5507zJCtSy697"}
	resource, err := getResourceSetForTesting(ctxTest, "iamkuwy3gqcfNexfQ697", "resourceset_local", "resourceset_local Resource Set Binding ")
	require.Nil(t, err)

	gr := grant.NewGrant(resource, bindingEntitlement, principalID)
	annos := annotations.Annotations(gr.Annotations)
	gr.Annotations = annos
	require.NotNil(t, gr)

	r := &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		client:       cliTest.client,
	}
	// it removes everything associated to custom-role-id
	_, err = r.Revoke(ctxTest, gr)
	require.Nil(t, err)
}

func TestResourceSetsList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsResourceType{
		resourceType: resourceTypeUser,
		client:       cliTest.client,
	}
	res, _, _, err := o.List(ctxTest, &v2.ResourceId{}, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetsBindingsList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeUser,
		client:       cliTest.client,
	}
	res, _, _, err := o.List(ctxTest, &v2.ResourceId{}, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetGrants(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		client:       cliTest.client,
	}

	rs, err := getResourceSetForTesting(ctxTest, "iamju0t17k506Mo3x697", "test", "")
	require.Nil(t, err)

	grants, _, _, err := o.Grants(ctxTest, rs, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, grants)
}

func TestResourceSetBindingsGrants(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
	}

	rs, err := getResourceSetBindingsResourceForTesting(ctxTest, "iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697", "test", "")
	require.Nil(t, err)

	grants, _, _, err := o.Grants(ctxTest, rs, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, grants)
}

func TestListResourceSetsBindings(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	resourceSetId := "iamju0t17k506Mo3x697"
	res, _, err := listBindings(ctxTest, cliTest.client, resourceSetId, nil)
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetBidingUserGrant(t *testing.T) {
	var entitlementName string
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	// --grant-entitlement "resourceset-binding:iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697:member"
	grantEntitlement := "resourceset-binding:iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697:member"
	// --grant-principal-type user
	grantPrincipalType := "user"
	// --grant-principal "00ujp5a9z0rMTsPRW697"
	grantPrincipal := "00ujp5atex1LouMvW697"
	_, data, err := parseBindingEntitlementID(grantEntitlement)
	require.Nil(t, err)
	require.NotNil(t, data)

	entitlementName = data[3]
	resource, err := getResourceSetBindingsResourceForTesting(ctxTest, data[1]+":"+data[2], "", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, resourceTypeResourceSetsBindings.Id, entitlementName)
	r := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
	}
	_, err = r.Grant(ctxTest, &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: grantPrincipalType,
			Resource:     grantPrincipal,
		},
	}, entitlement)
	require.Nil(t, err)
}

func TestResourceSetBidingGroupGrant(t *testing.T) {
	var entitlementName string
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	// --grant-entitlement "resourceset-binding:iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697:member"
	grantEntitlement := "resourceset-binding:iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697:member"
	// --grant-principal-type user
	grantPrincipalType := "group"
	// --grant-principal "00ujp5a9z0rMTsPRW697"
	grantPrincipal := "00gjp5attgbHSymFZ697"
	_, data, err := parseBindingEntitlementID(grantEntitlement)
	require.Nil(t, err)
	require.NotNil(t, data)

	entitlementName = data[3]
	resource, err := getResourceSetBindingsResourceForTesting(ctxTest, data[1]+":"+data[2], "", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, resourceTypeResourceSetsBindings.Id, entitlementName)
	r := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
	}
	_, err = r.Grant(ctxTest, &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: grantPrincipalType,
			Resource:     grantPrincipal,
		},
	}, entitlement)
	require.Nil(t, err)
}

func parseEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 3 || len(parts) > 3 {
		return nil, nil, fmt.Errorf("okta-connector: invalid resource id")
	}

	resourceId := &v2.ResourceId{
		ResourceType: parts[0],
		Resource:     strings.Join(parts[1:len(parts)-1], ":"),
	}

	return resourceId, parts, nil
}

func parseBindingEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 4 || len(parts) > 4 {
		return nil, nil, fmt.Errorf("okta-connector: invalid resource id")
	}

	resourceId := &v2.ResourceId{
		ResourceType: parts[0],
		Resource:     strings.Join(parts[1:len(parts)-1], ":"),
	}

	return resourceId, parts, nil
}

func getRoleResourceForTesting(ctxTest context.Context, id, label, ctype string) (*v2.Resource, error) {
	return roleResource(ctxTest, &okta.Role{
		Id:    id,
		Label: label,
		Type:  ctype,
	}, resourceTypeRole)
}

func getResourceSetBindingsResourceForTesting(ctxTest context.Context, id, label, description string) (*v2.Resource, error) {
	return resourceSetsBindingsResource(ctxTest, &ResourceSets{
		ID:          id,
		Label:       label,
		Description: description,
	}, nil)
}

func getResourceSetForTesting(ctxTest context.Context, id, label, ctype string) (*v2.Resource, error) {
	return resourceSetsResource(ctxTest, &ResourceSets{
		ID:          id,
		Label:       label,
		Description: ctype,
	}, nil)
}

func getEntitlementForTesting(resource *v2.Resource, resourceDisplayName, entitlement string) *v2.Entitlement {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeRole),
		ent.WithDisplayName(fmt.Sprintf("%s resource %s", resourceDisplayName, entitlement)),
		ent.WithDescription(fmt.Sprintf("%s of %s okta", entitlement, resourceDisplayName)),
	}

	return ent.NewAssignmentEntitlement(resource, entitlement, options...)
}

func getClietForTesting(ctx context.Context, cfg *Config) (*Okta, error) {
	var oktaClient *okta.Client
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	if cfg.ApiToken != "" && cfg.Domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cfg.Domain)),
			okta.WithToken(cfg.ApiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(cfg.Cache),
			okta.WithCacheTti(cfg.CacheTTI),
			okta.WithCacheTtl(cfg.CacheTTL),
		)
		if err != nil {
			return nil, err
		}
	}

	return &Okta{
		client:           oktaClient,
		domain:           cfg.Domain,
		apiToken:         cfg.ApiToken,
		syncInactiveApps: cfg.SyncInactiveApps,
		ciamConfig: &ciamConfig{
			Enabled:      cfg.Ciam,
			EmailDomains: cfg.CiamEmailDomains,
		},
	}, nil
}
