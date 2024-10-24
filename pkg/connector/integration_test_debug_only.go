package connector

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
)

var (
	batonApiToken           = os.Getenv("BATON_API_TOKEN")
	batonDomain             = os.Getenv("BATON_DOMAIN")
	batonSyncCustomRoles, _ = strconv.ParseBool(os.Getenv("BATON_SYNC_CUSTOM_ROLES"))
	ctxTest                 = context.Background()
)

func TestSyncRoles(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	r := &roleResourceType{
		resourceType:    resourceTypeRole,
		client:          cliTest.client,
		syncCustomRoles: batonSyncCustomRoles,
	}

	var token = "{}"
	for token != "" {
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

func TestRoleResourceTypeGrants(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	resource := &roleResourceType{
		resourceType:    resourceTypeRole,
		domain:          batonDomain,
		apiToken:        batonApiToken,
		client:          cliTest.client,
		syncCustomRoles: true,
	}

	principalID := &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: "09876"}
	gr := grant.NewGrant(&v2.Resource{
		Id:          principalID,
		DisplayName: "",
		Description: "",
	}, "member", principalID)

	grants, _, _, err := resource.Grants(ctxTest, gr.Principal, &pagination.Token{})
	if err != nil {
		panic(err)
	}

	log.Println(grants)
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

	// --grant-entitlement "role:READ_ONLY_ADMIN:assigned"
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
		resourceType:    resourceTypeRole,
		client:          cliTest.client,
		syncCustomRoles: true,
	}
	_, err = r.Grant(ctxTest, &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeUser.Id,
			Resource:     grantPrincipal,
		},
	}, entitlement)
	require.Nil(t, err)
}

func parseEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 3 || len(parts) > 3 {
		return nil, nil, fmt.Errorf("tailscale-connector: invalid resource id")
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
	})
}

func getEntitlementForTesting(resource *v2.Resource, resourceDisplayName, entitlement string) *v2.Entitlement {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeRole),
		ent.WithDisplayName(fmt.Sprintf("%s resource %s", resourceDisplayName, entitlement)),
		ent.WithDescription(fmt.Sprintf("%s of %s okta role", entitlement, resourceDisplayName)),
	}

	return ent.NewAssignmentEntitlement(resource, entitlement, options...)
}
