package connector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/stretchr/testify/require"
)

var (
	batonApiToken = os.Getenv("BATON_API_TOKEN")
	batonDomain   = os.Getenv("BATON_DOMAIN")
	// A user in the test org that holds no standard admin role before this
	// test runs -- it assigns and revokes every role in turn.
	roleDriftTestUserID = os.Getenv("BATON_ROLE_DRIFT_TEST_USER_ID")
	ctxTest             = context.Background()
)

// waitForPrivilegeGrantRoleLabel polls the System Log for the ROLE target's
// displayName on the most recent user.account.privilege.grant event for userID
// published at or after since. This is the label production actually matches
// against (StandardRoleTypeFromLabel), which can differ from what the
// role-assignment API reports for the same role. Returns "" without error if
// nothing showed up within the wait budget -- System Log indexing lag varies
// widely (seconds to over a minute), so a miss here isn't necessarily a bug.
//
// Known limitation: correlation is "most recent grant for this user", not a
// specific assignment -- the role-assignment API's Id is not the same value as
// the ROLE target's AlternateId in the log (confirmed against a live tenant), so
// there's no precise per-call correlator available here. If a subtest somehow
// finished in under ~1s, this could read the previous subtest's event instead.
func waitForPrivilegeGrantRoleLabel(ctx context.Context, client *okta.Client, userID string, since time.Time) (string, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		logs, _, err := client.LogEvent.GetLogs(ctx, &query.Params{
			Filter: `eventType eq "user.account.privilege.grant" and target.type eq "User" and target.type eq "ROLE"`,
			Since:  since.UTC().Format(time.RFC3339),
			Limit:  50,
		})
		if err != nil {
			return "", err
		}

		for i := len(logs) - 1; i >= 0; i-- {
			var roleLabel string
			var forUser bool
			for _, target := range logs[i].Target {
				switch target.Type {
				case "User":
					forUser = forUser || target.Id == userID
				case "ROLE":
					roleLabel = target.DisplayName
				}
			}
			if forUser && roleLabel != "" {
				return roleLabel, nil
			}
		}

		if time.Now().After(deadline) {
			return "", nil
		}
		time.Sleep(5 * time.Second)
	}
}

// Assigns each standard role to a live test user and checks StandardRoleTypeFromLabel
// resolves what Okta actually returns -- both from the role-assignment API and from
// the System Log directly, since the two have been observed to disagree for the same
// role (SUPER_ADMIN), and only the System Log's label is what production matches on.
func TestStandardRoleTypesMatchOkta(t *testing.T) {
	if batonApiToken == "" || batonDomain == "" || roleDriftTestUserID == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	for _, want := range standardRoleTypes {
		t.Run(want.Type, func(t *testing.T) {
			since := time.Now().Add(-time.Second)

			assigned, _, err := cliTest.client.User.AssignRoleToUser(ctxTest, roleDriftTestUserID, okta.AssignRoleRequest{Type: want.Type}, nil)
			require.Nil(t, err)
			require.NotNil(t, assigned)

			defer func() {
				_, err := cliTest.client.User.RemoveRoleFromUser(ctxTest, roleDriftTestUserID, assigned.Id)
				require.Nil(t, err)
			}()

			resolved := StandardRoleTypeFromLabel(assigned.Label)
			require.NotNil(t, resolved,
				"Okta's role-assignment API returned label %q for %s, which StandardRoleTypeFromLabel doesn't resolve -- "+
					"add it to oktaSystemLogLabels, or the event feed will silently drop this role's grant/revoke events",
				assigned.Label, want.Type)
			require.Equal(t, want.Type, resolved.Type)

			logLabel, err := waitForPrivilegeGrantRoleLabel(ctxTest, cliTest.client, roleDriftTestUserID, since)
			require.Nil(t, err)
			if logLabel == "" {
				t.Skip("System Log hadn't indexed this grant within the wait budget -- rerun to check this role")
			}

			resolved = StandardRoleTypeFromLabel(logLabel)
			require.NotNil(t, resolved,
				"Okta's System Log reported label %q for %s, which StandardRoleTypeFromLabel doesn't resolve -- "+
					"add it to oktaSystemLogLabels, or the event feed will silently drop this role's grant/revoke events",
				logLabel, want.Type)
			require.Equal(t, want.Type, resolved.Type)
		})
	}
}

func TestSyncRoles(t *testing.T) {
	var (
		token = "{}"
		empty = ""
	)
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	r := &roleResourceType{
		resourceType: resourceTypeRole,
		connector:    cliTest,
	}

	for token != empty {
		res, results, err := r.List(ctxTest, &v2.ResourceId{}, sdkResource.SyncOpAttrs{
			PageToken: pagination.Token{Token: token},
		})
		require.Nil(t, err)
		require.NotNil(t, res)
		token = results.NextPageToken
	}
}

func TestUserResourceTypeList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &userResourceType{
		resourceType: resourceTypeUser,
		connector:    cliTest,
	}
	res, _, err := o.List(ctxTest, &v2.ResourceId{}, sdkResource.SyncOpAttrs{
		PageToken: pagination.Token{},
	})
	require.Nil(t, err)
	require.NotNil(t, res)

	oktaUsers, resp, err := o.connector.client.User.ListAssignedRolesForUser(ctxTest, "00ujp5a9z0rMTsPRW697", nil)
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

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	resource := &roleResourceType{
		resourceType: resourceTypeRole,
		connector:    cliTest,
	}
	rs, err := getRoleResourceForTesting("READ_ONLY_ADMIN", "test", "")
	require.Nil(t, err)

	for token != empty {
		grants, results, err := resource.Grants(ctxTest, rs, sdkResource.SyncOpAttrs{
			PageToken: pagination.Token{Token: token},
		})
		require.Nil(t, err)
		require.NotNil(t, grants)
		token = results.NextPageToken
	}
}

func TestRoleResourceTypeGrant(t *testing.T) {
	var roleEntitlement string
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
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
	resource, err := getRoleResourceForTesting(data[1], "Read-Only Administrator", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, grantPrincipalType, roleEntitlement)
	r := &roleResourceType{
		resourceType: resourceTypeRole,
		connector:    cliTest,
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

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	// resource-set:iamkuwy3gqcfNexfQ697:bindings:custom-role:cr0kuwv5507zJCtSy697
	principalID := &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: "cr0kuwv5507zJCtSy697"}
	resource, err := getResourceSetForTesting("iamkuwy3gqcfNexfQ697", "resourceset_local", "resourceset_local Resource Set Binding ")
	require.Nil(t, err)

	gr := grant.NewGrant(resource, bindingEntitlement, principalID)
	annos := annotations.Annotations(gr.Annotations)
	gr.Annotations = annos
	require.NotNil(t, gr)

	r := &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
	}
	// it removes everything associated to custom-role-id
	_, err = r.Revoke(ctxTest, gr)
	require.Nil(t, err)
}

func TestResourceSetsList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsResourceType{
		resourceType: resourceTypeUser,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
	}
	res, _, err := o.List(ctxTest, &v2.ResourceId{}, sdkResource.SyncOpAttrs{
		PageToken: pagination.Token{},
	})
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetsBindingsList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeUser,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
		domain:       batonDomain,
	}
	res, _, err := o.List(ctxTest, &v2.ResourceId{}, sdkResource.SyncOpAttrs{
		PageToken: pagination.Token{},
	})
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetGrants(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
	}

	rs, err := getResourceSetForTesting("iamju0t17k506Mo3x697", "test", "")
	require.Nil(t, err)

	grants, _, err := o.Grants(ctxTest, rs, sdkResource.SyncOpAttrs{
		PageToken: pagination.Token{},
	})
	require.Nil(t, err)
	require.NotNil(t, grants)
}

func TestResourceSetBindingsGrants(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
	}

	rs, err := getResourceSetBindingsResourceForTesting("iamju0t17k506Mo3x697:cr0kp21kkuhjwMgRP697", "test", "")
	require.Nil(t, err)

	grants, _, err := o.Grants(ctxTest, rs, sdkResource.SyncOpAttrs{
		PageToken: pagination.Token{},
	})
	require.Nil(t, err)
	require.NotNil(t, grants)
}

func TestListResourceSetsBindings(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	resourceSetId := "iamju0t17k506Mo3x697"
	res, _, err := listBindings(ctxTest, cliTest.client, resourceSetId)
	require.Nil(t, err)
	require.NotNil(t, res)
}

func TestResourceSetBidingUserGrant(t *testing.T) {
	var entitlementName string
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
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
	resource, err := getResourceSetBindingsResourceForTesting(data[1]+":"+data[2], "", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, resourceTypeResourceSetsBindings.Id, entitlementName)
	r := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
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

	cliTest, err := getClientForTesting(ctxTest, &cfg.Okta{
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
	resource, err := getResourceSetBindingsResourceForTesting(data[1]+":"+data[2], "", "")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, resourceTypeResourceSetsBindings.Id, entitlementName)
	r := &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       batonDomain,
		client:       cliTest.client,
		clientV5:     cliTest.clientV5,
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

func getRoleResourceForTesting(id, label, ctype string) (*v2.Resource, error) {
	return roleResource(&okta.Role{
		Id:    id,
		Label: label,
		Type:  ctype,
	}, resourceTypeRole)
}

func getResourceSetBindingsResourceForTesting(id, label, description string) (*v2.Resource, error) {
	return resourceSetsBindingsResource(&ResourceSets{
		ID:          id,
		Label:       label,
		Description: description,
	}, nil)
}

func getResourceSetForTesting(id, label, ctype string) (*v2.Resource, error) {
	return resourceSetsResource(&ResourceSets{
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

func getClientForTesting(ctx context.Context, oktaCfg *cfg.Okta) (*Okta, error) {
	opts := &cli.ConnectorOpts{}

	connector, _, err := New(ctx, oktaCfg, opts)
	if err != nil {
		return nil, err
	}

	oktaConnector, ok := connector.(*Okta)
	if !ok {
		return nil, fmt.Errorf("failed to cast connector to *Okta")
	}

	return oktaConnector, nil
}
