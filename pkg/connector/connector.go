package connector

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

// TODO: use isNotFoundError() since E0000008 is also a not found error
const ResourceNotFoundExceptionErrorCode = "E0000007"
const AccessDeniedErrorCode = "E0000006"

type Okta struct {
	client              *okta.Client
	clientV5            *oktav5.APIClient
	domain              string
	apiToken            string
	syncInactiveApps    bool
	ciamConfig          *ciamConfig
	syncCustomRoles     bool
	skipSecondaryEmails bool
	SyncSecrets         bool
	userFilters         *userFilterConfig
}

type ciamConfig struct {
	Enabled      bool
	EmailDomains []string
}

type userFilterConfig struct {
	includedEmailDomains []string
}

func v1AnnotationsForResourceType(resourceTypeID string, skipEntitlementsAndGrants bool) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.V1Identifier{
		Id: resourceTypeID,
	})

	if skipEntitlementsAndGrants {
		annos.Update(&v2.SkipEntitlementsAndGrants{})
	}

	return annos
}

var (
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsForResourceType("role", false),
	}
	resourceTypeCustomRole = &v2.ResourceType{
		Id:          "custom-role",
		DisplayName: "Custom Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsForResourceType("custom-role", false),
	}
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: v1AnnotationsForResourceType("user", true),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsForResourceType("group", false),
	}
	resourceTypeApp = &v2.ResourceType{
		Id:          "app",
		DisplayName: "App",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: v1AnnotationsForResourceType("app", false),
	}
	resourceTypeResourceSets = &v2.ResourceType{
		Id:          "resource-set",
		DisplayName: "Resource Set",
		Annotations: v1AnnotationsForResourceType("resource-set", false),
	}
	resourceTypeResourceSetsBindings = &v2.ResourceType{
		Id:          "resourceset-binding",
		DisplayName: "Resource Set Binding",
		Annotations: v1AnnotationsForResourceType("resourceset-binding", false),
	}
	resourceTypeApiToken = &v2.ResourceType{
		Id:          "api-token",
		DisplayName: "API Token",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: v1AnnotationsForResourceType("api-token", true),
	}
	defaultScopes = []string{
		"okta.users.read",
		"okta.groups.read",
		"okta.roles.read",
		"okta.apps.read",
	}
	provisioningScopes = []string{
		"okta.users.manage",
		"okta.groups.manage",
		"okta.roles.manage",
		"okta.apps.manage",
	}

	// TODO (santhosh) Add required scopes for secrets sync
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	if o.ciamConfig.Enabled {
		return []connectorbuilder.ResourceSyncerV2{
			ciamUserBuilder(o),
			ciamBuilder(o.client, o.skipSecondaryEmails),
		}
	}

	resourceSyncer := []connectorbuilder.ResourceSyncerV2{
		roleBuilder(o.client, o),
		userBuilder(o),
		groupBuilder(o),
		appBuilder(o.domain, o.apiToken, o.syncInactiveApps, o.userFilters.includedEmailDomains, o.client),
	}

	if o.syncCustomRoles {
		resourceSyncer = append(resourceSyncer,
			customRoleBuilder(o),
			resourceSetsBuilder(o.domain, o.client, o.clientV5),
			resourceSetsBindingsBuilder(o.domain, o.client, o.clientV5),
		)
	}

	if o.SyncSecrets {
		resourceSyncer = append(resourceSyncer, apiTokenBuilder(o.clientV5))
	}

	return resourceSyncer
}

func (c *Okta) ListResourceTypes(ctx context.Context, request *v2.ResourceTypesServiceListResourceTypesRequest) (*v2.ResourceTypesServiceListResourceTypesResponse, error) {
       resourceTypes := []*v2.ResourceType{
               resourceTypeUser,
               resourceTypeGroup,
               resourceTypeRole,
               resourceTypeApp,
       }

       if c.syncCustomRoles {
               resourceTypes = append(resourceTypes, resourceTypeCustomRole, resourceTypeResourceSets, resourceTypeResourceSetsBindings)
       }

       if c.SyncSecrets {
               resourceTypes = append(resourceTypes, resourceTypeApiToken)
       }

       return &v2.ResourceTypesServiceListResourceTypesResponse{
               List: resourceTypes,
       }, nil
}

func (c *Okta) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	_, err := c.Validate(ctx)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(&v2.ExternalLink{
		Url: c.domain,
	})

	return &v2.ConnectorMetadata{
		DisplayName: "Okta",
		Description: "The Okta connector syncs user, group, role, and app data from Okta",
		Annotations: annos,
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"first_name": {
					DisplayName: "First Name",
					Required:    true,
					Description: "This first name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "First name",
					Order:       1,
				},
				"last_name": {
					DisplayName: "Last Name",
					Required:    true,
					Description: "This last name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Last name",
					Order:       2,
				},
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "This will be the email of the user. If login is unset this is also the login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Email",
					Order:       3,
				},
				"login": {
					DisplayName: "Login",
					Required:    false,
					Description: "This login will be used as the login for the user. Email will be used if login is not present.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Login",
					Order:       4,
				},
				"password_change_on_login_required": {
					DisplayName: "Password Change Required on Login",
					Required:    false,
					Description: "When creating accounts with a random password setting this to 'true' will require the user to change their password on first login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "True/False",
					Order:       5,
				},
			},
		},
	}, nil
}

func (c *Okta) Validate(ctx context.Context) (annotations.Annotations, error) {
	if c.apiToken == "" {
		return nil, nil
	}

	token := newPaginationToken(defaultLimit, "")

	_, respCtx, err := getOrgSettings(ctx, c.client, token)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to fetch org: %w", err)
	}

	_, _, err = parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to parse response: %w", err)
	}

	if respCtx.OktaResponse.StatusCode != http.StatusOK {
		err := fmt.Errorf("okta-connector: verify returned non-200: '%d'", respCtx.OktaResponse.StatusCode)
		return nil, err
	}

	return nil, nil
}

func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, fmt.Errorf("not implemented")
}

func safeCacheInt32(val int) (int32, error) {
	if val > math.MaxInt32 || val < 0 {
		return 0, fmt.Errorf("value %d is out of range for int32", val)
	}
	return int32(val), nil
}

func New(ctx context.Context, cc *cfg.Okta, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	var (
		oktaClient *okta.Client
		scopes     = defaultScopes
	)
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, nil, err
	}

	cacheTTI, err := safeCacheInt32(cc.CacheTti)
	if err != nil {
		return nil, nil, err
	}

	cacheTTL, err := safeCacheInt32(cc.CacheTtl)
	if err != nil {
		return nil, nil, err
	}

	var oktaClientV5 *oktav5.APIClient

	if cc.ApiToken != "" && cc.Domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			okta.WithToken(cc.ApiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(cc.Cache),
			okta.WithCacheTti(cacheTTI),
			okta.WithCacheTtl(cacheTTL),
		)
		if err != nil {
			return nil, nil, err
		}

		config, err := oktav5.NewConfiguration(
			oktav5.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			oktav5.WithToken(cc.ApiToken),
			oktav5.WithHttpClientPtr(client),
			oktav5.WithCache(cc.Cache),
			oktav5.WithCacheTti(cacheTTI),
			oktav5.WithCacheTtl(cacheTTL),
			oktav5.WithRateLimitPrevent(true),
		)
		if err != nil {
			return nil, nil, err
		}
		oktaClientV5 = oktav5.NewAPIClient(config)
	}

	if cc.OktaClientId != "" && cc.OktaPrivateKey != "" && cc.Domain != "" {
		if cc.OktaProvisioning {
			scopes = append(scopes, provisioningScopes...)
		}

		if cc.SyncSecrets {
			scopes = append(scopes, "okta.apiTokens.read")
		}

		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			okta.WithAuthorizationMode("PrivateKey"),
			okta.WithClientId(cc.OktaClientId),
			okta.WithScopes(scopes),
			okta.WithPrivateKey(cc.OktaPrivateKey),
			okta.WithPrivateKeyId(cc.OktaPrivateKeyId),
			okta.WithCache(cc.Cache),
			okta.WithCacheTti(cacheTTI),
			okta.WithCacheTtl(cacheTTL),
		)
		if err != nil {
			return nil, nil, err
		}

		config, err := oktav5.NewConfiguration(
			oktav5.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			oktav5.WithAuthorizationMode("PrivateKey"),
			oktav5.WithClientId(cc.OktaClientId),
			oktav5.WithScopes(scopes),
			oktav5.WithPrivateKey(cc.OktaPrivateKey),
			oktav5.WithPrivateKeyId(cc.OktaPrivateKeyId),
			oktav5.WithCache(cc.Cache),
			oktav5.WithCacheTti(cacheTTI),
			oktav5.WithCacheTtl(cacheTTL),
			oktav5.WithRateLimitPrevent(true),
		)
		if err != nil {
			return nil, nil, err
		}
		oktaClientV5 = oktav5.NewAPIClient(config)
	}

	return &Okta{
		client:              oktaClient,
		clientV5:            oktaClientV5,
		domain:              cc.Domain,
		apiToken:            cc.ApiToken,
		syncInactiveApps:    cc.SyncInactiveApps,
		syncCustomRoles:     cc.SyncCustomRoles,
		skipSecondaryEmails: cc.SkipSecondaryEmails,
		SyncSecrets:         cc.SyncSecrets,
		ciamConfig: &ciamConfig{
			Enabled:      cc.Ciam,
			EmailDomains: cc.CiamEmailDomains,
		},
		userFilters: &userFilterConfig{
			includedEmailDomains: lowerEmailDomains(cc.FilterEmailDomains),
		},
	}, nil, nil
}

func lowerEmailDomains(emailDomains []string) []string {
	var loweredDomains []string
	for _, domain := range emailDomains {
		loweredDomains = append(loweredDomains, strings.ToLower(domain))
	}
	return loweredDomains
}

type AppUserSchema struct {
	Definitions struct {
		Base struct {
			Properties struct {
				SamlRoles struct {
					Union string `json:"union,omitempty"`
				} `json:"samlRoles,omitempty"`
			} `json:"properties"`
		} `json:"base"`
	} `json:"definitions"`
}

// Cache namespace prefixes.
var (
	userFilterPrefix = sessions.WithPrefix("userFilter")
	userRolePrefix = sessions.WithPrefix("userRole")
)

func (o *Okta) getUserFilterFromCache(ctx context.Context, ss sessions.SessionStore, userId string) (bool, bool, error) {
	result, found, err := session.GetJSON[bool](ctx, ss, userId, userFilterPrefix)
	if err != nil {
		return false, false, err
	} else if !found {
		return false, false, nil
	}
	return result, true, nil
}

func (o *Okta) setUserFilterInCache(ctx context.Context, ss sessions.SessionStore, userId string, shouldInclude bool) error {
	return session.SetJSON(ctx, ss, userId, shouldInclude, userFilterPrefix)
}

// shouldIncludeUser checks if the user has the right email domain without caching.
// This should be used when the session store is not available.
func (o *Okta) shouldIncludeUser(user *okta.User) bool {
	if len(o.userFilters.includedEmailDomains) == 0 {
		return true
	}

	userEmails := extractEmailsFromUserProfile(user)
	return shouldIncludeUserByEmails(userEmails, o.userFilters.includedEmailDomains)
}

// shouldIncludeUserAndSetCache checks if the user has the right email domain while *also* caching the result.
func (o *Okta) shouldIncludeUserAndSetCache(ctx context.Context, ss sessions.SessionStore, user *okta.User) bool {
	shouldInclude := o.shouldIncludeUser(user)

	// only bother caching if email filters are set
	if len(o.userFilters.includedEmailDomains) > 0 {
		_ = o.setUserFilterInCache(ctx, ss, user.Id, shouldInclude)
	}

	return shouldInclude
}

// shouldIncludeUserFromCache checks the cache to see if the user has the right email domain and returns that result (and if found).
func (o *Okta) shouldIncludeUserFromCache(ctx context.Context, ss sessions.SessionStore, userId string) (bool, bool) {
	// don't bother reading from cache if no email filters are set
	if len(o.userFilters.includedEmailDomains) == 0 {
		return true, true
	}

	result, found, err := o.getUserFilterFromCache(ctx, ss, userId)
	if err != nil || !found {
		return false, false
	}

	return result, true
}

// getBatchUserRolesFromCache retrieves multiple users' role sets from the session store in one call.
func (o *Okta) getBatchUserRolesFromCache(ctx context.Context, ss sessions.SessionStore, userIDs []string) (map[string]mapset.Set[string], error) {
	if len(userIDs) == 0 {
		return make(map[string]mapset.Set[string]), nil
	}

	rolesMap, err := session.GetManyJSON[[]string](ctx, ss, userIDs, userRolePrefix)
	if err != nil {
		return nil, err
	}

	// Convert all role sets to mapset.Sets.
	result := make(map[string]mapset.Set[string], len(rolesMap))
	for userId, roleSlice := range rolesMap {
		result[userId] = mapset.NewSet[string](roleSlice...)
	}

	return result, nil
}

func (o *Okta) setBatchUserRolesInCache(ctx context.Context, ss sessions.SessionStore, userRoles map[string]mapset.Set[string]) error {
	if len(userRoles) == 0 {
		return nil
	}

	toCache := make(map[string][]string, len(userRoles))
	for userId, roleSet := range userRoles {
		toCache[userId] = roleSet.ToSlice()
	}

	return session.SetManyJSON(ctx, ss, toCache, userRolePrefix)
}
