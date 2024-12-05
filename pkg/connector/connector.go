package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const awsApp = "amazon_aws"
const ResourceNotFoundExceptionErrorCode = "E0000007"
const AccessDeniedErrorCode = "E0000006"
const ExpectedIdentityProviderArnRegexCaptureGroups = 2
const ExpectedGroupNameCaptureGroupsWithGroupFilterForMultipleAWSInstances = 3

type Okta struct {
	client           *okta.Client
	domain           string
	apiToken         string
	syncInactiveApps bool
	ciamConfig       *ciamConfig
	syncCustomRoles  bool
	awsConfig        *awsConfig
}

type ciamConfig struct {
	Enabled      bool
	EmailDomains []string
}

type awsConfig struct {
	Enabled                bool
	OktaAppId              string
	awsAppConfigCacheMutex sync.Mutex
	oktaAWSAppSettings     *oktaAWSAppSettings
}

/*
JoinAllRoles: This option enables merging all available roles assigned to a user as follows:

For example, if a user is directly assigned Role1 and Role2 (user to app assignment),
and the user belongs to group GroupAWS with RoleA and RoleB assigned (group to app assignment), then:

Join all roles OFF: Role1 and Role2 are available upon login to AWS
Join all roles ON: Role1, Role2, RoleA, and RoleB are available upon login to AWS

UseGroupMapping: Use Group Mapping enables CONNECT OKTA TO MULTIPLE AWS INSTANCES VIA USER GROUPS functionality.

IdentityProviderArnRegex: Uses the "Role Value Pattern" to obtain a regular expression to extract the account id.
This is only used when UseGroupMapping is not enabled.

Role Value Pattern: This field takes the AWS role and account ID captured within the syntax of your AWS role groups,
and translates it into the proper syntax AWS requires in Okta’s SAML assertion to allow users to view their accounts and roles when they sign in.

This field should always follow this specific syntax:
arn:aws:iam::${accountid}:saml-provider/[SAML Provider Name],arn:aws:iam::${accountid}:role/${role}
*/
type oktaAWSAppSettings struct {
	JoinAllRoles                 bool
	IdentityProviderArn          string
	RoleRegex                    string
	IdentityProviderArnRegex     string
	UseGroupMapping              bool
	IdentityProviderArnAccountID string
	appGroupCache                sync.Map // group ID to app group cache
	notAppGroupCache             sync.Map // group IDs that are not app groups
}

type Config struct {
	Domain           string
	ApiToken         string
	OktaClientId     string
	OktaPrivateKey   string
	OktaPrivateKeyId string
	SyncInactiveApps bool
	OktaProvisioning bool
	Ciam             bool
	CiamEmailDomains []string
	Cache            bool
	CacheTTI         int32
	CacheTTL         int32
	SyncCustomRoles  bool
	AWSMode          bool
	AWSOktaAppId     string
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
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account",
		DisplayName: "Account",
		Annotations: v1AnnotationsForResourceType("account", false),
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
	// TODO(lauren) use different scopes for aws mode?
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	if o.ciamConfig.Enabled {
		return []connectorbuilder.ResourceSyncer{
			ciamUserBuilder(o.domain, o.apiToken, o.client, o.ciamConfig.EmailDomains),
			ciamBuilder(o.client),
		}
	}

	if o.awsConfig.Enabled {
		return []connectorbuilder.ResourceSyncer{
			userBuilder(o.domain, o.apiToken, o.client),
			groupBuilder(o),
			accountBuilder(o),
		}
	}

	resourceSyncer := []connectorbuilder.ResourceSyncer{
		roleBuilder(o.client, o),
		userBuilder(o.domain, o.apiToken, o.client),
		groupBuilder(o),
		appBuilder(o.domain, o.apiToken, o.syncInactiveApps, o.client),
	}

	if o.syncCustomRoles {
		resourceSyncer = append(resourceSyncer,
			customRoleBuilder(o.domain, o.client),
			resourceSetsBuilder(o.domain, o.client),
			resourceSetsBindingsBuilder(o.domain, o.client),
		)
	}

	return resourceSyncer
}

func (c *Okta) ListResourceTypes(ctx context.Context, request *v2.ResourceTypesServiceListResourceTypesRequest) (*v2.ResourceTypesServiceListResourceTypesResponse, error) {
	resourceTypes := []*v2.ResourceType{
		resourceTypeUser,
		resourceTypeGroup,
	}
	if c.awsConfig != nil && c.awsConfig.Enabled {
		resourceTypes = append(resourceTypes, resourceTypeAccount)
	} else {
		resourceTypes = append(resourceTypes, resourceTypeRole, resourceTypeApp)
	}

	if c.syncCustomRoles {
		resourceTypes = append(resourceTypes, resourceTypeCustomRole, resourceTypeResourceSets, resourceTypeResourceSetsBindings)
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

	if c.awsConfig != nil && c.awsConfig.Enabled {
		_, err = c.getAWSApplicationConfig(ctx)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, fmt.Errorf("not implemented")
}

func New(ctx context.Context, cfg *Config) (*Okta, error) {
	var (
		oktaClient *okta.Client
		scopes     = defaultScopes
	)
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

	if cfg.OktaClientId != "" && cfg.OktaPrivateKey != "" && cfg.Domain != "" {
		if cfg.OktaProvisioning {
			scopes = append(scopes, provisioningScopes...)
		}
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cfg.Domain)),
			okta.WithAuthorizationMode("PrivateKey"),
			okta.WithClientId(cfg.OktaClientId),
			okta.WithScopes(scopes),
			okta.WithPrivateKey(cfg.OktaPrivateKey),
			okta.WithPrivateKeyId(cfg.OktaPrivateKeyId),
			okta.WithCache(cfg.Cache),
			okta.WithCacheTti(cfg.CacheTTI),
			okta.WithCacheTtl(cfg.CacheTTL),
		)
		if err != nil {
			return nil, err
		}
	}

	awsConfig := &awsConfig{
		Enabled:   cfg.AWSMode,
		OktaAppId: cfg.AWSOktaAppId,
	}

	return &Okta{
		client:           oktaClient,
		domain:           cfg.Domain,
		apiToken:         cfg.ApiToken,
		syncInactiveApps: cfg.SyncInactiveApps,
		syncCustomRoles:  cfg.SyncCustomRoles,
		ciamConfig: &ciamConfig{
			Enabled:      cfg.Ciam,
			EmailDomains: cfg.CiamEmailDomains,
		},
		awsConfig: awsConfig,
	}, nil
}

func (c *Okta) getAWSApplicationConfig(ctx context.Context) (*oktaAWSAppSettings, error) {
	if c.awsConfig == nil {
		return nil, nil
	}
	c.awsConfig.awsAppConfigCacheMutex.Lock()
	defer c.awsConfig.awsAppConfigCacheMutex.Unlock()
	if c.awsConfig.oktaAWSAppSettings != nil {
		return c.awsConfig.oktaAWSAppSettings, nil
	}

	if c.awsConfig.OktaAppId == "" {
		return nil, fmt.Errorf("okta-connector: no app id set")
	}

	app, awsAppResp, err := c.client.Application.GetApplication(ctx, c.awsConfig.OktaAppId, okta.NewApplication(), nil)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: verify failed to fetch aws app: %w", err)
	}
	awsAppRespCtx, err := responseToContext(&pagination.Token{}, awsAppResp)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: verify failed to convert get aws app response: %w", err)
	}
	if awsAppRespCtx.OktaResponse.StatusCode != http.StatusOK {
		err := fmt.Errorf("okta-connector: verify returned non-200 for aws app: '%d'", awsAppRespCtx.OktaResponse.StatusCode)
		return nil, err
	}
	oktaApp, err := oktaAppToOktaApplication(ctx, app)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to convert aws app: %w", err)
	}
	if oktaApp.Name != awsApp {
		return nil, fmt.Errorf("okta-connector: okta app is not aws: %w", err)
	}
	if oktaApp.Settings == nil {
		return nil, fmt.Errorf("okta-connector: settings are not present on okta app")
	}
	if oktaApp.Settings.App == nil {
		return nil, fmt.Errorf("okta-connector: app settings are not present on okta app")
	}
	appSettings := *oktaApp.Settings.App
	useGroupMapping, ok := appSettings["useGroupMapping"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'useGroupMapping' app setting is not present on okta app settings")
	}
	useGroupMappingBool, ok := useGroupMapping.(bool)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'useGroupMapping' app setting is not boolean")
	}
	groupFilter, ok := appSettings["groupFilter"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'groupFilter' app setting is not present on okta app settings")
	}
	groupFilterString, ok := groupFilter.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'groupFilter' app setting is not string")
	}
	joinAllRoles, ok := appSettings["joinAllRoles"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'joinAllRoles' app setting is not present on okta app settings")
	}
	joinAllRolesBool, ok := joinAllRoles.(bool)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'joinAllRoles' app setting is not boolean")
	}
	identityProviderArn, ok := appSettings["identityProviderArn"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'identityProviderArn' app setting is not present on okta app settings")
	}
	identityProviderArnString, ok := identityProviderArn.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'identityProviderArn' app setting is not string")
	}
	roleValuePattern, ok := appSettings["roleValuePattern"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'roleValuePattern' app setting is not present on okta app settings")
	}
	roleValuePatternString, ok := roleValuePattern.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'roleValuePattern' app setting is not string")
	}

	splitPattern := strings.Split(roleValuePatternString, ",")
	accountPattern := splitPattern[0]

	identityProviderRegex := strings.Replace(accountPattern, "${accountid}", `(\d{12})`, 1)
	groupFilterRegex := strings.Replace(groupFilterString, `(?{{accountid}}`, `(\d+`, 1)
	groupFilterRegex = strings.Replace(groupFilterRegex, `(?{{role}}`, `([a-zA-Z0-9+=,.@\\-_]+`, 1)

	// Unescape the groupFilterRegex regex string
	roleRegex := strings.ReplaceAll(groupFilterRegex, `\\`, `\`)

	// TODO(lauren) only do this if use group mapping not enabled?
	identityProvideArnAccountIDRegex, err := regexp.Compile(strings.ToLower(identityProviderRegex))
	if err != nil {
		return nil, fmt.Errorf("okta-connector: error compiling 'identityProviderRegex' regex")
	}
	identityProviderArnAccountID := identityProvideArnAccountIDRegex.FindStringSubmatch(strings.ToLower(identityProviderArnString))

	// First element is full string
	if len(identityProviderArnAccountID) != ExpectedIdentityProviderArnRegexCaptureGroups {
		return nil, fmt.Errorf("okta-aws-connector: error getting account id from identityProviderArn")
	}
	accountId := identityProviderArnAccountID[1]

	oktaAWSAppSettings := &oktaAWSAppSettings{
		JoinAllRoles:                 joinAllRolesBool,
		IdentityProviderArn:          identityProviderArnString,
		RoleRegex:                    roleRegex,
		IdentityProviderArnRegex:     identityProviderRegex,
		UseGroupMapping:              useGroupMappingBool,
		IdentityProviderArnAccountID: accountId,
	}
	c.awsConfig.oktaAWSAppSettings = oktaAWSAppSettings
	return oktaAWSAppSettings, nil
}

func (a *oktaAWSAppSettings) getAppGroupFromCache(ctx context.Context, groupId string) (*OktaAppGroupWrapper, error) {
	appGroupCacheVal, ok := a.appGroupCache.Load(groupId)
	if !ok {
		return nil, nil
	}
	oktaAppGroup, ok := appGroupCacheVal.(*OktaAppGroupWrapper)
	if !ok {
		return nil, fmt.Errorf("error converting app group '%s' from cache", groupId)
	}
	return oktaAppGroup, nil
}

func (a *oktaAWSAppSettings) checkIfNotAppGroupFromCache(ctx context.Context, groupId string) (bool, error) {
	notAppGroupCacheVal, ok := a.notAppGroupCache.Load(groupId)
	if !ok {
		return false, nil
	}
	notAppGroup, ok := notAppGroupCacheVal.(bool)
	if !ok {
		return false, fmt.Errorf("error converting not a app group bool for group '%s' ", groupId)
	}
	return notAppGroup, nil
}

func (a *oktaAWSAppSettings) oktaAppGroup(ctx context.Context, appGroup *okta.ApplicationGroupAssignment) (*OktaAppGroupWrapper, error) {
	oktaGroup, err := embeddedOktaGroupFromAppGroup(appGroup)
	if err != nil {
		return nil, err
	}

	appGroupProfile, ok := appGroup.Profile.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("error converting app group profile '%s'", appGroup.Id)
	}

	samlRoles := make([]string, 0)
	accountId := a.IdentityProviderArnAccountID
	var roleName string
	matchesRolePattern := false

	if a.UseGroupMapping {
		accountId, roleName, matchesRolePattern, err = parseAccountIDAndRoleFromGroupName(ctx, a.RoleRegex, oktaGroup.Profile.Name)
		if err != nil {
			return nil, err
		}
		if matchesRolePattern {
			samlRoles = append(samlRoles, roleName)
		}
	} else {
		samlRoles, err = getSAMLRoles(appGroupProfile)
		if err != nil {
			return nil, err
		}
	}

	return &OktaAppGroupWrapper{
		oktaGroup: oktaGroup,
		samlRoles: samlRoles,
		accountID: accountId,
	}, nil
}
