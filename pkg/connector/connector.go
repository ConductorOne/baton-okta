package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
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

type Okta struct {
	client           *okta.Client
	domain           string
	apiToken         string
	syncInactiveApps bool
	ciamConfig       *ciamConfig
	awsConfig        *awsConfig
}

type ciamConfig struct {
	Enabled      bool
	EmailDomains []string
}

// "groupFilter": "aws_(?{{accountid}}\\d+)_(?{{role}}[a-zA-Z0-9+=,.@\\-_]+)",
// arn:aws:iam::${accountid}:saml-provider/OKTA,arn:aws:iam::${accountid}:role/${role}"
type awsConfig struct {
	Enabled                  bool
	OktaAppId                string
	JoinAllRoles             bool
	IdentityProviderArn      string
	RoleRegex                string
	IdentityProviderArnRegex string
	UseGroupMapping          bool
	appUserToGroup           sync.Map // user id (key) to group mapset
	groupToSamlRoleCache     sync.Map // group id to samlRoles mapset
	accountRoleCache         sync.Map // key is account id, val is samlRole mapset
	accountGrantCache        sync.Map // account -> slice of group grants
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
			groupBuilder(o.domain, o.apiToken, o.client, o.awsConfig),
			accountBuilder(o.domain, o.apiToken, o.client, o.awsConfig),
		}
	}
	return []connectorbuilder.ResourceSyncer{
		roleBuilder(o.domain, o.apiToken, o.client),
		userBuilder(o.domain, o.apiToken, o.client),
		groupBuilder(o.domain, o.apiToken, o.client, nil),
		appBuilder(o.domain, o.apiToken, o.syncInactiveApps, o.client),
	}
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

	if c.awsConfig.Enabled {
		if c.awsConfig.OktaAppId == "" {
			return nil, fmt.Errorf("okta-connector: no app id set")
		}
		app, awsAppResp, err := c.client.Application.GetApplication(ctx, c.awsConfig.OktaAppId, okta.NewApplication(), nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: verify failed to fetch aws app: %w", err)
		}
		awsAppRespCtx, err := responseToContext(&pagination.Token{}, awsAppResp)
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
	if cfg.AWSMode {
		if cfg.AWSOktaAppId == "" {
			return nil, fmt.Errorf("okta-connector: no app id set")
		}
		app, awsAppResp, err := oktaClient.Application.GetApplication(ctx, awsConfig.OktaAppId, okta.NewApplication(), nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: verify failed to fetch aws app: %w", err)
		}
		// TODO(lauren) do we need to parseResp?
		awsAppRespCtx, err := responseToContext(&pagination.Token{}, awsAppResp)
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
		roleRegex := strings.Replace(groupFilterRegex, `\\`, `\`, -1)

		awsConfig.UseGroupMapping = useGroupMappingBool
		awsConfig.JoinAllRoles = joinAllRolesBool
		awsConfig.IdentityProviderArn = identityProviderArnString
		awsConfig.IdentityProviderArnRegex = identityProviderRegex
		awsConfig.RoleRegex = roleRegex
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
		awsConfig: awsConfig,
	}, nil
}
