package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

type Okta struct {
	client           *okta.Client
	domain           string
	apiToken         string
	syncInactiveApps bool
	config           *ConfigOAuth2
}

type ConfigOAuth2 struct {
	OktaClientId            string
	OktaPrivateKey          string
	OktaPrivateKeyId        string
	OktaProvisioningEnabled bool
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
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		roleBuilder(o.domain, o.apiToken, o.client),
		userBuilder(o.domain, o.apiToken, o.client),
		groupBuilder(o.domain, o.apiToken, o.client),
		appBuilder(o.domain, o.apiToken, o.syncInactiveApps, o.client),
	}
}

func (c *Okta) ListResourceTypes(ctx context.Context, request *v2.ResourceTypesServiceListResourceTypesRequest) (*v2.ResourceTypesServiceListResourceTypesResponse, error) {
	return &v2.ResourceTypesServiceListResourceTypesResponse{
		List: []*v2.ResourceType{
			resourceTypeRole,
			resourceTypeUser,
			resourceTypeGroup,
			resourceTypeApp,
		},
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
	if c.apiToken != "" {
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
	}

	return nil, nil
}

func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, fmt.Errorf("not implemented")
}

func NewOktaClient(domain, apiToken string, syncInactiveApps bool, cfg *ConfigOAuth2) *Okta {
	return &Okta{
		client:           &okta.Client{},
		domain:           domain,
		apiToken:         apiToken,
		syncInactiveApps: syncInactiveApps,
		config: &ConfigOAuth2{
			OktaClientId:            cfg.OktaClientId,
			OktaPrivateKey:          cfg.OktaPrivateKey,
			OktaPrivateKeyId:        cfg.OktaPrivateKeyId,
			OktaProvisioningEnabled: cfg.OktaProvisioningEnabled,
		},
	}
}

func New(ctx context.Context, o *Okta) (*Okta, error) {
	var (
		oktaClient *okta.Client
		scopes     = defaultScopes
	)
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	if o.apiToken != "" && o.domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", o.domain)),
			okta.WithToken(o.apiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(false),
		)
		if err != nil {
			return nil, err
		}
	}

	if o.config.OktaClientId != "" && o.config.OktaPrivateKey != "" && o.domain != "" {
		if o.config.OktaProvisioningEnabled {
			scopes = append(scopes, provisioningScopes...)
		}
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", o.domain)),
			okta.WithAuthorizationMode("PrivateKey"),
			okta.WithClientId(o.config.OktaClientId),
			okta.WithScopes(scopes),
			okta.WithPrivateKey(o.config.OktaPrivateKey),
			okta.WithPrivateKeyId(o.config.OktaPrivateKeyId),
			okta.WithCache(false),
		)
		if err != nil {
			return nil, err
		}
	}

	return &Okta{
		client:           oktaClient,
		domain:           o.domain,
		apiToken:         o.apiToken,
		syncInactiveApps: o.syncInactiveApps,
	}, nil
}
