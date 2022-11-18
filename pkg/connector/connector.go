package connector

import (
	"context"
	"fmt"

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
}

// const (
// 	verifyURL = "/api/v1/org"
// )

func v1AnnotationsForResourceType(resourceTypeID string) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Append(&v2.V1Identifier{
		Id: resourceTypeID,
	})

	return annos
}

var (
	resourceTypeOrg = &v2.ResourceType{
		Id:          "org",
		DisplayName: "Org",
		Annotations: v1AnnotationsForResourceType("org"),
	}
	// resourceTypeGroup = &v2.ResourceType{
	// 	Id:          "group",
	// 	DisplayName: "Group",
	// 	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
	// 	Annotations: v1AnnotationsForResourceType("group"),
	// }
	// resourceTypeRole = &v2.ResourceType{
	// 	Id:          "role",
	// 	DisplayName: "Role",
	// 	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
	// 	Annotations: v1AnnotationsForResourceType("role"),
	// }
	// resourceTypeApp = &v2.ResourceType{
	// 	Id:          "app",
	// 	DisplayName: "App",
	// 	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
	// 	Annotations: v1AnnotationsForResourceType("app"),
	// }.
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: v1AnnotationsForResourceType("user"),
	}
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		orgBuilder(o.domain, o.apiToken, o.client),
		// groupBuilder(o.domain, o.apiToken, o.client),
		// roleBuilder(o.domain, o.apiToken, o.client),
		// appBuilder(o.domain, o.apiToken, o.client),
		userBuilder(o.domain, o.apiToken, o.client),
	}
}

func (c *Okta) ListResourceTypes(ctx context.Context, request *v2.ResourceTypesServiceListResourceTypesRequest) (*v2.ResourceTypesServiceListResourceTypesResponse, error) {
	return &v2.ResourceTypesServiceListResourceTypesResponse{
		List: []*v2.ResourceType{
			resourceTypeOrg,
			// resourceTypeGroup,
			// resourceTypeRole,
			// resourceTypeApp,
			resourceTypeUser,
		},
	}, nil
}

// func (c *Okta) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
// 	err := c.Verify(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var annos annotations.Annotations
// 	annos.Append(&v2.ExternalLink{
// 		Url: c.domain,
// 	})

// 	return &v2.ConnectorMetadata{
// 		DisplayName: "Okta",
// 		Annotations: annos,
// 	}, nil
// }

// func (c *Okta) Validate(ctx context.Context) (annotations.Annotations, error) {
// 	err := c.Verify(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("okta-connector: failed to validate: %w", err)
// 	}

// 	return nil, nil
// }

// func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
// 	return "", nil, fmt.Errorf("not implemented")
// }

// func (c *Okta) Verify(ctx context.Context) error {
// 	// TODO @degzhaus: finish this
// 	l := ctxzap.Extract(ctx)

// 	settings, resp, err := c.GetOrgSettings(ctx)
// 	if err != nil {
// 		err := fmt.Errorf("verify: request to '%s' failed: %w", verifyURL, err)
// 		l.Error("Okta GetOrgSettings Request Failed in verify", zap.Error(err))
// 		return err

// 	}

// 	if resp.StatusCode != http.StatusOK {
// 		err := fmt.Errorf("verify: request to '%s' returned non-200: '%d'", verifyURL, resp.StatusCode)
// 		l.Error("Invalid Status Code from Verity", zap.Error(err))
// 		return err
// 	}
// 	return nil
// }

func New(ctx context.Context, domain, apiToken string, syncInactiveApps bool) (*Okta, error) {
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	_, oktaClient, err := okta.NewClient(ctx,
		okta.WithOrgUrl(fmt.Sprintf("https://%s", domain)),
		okta.WithToken(apiToken),
		okta.WithHttpClientPtr(client),
		okta.WithCache(false),
	)
	if err != nil {
		return nil, err
	}

	return &Okta{
		client:           oktaClient,
		domain:           domain,
		apiToken:         apiToken,
		syncInactiveApps: syncInactiveApps,
	}, nil
}
