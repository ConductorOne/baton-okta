package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func TestAppEntitlements_AccessHasV1Identifier(t *testing.T) {
	const appID = "0oa1abc2def3GHI4jk5"

	o := &appResourceType{resourceType: resourceTypeApp}
	resource := &v2.Resource{
		Id:          &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: appID},
		DisplayName: "Test App",
	}

	ents, _, err := o.Entitlements(context.Background(), resource, sdkResource.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Entitlements returned error: %v", err)
	}

	var accessEnt *v2.Entitlement
	for _, e := range ents {
		if e.Slug == "access" {
			accessEnt = e
			break
		}
	}
	if accessEnt == nil {
		t.Fatalf("no entitlement with slug %q returned; got %d entitlements", "access", len(ents))
	}

	annos := annotations.Annotations(accessEnt.GetAnnotations())
	v1id := &v2.V1Identifier{}
	found, err := annos.Pick(v1id)
	if err != nil {
		t.Fatalf("Pick(V1Identifier) returned error: %v", err)
	}
	if !found {
		t.Fatalf("app-access entitlement is missing V1Identifier annotation")
	}

	want := V1MembershipEntitlementID(appID)
	if v1id.GetId() != want {
		t.Errorf("V1Identifier id = %q, want %q", v1id.GetId(), want)
	}
}
