package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
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

func TestAppResource_NHIType(t *testing.T) {
	const appID = "0oa1abc2def3GHI4jk5"

	cases := []struct {
		name       string
		signOnMode string
		wantNHI    bool
		wantDetail string
	}{
		{"oidc", "OPENID_CONNECT", true, "okta.app.openid_connect"},
		{"saml", "SAML_2_0", true, "okta.app.saml_2_0"},
		{"wsfed", "WS_FEDERATION", true, "okta.app.ws_federation"},
		{"empty", "", true, "okta.app"},
		{"bookmark", "BOOKMARK", false, ""},
		{"swa_browser_plugin", "BROWSER_PLUGIN", false, ""},
		{"swa_auto_login", "AUTO_LOGIN", false, ""},
		{"swa_basic_auth", "BASIC_AUTH", false, ""},
		{"swa_secure_password_store", "SECURE_PASSWORD_STORE", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &okta.Application{Id: appID, Label: "Test App", Status: "ACTIVE", SignOnMode: tc.signOnMode}
			resource, err := appResource(context.Background(), app)
			if err != nil {
				t.Fatalf("appResource returned error: %v", err)
			}

			annos := annotations.Annotations(resource.GetAnnotations())
			nhi := &v2.NonHumanIdentityTrait{}
			found, err := annos.Pick(nhi)
			if err != nil {
				t.Fatalf("Pick(NonHumanIdentityTrait) returned error: %v", err)
			}
			if found != tc.wantNHI {
				t.Fatalf("NHI annotation present = %v, want %v (signOnMode %q)", found, tc.wantNHI, tc.signOnMode)
			}
			if !tc.wantNHI {
				return
			}
			if nhi.GetNhiType() != v2.NonHumanIdentityTrait_NHI_TYPE_APP_REGISTRATION {
				t.Errorf("nhi_type = %v, want NHI_TYPE_APP_REGISTRATION", nhi.GetNhiType())
			}
			if nhi.GetNhiDetail() != tc.wantDetail {
				t.Errorf("nhi_detail = %q, want %q", nhi.GetNhiDetail(), tc.wantDetail)
			}
		})
	}
}
