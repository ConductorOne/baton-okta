package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
)

func TestDeviceResource_WithProfile(t *testing.T) {
	device := &oktav5.DeviceList{
		Id: oktav5.PtrString("guo1a2b3c4d5e6f7g8h9"),
		Profile: &oktav5.DeviceProfile{
			DisplayName:  "Ada's MacBook Pro",
			SerialNumber: oktav5.PtrString("C02ABC123DEF"),
			Udid:         oktav5.PtrString("00001234-0011AABB2233CCDD"),
			Model:        oktav5.PtrString("MacBookPro18,3"),
			Manufacturer: oktav5.PtrString("Apple Inc."),
			Platform:     "MACOS",
			OsVersion:    oktav5.PtrString("14.5.0"),
			Registered:   true,
		},
	}

	rv, err := deviceResource(device)
	if err != nil {
		t.Fatalf("deviceResource returned error: %v", err)
	}

	if rv.GetDisplayName() != "Ada's MacBook Pro" {
		t.Errorf("DisplayName = %q, want %q", rv.GetDisplayName(), "Ada's MacBook Pro")
	}
	if rv.Id.GetResource() != "guo1a2b3c4d5e6f7g8h9" {
		t.Errorf("resource id = %q, want %q", rv.Id.GetResource(), "guo1a2b3c4d5e6f7g8h9")
	}

	trait := &v2.ManagedDeviceTrait{}
	annos := annotations.Annotations(rv.GetAnnotations())
	found, err := annos.Pick(trait)
	if err != nil {
		t.Fatalf("Pick(ManagedDeviceTrait) returned error: %v", err)
	}
	if !found {
		t.Fatalf("device resource is missing ManagedDeviceTrait annotation")
	}
	if trait.GetSerial() != "C02ABC123DEF" {
		t.Errorf("Serial = %q, want %q", trait.GetSerial(), "C02ABC123DEF")
	}
	if trait.GetUdid() != "00001234-0011AABB2233CCDD" {
		t.Errorf("Udid = %q, want %q", trait.GetUdid(), "00001234-0011AABB2233CCDD")
	}
	if trait.GetModel() != "MacBookPro18,3" {
		t.Errorf("Model = %q, want %q", trait.GetModel(), "MacBookPro18,3")
	}
	if trait.GetVendor() != "Apple Inc." {
		t.Errorf("Vendor = %q, want %q", trait.GetVendor(), "Apple Inc.")
	}
	if trait.GetOs().GetName() != "MACOS" {
		t.Errorf("Os.Name = %q, want %q", trait.GetOs().GetName(), "MACOS")
	}
	if trait.GetOs().GetVersion() != "14.5.0" {
		t.Errorf("Os.Version = %q, want %q", trait.GetOs().GetVersion(), "14.5.0")
	}
}

func TestDeviceResource_NoProfile(t *testing.T) {
	device := &oktav5.DeviceList{
		Id: oktav5.PtrString("guo1a2b3c4d5e6f7g8h9"),
	}

	rv, err := deviceResource(device)
	if err != nil {
		t.Fatalf("deviceResource returned error: %v", err)
	}

	if rv.GetDisplayName() != "guo1a2b3c4d5e6f7g8h9" {
		t.Errorf("DisplayName = %q, want device id fallback %q", rv.GetDisplayName(), "guo1a2b3c4d5e6f7g8h9")
	}

	trait := &v2.ManagedDeviceTrait{}
	annos := annotations.Annotations(rv.GetAnnotations())
	found, err := annos.Pick(trait)
	if err != nil {
		t.Fatalf("Pick(ManagedDeviceTrait) returned error: %v", err)
	}
	if !found {
		t.Fatalf("device resource is missing ManagedDeviceTrait annotation")
	}
	if trait.GetSerial() != "" {
		t.Errorf("Serial = %q, want empty when profile is absent", trait.GetSerial())
	}
}
