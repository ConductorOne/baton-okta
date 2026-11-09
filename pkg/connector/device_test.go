package connector

import (
	"testing"

	"github.com/conductorone/baton-okta/pkg/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func TestDeviceResource_WithProfile(t *testing.T) {
	device := &okta.Device{
		Id: devStrPtr("guo1a2b3c4d5e6f7g8h9"),
		Profile: &okta.DeviceProfile{
			DisplayName:  "Ada's MacBook Pro",
			SerialNumber: devStrPtr("C02ABC123DEF"),
			Udid:         devStrPtr("00001234-0011AABB2233CCDD"),
			Model:        devStrPtr("MacBookPro18,3"),
			Manufacturer: devStrPtr("Apple Inc."),
			Platform:     "MACOS",
			OsVersion:    devStrPtr("14.5.0"),
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
	if trait.GetOs().GetType() != v2.DeviceOS_OS_TYPE_MACOS {
		t.Errorf("Os.Type = %v, want %v", trait.GetOs().GetType(), v2.DeviceOS_OS_TYPE_MACOS)
	}
}

func TestDevicePlatformOSType(t *testing.T) {
	tests := []struct {
		platform string
		want     v2.DeviceOS_OsType
	}{
		{"WINDOWS", v2.DeviceOS_OS_TYPE_WINDOWS},
		{"MACOS", v2.DeviceOS_OS_TYPE_MACOS},
		{"IOS", v2.DeviceOS_OS_TYPE_IOS},
		{"ANDROID", v2.DeviceOS_OS_TYPE_ANDROID},
		{"CHROMEOS", v2.DeviceOS_OS_TYPE_CHROMEOS},
		{"SOMETHING_NEW", v2.DeviceOS_OS_TYPE_UNSPECIFIED},
		{"", v2.DeviceOS_OS_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		if got := devicePlatformOSType(tt.platform); got != tt.want {
			t.Errorf("devicePlatformOSType(%q) = %v, want %v", tt.platform, got, tt.want)
		}
	}
}

func TestDeviceResource_NoProfile(t *testing.T) {
	device := &okta.Device{
		Id: devStrPtr("guo1a2b3c4d5e6f7g8h9"),
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

func devStrPtr(s string) *string { return &s }
