package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
)

// deviceListLimit is Okta's enforced maximum for the devices list endpoint's `limit` param.
const deviceListLimit = 200

type deviceResourceType struct {
	resourceType *v2.ResourceType
	clientV5     *oktav5.APIClient
}

func deviceBuilder(clientV5 *oktav5.APIClient) *deviceResourceType {
	return &deviceResourceType{
		resourceType: resourceTypeDevice,
		clientV5:     clientV5,
	}
}

func (o *deviceResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *deviceResourceType) Entitlements(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *deviceResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *deviceResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	token := &attrs.PageToken
	bag, prevSerializedResp, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeDevice.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connector-v5: failed to parse page token: %w", err)
	}

	var devices []oktav5.DeviceList
	var resp *oktav5.APIResponse

	if prevSerializedResp == "" {
		limit := token.Size
		if limit <= 0 || limit > deviceListLimit {
			limit = deviceListLimit
		}
		devices, resp, err = o.clientV5.DeviceAPI.ListDevices(ctx).Limit(int32(limit)).Execute()
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connector-v5: failed to list devices: %w", err)
		}
	} else {
		prevResp, err := deserializeOktaResponseV5(prevSerializedResp)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connector-v5: failed to deserialize page token: %w", err)
		}

		localOktaAPIResponse := oktav5.NewAPIResponse(prevResp.Response, o.clientV5, nil)
		if localOktaAPIResponse.HasNextPage() {
			resp, err = localOktaAPIResponse.Next(&devices)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	nextPage, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connector-v5: failed to parse response: %w", err)
	}

	ret := make([]*v2.Resource, 0, len(devices))
	for _, device := range devices {
		rv, err := deviceResource(&device)
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, rv)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, err
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return ret, &resource.SyncOpResults{NextPageToken: nextPageToken, Annotations: annos}, nil
}

// devicePlatformOSType maps Okta's device profile platform value to a DeviceOS_OsType.
// Unmapped values (unknown platform) leave the type unset rather than guessing.
func devicePlatformOSType(platform string) v2.DeviceOS_OsType {
	switch platform {
	case "WINDOWS":
		return v2.DeviceOS_OS_TYPE_WINDOWS
	case "MACOS":
		return v2.DeviceOS_OS_TYPE_MACOS
	case "IOS":
		return v2.DeviceOS_OS_TYPE_IOS
	case "ANDROID":
		return v2.DeviceOS_OS_TYPE_ANDROID
	case "CHROMEOS":
		return v2.DeviceOS_OS_TYPE_CHROMEOS
	default:
		return v2.DeviceOS_OS_TYPE_UNSPECIFIED
	}
}

func deviceResource(device *oktav5.DeviceList) (*v2.Resource, error) {
	deviceID := device.GetId()

	name := deviceID
	var options []resource.ManagedDeviceTraitOption
	if device.Profile != nil {
		profile := device.Profile
		if profile.GetDisplayName() != "" {
			name = profile.GetDisplayName()
		}
		options = []resource.ManagedDeviceTraitOption{
			resource.WithManagedDeviceSerial(profile.GetSerialNumber()),
			resource.WithManagedDeviceUDID(profile.GetUdid()),
			resource.WithManagedDeviceModel(profile.GetModel()),
			resource.WithManagedDeviceVendor(profile.GetManufacturer()),
			resource.WithManagedDeviceOS(&v2.DeviceOS{
				Type:    devicePlatformOSType(profile.GetPlatform()),
				Name:    profile.GetPlatform(),
				Version: profile.GetOsVersion(),
			}),
		}
	}

	rv, err := resource.NewManagedDeviceResource(
		name,
		resourceTypeDevice,
		deviceID,
		options,
	)
	if err != nil {
		return nil, err
	}

	return rv, nil
}
