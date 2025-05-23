/*
Okta Admin Management

Allows customers to easily access the Okta Management APIs

Copyright 2018 - Present Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

API version: 2024.06.1
Contact: devex-public@okta.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.
package okta

import (
	"encoding/json"
	"fmt"
)


//model_oneof.mustache
// ListBehaviorDetectionRules200ResponseInner - struct for ListBehaviorDetectionRules200ResponseInner
type ListBehaviorDetectionRules200ResponseInner struct {
	BehaviorRuleAnomalousDevice *BehaviorRuleAnomalousDevice
	BehaviorRuleAnomalousIP *BehaviorRuleAnomalousIP
	BehaviorRuleAnomalousLocation *BehaviorRuleAnomalousLocation
	BehaviorRuleVelocity *BehaviorRuleVelocity
}

// BehaviorRuleAnomalousDeviceAsListBehaviorDetectionRules200ResponseInner is a convenience function that returns BehaviorRuleAnomalousDevice wrapped in ListBehaviorDetectionRules200ResponseInner
func BehaviorRuleAnomalousDeviceAsListBehaviorDetectionRules200ResponseInner(v *BehaviorRuleAnomalousDevice) ListBehaviorDetectionRules200ResponseInner {
	return ListBehaviorDetectionRules200ResponseInner{
		BehaviorRuleAnomalousDevice: v,
	}
}

// BehaviorRuleAnomalousIPAsListBehaviorDetectionRules200ResponseInner is a convenience function that returns BehaviorRuleAnomalousIP wrapped in ListBehaviorDetectionRules200ResponseInner
func BehaviorRuleAnomalousIPAsListBehaviorDetectionRules200ResponseInner(v *BehaviorRuleAnomalousIP) ListBehaviorDetectionRules200ResponseInner {
	return ListBehaviorDetectionRules200ResponseInner{
		BehaviorRuleAnomalousIP: v,
	}
}

// BehaviorRuleAnomalousLocationAsListBehaviorDetectionRules200ResponseInner is a convenience function that returns BehaviorRuleAnomalousLocation wrapped in ListBehaviorDetectionRules200ResponseInner
func BehaviorRuleAnomalousLocationAsListBehaviorDetectionRules200ResponseInner(v *BehaviorRuleAnomalousLocation) ListBehaviorDetectionRules200ResponseInner {
	return ListBehaviorDetectionRules200ResponseInner{
		BehaviorRuleAnomalousLocation: v,
	}
}

// BehaviorRuleVelocityAsListBehaviorDetectionRules200ResponseInner is a convenience function that returns BehaviorRuleVelocity wrapped in ListBehaviorDetectionRules200ResponseInner
func BehaviorRuleVelocityAsListBehaviorDetectionRules200ResponseInner(v *BehaviorRuleVelocity) ListBehaviorDetectionRules200ResponseInner {
	return ListBehaviorDetectionRules200ResponseInner{
		BehaviorRuleVelocity: v,
	}
}


// Unmarshal JSON data into one of the pointers in the struct  CUSTOM
func (dst *ListBehaviorDetectionRules200ResponseInner) UnmarshalJSON(data []byte) error {
	var err error
	// use discriminator value to speed up the lookup
	var jsonDict map[string]interface{}
	err = newStrictDecoder(data).Decode(&jsonDict)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal JSON into map for the discriminator lookup.")
	}

	// check if the discriminator value is 'ANOMALOUS_DEVICE'
	if jsonDict["type"] == "ANOMALOUS_DEVICE" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousDevice
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousDevice)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousDevice, return on the first match
		} else {
			dst.BehaviorRuleAnomalousDevice = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousDevice: %s", err.Error())
		}
	}

	// check if the discriminator value is 'ANOMALOUS_IP'
	if jsonDict["type"] == "ANOMALOUS_IP" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousIP
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousIP)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousIP, return on the first match
		} else {
			dst.BehaviorRuleAnomalousIP = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousIP: %s", err.Error())
		}
	}

	// check if the discriminator value is 'ANOMALOUS_LOCATION'
	if jsonDict["type"] == "ANOMALOUS_LOCATION" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousLocation
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousLocation)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousLocation, return on the first match
		} else {
			dst.BehaviorRuleAnomalousLocation = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousLocation: %s", err.Error())
		}
	}

	// check if the discriminator value is 'BehaviorRuleAnomalousDevice'
	if jsonDict["type"] == "BehaviorRuleAnomalousDevice" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousDevice
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousDevice)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousDevice, return on the first match
		} else {
			dst.BehaviorRuleAnomalousDevice = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousDevice: %s", err.Error())
		}
	}

	// check if the discriminator value is 'BehaviorRuleAnomalousIP'
	if jsonDict["type"] == "BehaviorRuleAnomalousIP" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousIP
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousIP)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousIP, return on the first match
		} else {
			dst.BehaviorRuleAnomalousIP = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousIP: %s", err.Error())
		}
	}

	// check if the discriminator value is 'BehaviorRuleAnomalousLocation'
	if jsonDict["type"] == "BehaviorRuleAnomalousLocation" {
		// try to unmarshal JSON data into BehaviorRuleAnomalousLocation
		err = json.Unmarshal(data, &dst.BehaviorRuleAnomalousLocation)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleAnomalousLocation, return on the first match
		} else {
			dst.BehaviorRuleAnomalousLocation = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleAnomalousLocation: %s", err.Error())
		}
	}

	// check if the discriminator value is 'BehaviorRuleVelocity'
	if jsonDict["type"] == "BehaviorRuleVelocity" {
		// try to unmarshal JSON data into BehaviorRuleVelocity
		err = json.Unmarshal(data, &dst.BehaviorRuleVelocity)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleVelocity, return on the first match
		} else {
			dst.BehaviorRuleVelocity = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleVelocity: %s", err.Error())
		}
	}

	// check if the discriminator value is 'VELOCITY'
	if jsonDict["type"] == "VELOCITY" {
		// try to unmarshal JSON data into BehaviorRuleVelocity
		err = json.Unmarshal(data, &dst.BehaviorRuleVelocity)
		if err == nil {
			return nil // data stored in dst.BehaviorRuleVelocity, return on the first match
		} else {
			dst.BehaviorRuleVelocity = nil
			return fmt.Errorf("Failed to unmarshal ListBehaviorDetectionRules200ResponseInner as BehaviorRuleVelocity: %s", err.Error())
		}
	}

	return nil
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src ListBehaviorDetectionRules200ResponseInner) MarshalJSON() ([]byte, error) {
	if src.BehaviorRuleAnomalousDevice != nil {
		return json.Marshal(&src.BehaviorRuleAnomalousDevice)
	}

	if src.BehaviorRuleAnomalousIP != nil {
		return json.Marshal(&src.BehaviorRuleAnomalousIP)
	}

	if src.BehaviorRuleAnomalousLocation != nil {
		return json.Marshal(&src.BehaviorRuleAnomalousLocation)
	}

	if src.BehaviorRuleVelocity != nil {
		return json.Marshal(&src.BehaviorRuleVelocity)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *ListBehaviorDetectionRules200ResponseInner) GetActualInstance() (interface{}) {
	if obj == nil {
		return nil
	}
	if obj.BehaviorRuleAnomalousDevice != nil {
		return obj.BehaviorRuleAnomalousDevice
	}

	if obj.BehaviorRuleAnomalousIP != nil {
		return obj.BehaviorRuleAnomalousIP
	}

	if obj.BehaviorRuleAnomalousLocation != nil {
		return obj.BehaviorRuleAnomalousLocation
	}

	if obj.BehaviorRuleVelocity != nil {
		return obj.BehaviorRuleVelocity
	}

	// all schemas are nil
	return nil
}

type NullableListBehaviorDetectionRules200ResponseInner struct {
	value *ListBehaviorDetectionRules200ResponseInner
	isSet bool
}

func (v NullableListBehaviorDetectionRules200ResponseInner) Get() *ListBehaviorDetectionRules200ResponseInner {
	return v.value
}

func (v *NullableListBehaviorDetectionRules200ResponseInner) Set(val *ListBehaviorDetectionRules200ResponseInner) {
	v.value = val
	v.isSet = true
}

func (v NullableListBehaviorDetectionRules200ResponseInner) IsSet() bool {
	return v.isSet
}

func (v *NullableListBehaviorDetectionRules200ResponseInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableListBehaviorDetectionRules200ResponseInner(val *ListBehaviorDetectionRules200ResponseInner) *NullableListBehaviorDetectionRules200ResponseInner {
	return &NullableListBehaviorDetectionRules200ResponseInner{value: val, isSet: true}
}

func (v NullableListBehaviorDetectionRules200ResponseInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableListBehaviorDetectionRules200ResponseInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


