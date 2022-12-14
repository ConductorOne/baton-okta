/*
* Copyright 2018 - Present Okta, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 */

// Code generated by okta openapi generator. DO NOT EDIT.

package okta

import (
	"context"
	"fmt"
)

type UserSchemaResource resource

type UserSchema struct {
	Schema      string                 `json:"$schema,omitempty"`
	Links       interface{}            `json:"_links,omitempty"`
	Created     string                 `json:"created,omitempty"`
	Definitions *UserSchemaDefinitions `json:"definitions,omitempty"`
	Id          string                 `json:"id,omitempty"`
	LastUpdated string                 `json:"lastUpdated,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Properties  *UserSchemaProperties  `json:"properties,omitempty"`
	Title       string                 `json:"title,omitempty"`
	Type        string                 `json:"type,omitempty"`
}

// Fetches the Schema for an App User
func (m *UserSchemaResource) GetApplicationUserSchema(ctx context.Context, appInstanceId string) (*UserSchema, *Response, error) {
	url := fmt.Sprintf("/api/v1/meta/schemas/apps/%v/default", appInstanceId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var userSchema *UserSchema

	resp, err := rq.Do(ctx, req, &userSchema)
	if err != nil {
		return nil, resp, err
	}

	return userSchema, resp, nil
}

// Partial updates on the User Profile properties of the Application User Schema.
func (m *UserSchemaResource) UpdateApplicationUserProfile(ctx context.Context, appInstanceId string, body UserSchema) (*UserSchema, *Response, error) {
	url := fmt.Sprintf("/api/v1/meta/schemas/apps/%v/default", appInstanceId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var userSchema *UserSchema

	resp, err := rq.Do(ctx, req, &userSchema)
	if err != nil {
		return nil, resp, err
	}

	return userSchema, resp, nil
}

// Fetches the schema for a Schema Id.
func (m *UserSchemaResource) GetUserSchema(ctx context.Context, schemaId string) (*UserSchema, *Response, error) {
	url := fmt.Sprintf("/api/v1/meta/schemas/user/%v", schemaId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var userSchema *UserSchema

	resp, err := rq.Do(ctx, req, &userSchema)
	if err != nil {
		return nil, resp, err
	}

	return userSchema, resp, nil
}

// Partial updates on the User Profile properties of the user schema.
func (m *UserSchemaResource) UpdateUserProfile(ctx context.Context, schemaId string, body UserSchema) (*UserSchema, *Response, error) {
	url := fmt.Sprintf("/api/v1/meta/schemas/user/%v", schemaId)

	rq := m.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var userSchema *UserSchema

	resp, err := rq.Do(ctx, req, &userSchema)
	if err != nil {
		return nil, resp, err
	}

	return userSchema, resp, nil
}
