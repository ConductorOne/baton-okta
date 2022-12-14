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

type IonForm struct {
	Accepts   string      `json:"accepts,omitempty"`
	Href      string      `json:"href,omitempty"`
	Method    string      `json:"method,omitempty"`
	Name      string      `json:"name,omitempty"`
	Produces  string      `json:"produces,omitempty"`
	Refresh   *int64      `json:"refresh,omitempty"`
	Rel       []string    `json:"rel,omitempty"`
	RelatesTo []string    `json:"relatesTo,omitempty"`
	Value     []*IonField `json:"value,omitempty"`
}
