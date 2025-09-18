package connector

import "time"

type ResourceSetsAPIData struct {
	ResourceSets []ResourceSets `json:"resource-sets,omitempty"`
	Links        Link           `json:"_links,omitempty"`
}

type ResourceSets struct {
	ID          string      `json:"id,omitempty"`
	Label       string      `json:"label,omitempty"`
	Description string      `json:"description,omitempty"`
	Created     time.Time   `json:"created,omitempty"`
	LastUpdated time.Time   `json:"lastUpdated,omitempty"`
	Links       interface{} `json:"_links,omitempty"`
}

type Next struct {
	Href string `json:"href,omitempty"`
}

type Link struct {
	Next Next `json:"next,omitempty"`
}

// Id is the role assignment id
// Role is the role id.
type Roles struct {
	Links          interface{} `json:"_links,omitempty"`
	AssignmentType string      `json:"assignmentType,omitempty"`
	Created        *time.Time  `json:"created,omitempty"`
	Description    string      `json:"description,omitempty"`
	Id             string      `json:"id,omitempty"`
	Label          string      `json:"label,omitempty"`
	LastUpdated    *time.Time  `json:"lastUpdated,omitempty"`
	Status         string      `json:"status,omitempty"`
	Type           string      `json:"type,omitempty"`
	ResourceSet    string      `json:"resource-set,omitempty"`
	Role           string      `json:"role,omitempty"`
}

type ResourceSetsBindingsAPIData struct {
	Roles []Role `json:"roles,omitempty"`
	Links _Links `json:"_links"`
}

type Members struct {
	Href string `json:"href,omitempty"`
}

type Self struct {
	Href string `json:"href,omitempty"`
}

type Links struct {
	Members Members `json:"members,omitempty"`
	Self    Self    `json:"self,omitempty"`
}

type Role struct {
	ID    string `json:"id,omitempty"`
	Links Links  `json:"_links,omitempty"`
}

type ResourceSet struct {
	Href string `json:"href,omitempty"`
}

type _Links struct {
	ResourceSet ResourceSet `json:"resource-set,omitempty"`
	Self        Self        `json:"self,omitempty"`
}

type MembersDetails struct {
	ID          string    `json:"id,omitempty"`
	Created     time.Time `json:"created,omitempty"`
	LastUpdated time.Time `json:"lastUpdated,omitempty"`
	Links       LinksSelf `json:"_links,omitempty"`
}

type LinksSelfBinding struct {
	Self    Self    `json:"self,omitempty"`
	Binding Binding `json:"binding,omitempty"`
}

type LinksSelf struct {
	Self Self `json:"self,omitempty"`
}

type Binding struct {
	Href string `json:"href,omitempty"`
}
