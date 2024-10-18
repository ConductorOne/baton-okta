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
