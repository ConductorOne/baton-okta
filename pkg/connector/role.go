package connector

import "github.com/okta/okta-sdk-golang/v2/okta"

func roleIn(roles []*okta.Role, role *okta.Role) bool {
	for _, r := range roles {
		if role.Type == r.Type {
			return true
		}
	}
	return false
}
