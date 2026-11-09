package connector_test

import (
	"testing"
)

func TestBlackboxUserList(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/users", "users_page1.json", "users_page2.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	listAllResources(t, g, srv, "user", nil, 2)
	g.Check()
}
