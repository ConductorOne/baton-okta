package connector_test

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCustomRoleGroupProvisioningAvailability(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f, idnWithCustomRoles())
	ent := idnEnt(idnRes("custom-role", "cr0custom"), "assigned")
	principal := idnRes("group", idnGroupEng)
	_, err := srv.Grant(context.Background(), &v2.GrantManagerServiceGrantRequest{Entitlement: ent, Principal: principal})
	require.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = srv.Revoke(context.Background(), &v2.GrantManagerServiceRevokeRequest{
		Grant: &v2.Grant{Entitlement: ent, Principal: principal},
	})
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.Empty(t, f.Requests())
}
