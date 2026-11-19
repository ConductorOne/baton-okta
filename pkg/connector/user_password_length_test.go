package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRandomPasswordRequestedLength(t *testing.T) {
	for _, tc := range []struct {
		requested int64
		expected  int
	}{{5, 8}, {8, 8}, {16, 16}, {64, 64}} {
		options := v2.LocalCredentialOptions_builder{
			RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: tc.requested},
		}.Build()
		credentials, err := getCredentialOption(options)
		require.NoError(t, err)
		require.Len(t, credentials.Password.Value, tc.expected)
	}
	options := v2.LocalCredentialOptions_builder{
		RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: 65},
	}.Build()
	_, err := getCredentialOption(options)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
