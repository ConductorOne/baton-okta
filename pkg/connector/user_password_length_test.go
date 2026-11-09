package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
)

func TestRandomPasswordRequestedLength(t *testing.T) {
	options := v2.LocalCredentialOptions_builder{
		RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: 16},
	}.Build()
	credentials, err := getCredentialOption(options)
	require.NoError(t, err)
	require.Len(t, credentials.Password.Value, 8)
}
