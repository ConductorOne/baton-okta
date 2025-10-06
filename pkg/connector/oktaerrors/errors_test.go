package oktaerrors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindError(t *testing.T) {
	err := FindError("E0000001")
	require.Equal(t, err.ErrorCode, "E0000001")
}
