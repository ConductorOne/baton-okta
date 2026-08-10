package connector

import (
	"context"
	"testing"
)

func TestAccountCreationSchemaBooleanishFields(t *testing.T) {
	t.Parallel()

	// Empty apiToken skips Validate's live org check, so Metadata is unit-testable.
	md, err := (&Okta{domain: "example.okta.com"}).Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.AccountCreationSchema == nil {
		t.Fatal("AccountCreationSchema is nil")
	}

	booleanish := []struct {
		key             string
		wantDefault     *string
		wantPlaceholder string
	}{
		{key: profileFieldPasswordChangeOnLoginRequired, wantPlaceholder: placeholderBoolean},
		{key: profileFieldCreateInactive, wantPlaceholder: placeholderBoolean},
		{key: profileFieldSendActivationEmail, wantDefault: ToPtr("true"), wantPlaceholder: placeholderBoolean},
	}

	for _, tt := range booleanish {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()

			field, ok := md.AccountCreationSchema.FieldMap[tt.key]
			if !ok {
				t.Fatalf("missing field %q", tt.key)
			}
			sf := field.GetStringField()
			if sf == nil {
				t.Fatalf("%s: want StringField, got %T", tt.key, field.GetField())
			}
			if field.GetPlaceholder() != tt.wantPlaceholder {
				t.Errorf("%s Placeholder = %q, want %q", tt.key, field.GetPlaceholder(), tt.wantPlaceholder)
			}
			gotDefault := sf.DefaultValue
			switch {
			case tt.wantDefault == nil && gotDefault != nil:
				t.Errorf("%s DefaultValue = %q, want unset", tt.key, *gotDefault)
			case tt.wantDefault != nil && gotDefault == nil:
				t.Errorf("%s DefaultValue unset, want %q", tt.key, *tt.wantDefault)
			case tt.wantDefault != nil && gotDefault != nil && *gotDefault != *tt.wantDefault:
				t.Errorf("%s DefaultValue = %q, want %q", tt.key, *gotDefault, *tt.wantDefault)
			}
		})
	}
}
