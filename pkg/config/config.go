package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain = field.StringField("domain",
		field.WithDisplayName("Okta domain"),
		field.WithRequired(true),
		field.WithDescription("The URL for the Okta organization"),
		field.WithPlaceholder("e.g. acmeco.okta.com"),
	)
	apiToken = field.StringField("api-token",
		field.WithDisplayName("API token"),
		field.WithDescription("The API token for the service account"),
		field.WithPlaceholder("Your Okta API token"),
		field.WithIsSecret(true),
	)
	oktaClientId = field.StringField("okta-client-id",
		field.WithDisplayName("Okta Client ID"),
		field.WithDescription("The Okta Client ID"),
	)
	oktaPrivateKeyId = field.StringField("okta-private-key-id",
		field.WithDisplayName("Okta Private Key ID"),
		field.WithDescription("The Okta Private Key ID"),
	)
	oktaPrivateKey = field.StringField("okta-private-key",
		field.WithDisplayName("Okta Private Key"),
		field.WithDescription("The Okta Private Key. This can be the whole private key or the path to the private key"),
		field.WithIsSecret(true),
	)
	syncInactivateApps = field.BoolField("sync-inactive-apps",
		field.WithDisplayName("Sync inactive apps"),
		field.WithDescription("Whether to sync inactive apps or not"),
		field.WithDefaultValue(true),
	)
	oktaProvisioning = field.BoolField("okta-provisioning",
		field.WithDisplayName("Okta provisioning"),
	)
	ciam = field.BoolField("ciam",
		field.WithDisplayName("CIAM mode"),
		field.WithDescription("Whether to run in CIAM mode or not. In CIAM mode, only roles and the users assigned to roles are synced"),
	)
	ciamEmailDomains = field.StringSliceField("ciam-email-domains",
		field.WithDisplayName("CIAM email domains"),
		field.WithDescription("The email domains to use for CIAM mode. Any users that don't have an email address with one of the provided domains will be ignored, unless explicitly granted a role"),
	)
	cache = field.BoolField("cache",
		field.WithDisplayName("Enable cache"),
		field.WithDescription("Enable response cache"),
		field.WithDefaultValue(true),
	)
	cacheTTI = field.IntField("cache-tti",
		field.WithDisplayName("Cache TTI"),
		field.WithDescription("Response cache cleanup interval in seconds"),
		field.WithDefaultValue(60),
	)
	cacheTTL = field.IntField("cache-ttl",
		field.WithDisplayName("Cache TTL"),
		field.WithDescription("Response cache time to live in seconds"),
		field.WithDefaultValue(300),
	)
	syncCustomRoles = field.BoolField("sync-custom-roles",
		field.WithDisplayName("Sync custom roles"),
		field.WithDescription("Enable syncing custom roles"),
		field.WithDefaultValue(false),
	)
	skipSecondaryEmails = field.BoolField("skip-secondary-emails",
		field.WithDisplayName("Skip secondary emails"),
		field.WithDescription("Skip syncing secondary emails"),
		field.WithDefaultValue(false),
	)
	SyncSecrets = field.BoolField("sync-secrets",
		field.WithDisplayName("Sync secrets"),
		field.WithDescription("Whether to sync secrets or not"),
		field.WithDefaultValue(false),
	)
	filterEmailDomains = field.StringSliceField("filter-email-domains",
		field.WithDisplayName("Filter email domains"),
		field.WithDescription("Only sync users with primary email addresses that match at least one of the provided domains. When unset or empty, all users will be synced."),
	)
)

var relationships = []field.SchemaFieldRelationship{
	field.FieldsDependentOn([]field.SchemaField{oktaPrivateKeyId, oktaPrivateKey}, []field.SchemaField{oktaClientId}),
	field.FieldsMutuallyExclusive(apiToken, oktaClientId),
	field.FieldsAtLeastOneUsed(apiToken, oktaClientId),
}

//go:generate go run ./gen
var Config = field.NewConfiguration([]field.SchemaField{
	domain,
	apiToken,
	oktaClientId,
	oktaPrivateKey,
	oktaPrivateKeyId,
	syncInactivateApps,
	oktaProvisioning,
	ciam,
	ciamEmailDomains,
	cache,
	cacheTTI,
	cacheTTL,
	syncCustomRoles,
	skipSecondaryEmails,
	SyncSecrets,
	filterEmailDomains,
},
	field.WithConstraints(relationships...),
	field.WithConnectorDisplayName("Okta"),
	field.WithIconUrl("/static/app-icons/okta.svg"),
	field.WithIsDirectory(true),
)
