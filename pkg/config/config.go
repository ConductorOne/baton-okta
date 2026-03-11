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
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	oktaPrivateKey = field.StringField("okta-private-key",
		field.WithDisplayName("Okta Private Key"),
		field.WithDescription("The Okta Private Key. This can be the whole private key or the path to the private key"),
		field.WithIsSecret(true),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	syncInactivateApps = field.BoolField("sync-inactive-apps",
		field.WithDisplayName("Sync inactive apps"),
		field.WithDescription("Whether to sync inactive apps or not"),
		field.WithDefaultValue(true),
	)
	cache = field.BoolField("cache",
		field.WithDisplayName("Enable cache"),
		field.WithDescription("Enable response cache"),
		field.WithDefaultValue(true),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	cacheTTI = field.IntField("cache-tti",
		field.WithDisplayName("Cache TTI"),
		field.WithDescription("Response cache cleanup interval in seconds"),
		field.WithDefaultValue(60),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	cacheTTL = field.IntField("cache-ttl",
		field.WithDisplayName("Cache TTL"),
		field.WithDescription("Response cache time to live in seconds"),
		field.WithDefaultValue(300),
		field.WithExportTarget(field.ExportTargetCLIOnly),
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
	syncSecrets = field.BoolField("sync-secrets",
		field.WithDisplayName("Sync secrets"),
		field.WithDescription("Whether to sync secrets or not"),
		field.WithDefaultValue(false),
	)
	filterEmailDomains = field.StringSliceField("filter-email-domains",
		field.WithDisplayName("Filter email domains"),
		field.WithDescription("Only sync users with primary email addresses that match at least one of the provided domains. When unset or empty, all users will be synced."),
	)
	skipAppGroups = field.BoolField("skip-app-groups",
		field.WithDisplayName("Skip app groups"),
		field.WithDescription("Skip syncing APP_GROUP type groups (Okta push groups created by SCIM-integrated apps)"),
		field.WithDefaultValue(false),
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
	cache,
	cacheTTI,
	cacheTTL,
	syncCustomRoles,
	skipSecondaryEmails,
	syncSecrets,
	filterEmailDomains,
	skipAppGroups,
},
	field.WithConstraints(relationships...),
	field.WithConnectorDisplayName("Okta"),
	field.WithIconUrl("/static/app-icons/okta.svg"),
	field.WithIsDirectory(true),
)
