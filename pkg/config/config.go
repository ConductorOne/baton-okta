package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

const (
	// Field group names.
	ApiTokenGroup = "api-token-group"
	PrivateKeyGroup = "private-key-group"
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
		field.WithRequired(true),
		field.WithDescription("The API token for the service account"),
		field.WithPlaceholder("Your Okta API token"),
		field.WithIsSecret(true),
	)
	oktaClientId = field.StringField("okta-client-id",
		field.WithDisplayName("Okta Client ID"),
		field.WithRequired(true),
		field.WithDescription("The Okta Client ID"),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	oktaPrivateKeyId = field.StringField("okta-private-key-id",
		field.WithDisplayName("Okta Private Key ID"),
		field.WithRequired(true),
		field.WithDescription("The Okta Private Key ID"),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	oktaPrivateKey = field.StringField("okta-private-key",
		field.WithDisplayName("Okta Private Key"),
		field.WithRequired(true),
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
		field.WithDescription("Whether to enable syncing custom roles or not"),
		field.WithDefaultValue(false),
	)
	skipSecondaryEmails = field.BoolField("skip-secondary-emails",
		field.WithDisplayName("Skip secondary emails"),
		field.WithDescription("Whether to skip syncing secondary emails or not"),
		field.WithDefaultValue(false),
	)
	syncSecrets = field.BoolField("sync-secrets",
		field.WithDisplayName("Sync secrets"),
		field.WithDescription("Whether to sync secrets or not"),
		field.WithDefaultValue(false),
	)
	filterEmailDomains = field.StringSliceField("filter-email-domains",
		field.WithDisplayName("Filter email domains"),
		field.WithDescription("Press Enter to add multiple items."),
		field.WithPlaceholder("A list of user email domains to include for syncs, e.g. acmeco.com"),
	)
	skipAppGroups = field.BoolField("skip-app-groups",
		field.WithDisplayName("Skip app groups"),
		field.WithDescription("Whether to skip syncing APP_GROUP type groups (Okta push groups created by SCIM-integrated apps) or not"),
		field.WithDefaultValue(false),
	)
)

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
	field.WithConnectorDisplayName("Okta"),
	field.WithIconUrl("/static/app-icons/okta.svg"),
	field.WithIsDirectory(true),
	field.WithFieldGroups([]field.SchemaFieldGroup{
		{
			Name: ApiTokenGroup,
			DisplayName: "API Token",
			HelpText: "Use an API token to authenticate.",
			Fields:    []field.SchemaField{
				apiToken,
				domain,
				syncInactivateApps,
				cache,
				cacheTTI,
				cacheTTL,
				syncCustomRoles,
				skipSecondaryEmails,
				syncSecrets,
				filterEmailDomains,
				skipAppGroups},
		},
		{
			Name: PrivateKeyGroup,
			DisplayName: "Private Key",
			HelpText: "Use a private key to authenticate.",
			Fields: []field.SchemaField{
				oktaClientId,
				oktaPrivateKeyId,
				oktaPrivateKey,
				domain,
				syncInactivateApps,
				cache,
				cacheTTI,
				cacheTTL,
				syncCustomRoles,
				skipSecondaryEmails,
				syncSecrets,
				filterEmailDomains,
				skipAppGroups},
			ExportTarget: field.ExportTargetCLIOnly,
		},
	}),
)
