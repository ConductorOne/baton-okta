package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain             = field.StringField("domain", field.WithRequired(true), field.WithDescription("The URL for the Okta organization"))
	apiToken           = field.StringField("api-token", field.WithDescription("The API token for the service account"))
	oktaClientId       = field.StringField("okta-client-id", field.WithDescription("The Okta Client ID"))
	oktaPrivateKeyId   = field.StringField("okta-private-key-id", field.WithDescription("The Okta Private Key ID"))
	oktaPrivateKey     = field.StringField("okta-private-key", field.WithDescription("The Okta Private Key. This can be the whole private key or the path to the private key"))
	syncInactivateApps = field.BoolField("sync-inactive-apps", field.WithDescription("Whether to sync inactive apps or not"), field.WithDefaultValue(true))
	oktaProvisioning   = field.BoolField("okta-provisioning")
	ciam               = field.BoolField("ciam", field.WithDescription("Whether to run in CIAM mode or not. In CIAM mode, only roles and the users assigned to roles are synced"))
	ciamEmailDomains   = field.StringSliceField("ciam-email-domains",
		field.WithDescription("The email domains to use for CIAM mode. Any users that don't have an email address with one of the provided domains will be ignored, unless explicitly granted a role"))
	cache                 = field.BoolField("cache", field.WithDescription("Enable response cache"), field.WithDefaultValue(true))
	cacheTTI              = field.IntField("cache-tti", field.WithDescription("Response cache cleanup interval in seconds"), field.WithDefaultValue(60))
	cacheTTL              = field.IntField("cache-ttl", field.WithDescription("Response cache time to live in seconds"), field.WithDefaultValue(300))
	syncCustomRoles       = field.BoolField("sync-custom-roles", field.WithDescription("Enable syncing custom roles"), field.WithDefaultValue(false))
	skipSecondaryEmails   = field.BoolField("skip-secondary-emails", field.WithDescription("Skip syncing secondary emails"), field.WithDefaultValue(false))
	awsIdentityCenterMode = field.BoolField("aws-identity-center-mode",
		field.WithDescription("Whether to run in AWS Identity center mode or not. In AWS mode, only samlRoles for groups and the users assigned to groups are synced"))
	awsAllowGroupToDirectAssignmentConversionForProvisioning = field.BoolField("aws-allow-group-to-direct-assignment-conversion-for-provisioning",
		field.WithDescription("Whether to allow group to direct assignment conversion when provisioning"))
	awsSourceIdentityMode = field.BoolField("aws-source-identity-mode",
		field.WithDescription("Enable AWS source identity mode. When set, user and group identities are loaded from the source connector .c1z file"))
	awsOktaAppId = field.StringField("aws-okta-app-id", field.WithDescription("The Okta app id for the AWS application"))
	SyncSecrets  = field.BoolField("sync-secrets", field.WithDescription("Whether to sync secrets or not"), field.WithDefaultValue(false))
)

var relationships = []field.SchemaFieldRelationship{
	field.FieldsDependentOn([]field.SchemaField{oktaPrivateKeyId, oktaPrivateKey}, []field.SchemaField{oktaClientId}),
	field.FieldsDependentOn([]field.SchemaField{awsOktaAppId}, []field.SchemaField{awsIdentityCenterMode}),
	field.FieldsMutuallyExclusive(apiToken, oktaClientId),
	field.FieldsAtLeastOneUsed(apiToken, oktaClientId),
	field.FieldsMutuallyExclusive(ciam, awsIdentityCenterMode),
	field.FieldsRequiredTogether(awsIdentityCenterMode, awsOktaAppId),
	field.FieldsDependentOn([]field.SchemaField{awsSourceIdentityMode, awsAllowGroupToDirectAssignmentConversionForProvisioning}, []field.SchemaField{awsIdentityCenterMode}),
}

var configuration = field.NewConfiguration([]field.SchemaField{
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
	awsIdentityCenterMode,
	awsOktaAppId,
	SyncSecrets,
	awsSourceIdentityMode,
	awsAllowGroupToDirectAssignmentConversionForProvisioning,
}, field.WithConstraints(relationships...))
