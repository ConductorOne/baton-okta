package connector

import (
	"testing"
)

// allOktaUserStatuses is spelled out (not derived) so a status added to only one
// of enabled/disabled fails TestOktaStatusPredicates_Partition.
var allOktaUserStatuses = []string{
	userStatusActive,
	userStatusProvisioned,
	userStatusRecovery,
	userStatusPasswordExpired,
	userStatusLockedOut,
	userStatusStaged,
	userStatusSuspended,
	userStatusDeprovisioned,
}

func TestOktaStatusPredicates_Partition(t *testing.T) {
	t.Parallel()

	for _, oktaStatus := range allOktaUserStatuses {
		t.Run(oktaStatus, func(t *testing.T) {
			t.Parallel()

			enabled := isEnabledOktaStatus(oktaStatus)
			disabled := isDisabledOktaStatus(oktaStatus)
			if enabled == disabled {
				t.Fatalf("status %s must be exactly one of enabled/disabled, got enabled=%v disabled=%v", oktaStatus, enabled, disabled)
			}
		})
	}

	t.Run("unknown status is neither", func(t *testing.T) {
		t.Parallel()

		const unknown = "NOT_A_STATUS"
		if isEnabledOktaStatus(unknown) || isDisabledOktaStatus(unknown) {
			t.Fatal("unrecognized status must not be classified")
		}
	})
}

// TestPlanUserLifecycle pins the status matrix. STAGED→transition is the regression
// (enable_user used to report already-enabled without touching the account).
func TestPlanUserLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		enabled    bool
		oktaStatus string
		want       lifecyclePlan
	}{
		{name: "enable activates a staged account", enabled: true, oktaStatus: userStatusStaged, want: planTransition},
		{name: "enable unsuspends a suspended account", enabled: true, oktaStatus: userStatusSuspended, want: planTransition},
		{name: "enable leaves an active account alone", enabled: true, oktaStatus: userStatusActive, want: planAlreadySatisfied},
		{name: "enable leaves a provisioned account alone", enabled: true, oktaStatus: userStatusProvisioned, want: planAlreadySatisfied},
		{name: "enable does not clear a recovery state", enabled: true, oktaStatus: userStatusRecovery, want: planAlreadySatisfied},
		{name: "enable does not clear an expired password", enabled: true, oktaStatus: userStatusPasswordExpired, want: planAlreadySatisfied},
		{name: "enable does not unlock a locked out account", enabled: true, oktaStatus: userStatusLockedOut, want: planAlreadySatisfied},
		{name: "enable refuses to reactivate a deactivated account", enabled: true, oktaStatus: userStatusDeprovisioned, want: planUnsupported},
		{name: "enable refuses an unknown status", enabled: true, oktaStatus: "NOT_A_STATUS", want: planUnsupported},

		{name: "disable suspends an active account", oktaStatus: userStatusActive, want: planTransition},
		{name: "disable suspends a provisioned account", oktaStatus: userStatusProvisioned, want: planTransition},
		{name: "disable suspends an account in recovery", oktaStatus: userStatusRecovery, want: planTransition},
		{name: "disable suspends an account with an expired password", oktaStatus: userStatusPasswordExpired, want: planTransition},
		{name: "disable suspends a locked out account", oktaStatus: userStatusLockedOut, want: planTransition},
		{name: "disable leaves a suspended account alone", oktaStatus: userStatusSuspended, want: planAlreadySatisfied},
		{name: "disable leaves a staged account alone", oktaStatus: userStatusStaged, want: planAlreadySatisfied},
		{name: "disable leaves a deactivated account alone", oktaStatus: userStatusDeprovisioned, want: planAlreadySatisfied},
		{name: "disable refuses an unknown status", oktaStatus: "NOT_A_STATUS", want: planUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, transition := planUserLifecycle(tt.oktaStatus, tt.enabled)
			if got != tt.want {
				t.Fatalf("planUserLifecycle(%s, %t) = %v, want %v", tt.oktaStatus, tt.enabled, got, tt.want)
			}
			if (transition != nil) != (tt.want == planTransition) {
				t.Errorf("planUserLifecycle(%s, %t) returned transition=%v, which does not match plan %v", tt.oktaStatus, tt.enabled, transition != nil, got)
			}
		})
	}
}
