package connector

// Randomized churn equivalence fuzzer for the source-cache warm path.
//
// The scripted scenarios in sourcecache_sync_test.go each pin one known
// hazard. This test covers the space BETWEEN them: every round applies a
// random batch of org mutations (user lifecycle, membership, group
// lifecycle, renames, role assignments, validator-only touches, and
// occasional mass invalidation), runs a warm sync chained off the previous
// round's output, runs a fresh uncached control sync of the same org
// state, and requires the two to be byte-identical at the reader surface.
// Any divergence — a stale replay, a missed dirty group, a leaked grant —
// fails with the round's seed and mutation log, which replays
// deterministically.
//
// Runs are deterministic by default (fixed seed) so CI is stable; set
// BATON_FUZZ_SEED to explore a different trajectory, and BATON_FUZZ_ROUNDS
// to run longer soaks.

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/logging"
	"github.com/stretchr/testify/require"
)

// fuzzOrgView is a locked copy of the mock org's mutable state, used to
// pick valid mutation targets without racing the handler.
type fuzzOrgView struct {
	activeUsers []string
	allUsers    []string
	groups      []string
	members     map[string][]string
	roles       map[string][]string // group id → role types
}

func (m *mockOkta) fuzzView() fuzzOrgView {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := fuzzOrgView{
		members: map[string][]string{},
		roles:   map[string][]string{},
	}
	for _, id := range m.userOrder {
		v.allUsers = append(v.allUsers, id)
		if m.users[id].Status == "ACTIVE" {
			v.activeUsers = append(v.activeUsers, id)
		}
	}
	for _, gid := range m.groupOrder {
		g := m.groups[gid]
		v.groups = append(v.groups, gid)
		v.members[gid] = append([]string{}, g.Members...)
		for _, r := range g.Roles {
			v.roles[gid] = append(v.roles[gid], r.Type)
		}
	}
	return v
}

type fuzzOp struct {
	name string
	// ready reports whether the op has a valid target in this state.
	ready func(v fuzzOrgView) bool
	apply func(f *fuzzRun, v fuzzOrgView)
}

type fuzzRun struct {
	t      *testing.T
	m      *mockOkta
	rng    *rand.Rand
	nextID int
	log    []string
}

func (f *fuzzRun) id(prefix string) string {
	f.nextID++
	return fmt.Sprintf("fz-%s-%03d", prefix, f.nextID)
}

func (f *fuzzRun) pick(items []string) string {
	return items[f.rng.Intn(len(items))]
}

func (f *fuzzRun) note(format string, args ...any) {
	f.log = append(f.log, fmt.Sprintf(format, args...))
}

// fuzzableRoleTypes are standard org roles the fuzzer assigns to groups
// (drawn from standardRoleTypes so the role resources exist).
var fuzzableRoleTypes = []string{"USER_ADMIN", "HELP_DESK_ADMIN", "APP_ADMIN", "REPORT_ADMIN"}

func fuzzOps() []fuzzOp {
	return []fuzzOp{
		{
			name:  "add-user",
			ready: func(v fuzzOrgView) bool { return true },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				id := f.id("user")
				f.m.addUser(&mockOktaUser{
					ID: id, FirstName: "Fuzz", LastName: id, Email: id + "@x.test",
				})
				f.note("add-user %s", id)
			},
		},
		{
			name:  "deactivate-user",
			ready: func(v fuzzOrgView) bool { return len(v.activeUsers) > 1 },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				uid := f.pick(v.activeUsers)
				f.m.deactivateUser(uid)
				f.note("deactivate-user %s", uid)
			},
		},
		{
			name:  "delete-user",
			ready: func(v fuzzOrgView) bool { return len(v.allUsers) > 2 },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				uid := f.pick(v.allUsers)
				f.m.deleteUser(uid)
				f.note("delete-user %s", uid)
			},
		},
		{
			name:  "create-group",
			ready: func(v fuzzOrgView) bool { return true },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				gid := f.id("group")
				g := &mockOktaGroup{ID: gid, Name: "Fuzz " + gid}
				if len(v.activeUsers) > 0 && f.rng.Intn(2) == 0 {
					g.Members = []string{f.pick(v.activeUsers)}
				}
				f.m.addGroup(g)
				f.note("create-group %s (members=%v)", gid, g.Members)
			},
		},
		{
			name:  "delete-group",
			ready: func(v fuzzOrgView) bool { return len(v.groups) > 1 },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				gid := f.pick(v.groups)
				f.m.deleteGroup(gid)
				f.note("delete-group %s", gid)
			},
		},
		{
			name: "add-member",
			ready: func(v fuzzOrgView) bool {
				return len(v.groups) > 0 && len(v.activeUsers) > 0
			},
			apply: func(f *fuzzRun, v fuzzOrgView) {
				gid := f.pick(v.groups)
				current := map[string]bool{}
				for _, mid := range v.members[gid] {
					current[mid] = true
				}
				var cands []string
				for _, uid := range v.activeUsers {
					if !current[uid] {
						cands = append(cands, uid)
					}
				}
				if len(cands) == 0 {
					return
				}
				uid := f.pick(cands)
				f.m.addMember(gid, uid)
				f.note("add-member %s -> %s", uid, gid)
			},
		},
		{
			name: "remove-member",
			ready: func(v fuzzOrgView) bool {
				for _, gid := range v.groups {
					if len(v.members[gid]) > 0 {
						return true
					}
				}
				return false
			},
			apply: func(f *fuzzRun, v fuzzOrgView) {
				var withMembers []string
				for _, gid := range v.groups {
					if len(v.members[gid]) > 0 {
						withMembers = append(withMembers, gid)
					}
				}
				gid := f.pick(withMembers)
				uid := f.pick(v.members[gid])
				f.m.removeMember(gid, uid)
				f.note("remove-member %s <- %s", uid, gid)
			},
		},
		{
			name:  "rename-group",
			ready: func(v fuzzOrgView) bool { return len(v.groups) > 0 },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				gid := f.pick(v.groups)
				f.m.renameGroup(gid, "Renamed "+f.id("nm"))
				f.note("rename-group %s", gid)
			},
		},
		{
			name:  "touch-group",
			ready: func(v fuzzOrgView) bool { return len(v.groups) > 0 },
			apply: func(f *fuzzRun, v fuzzOrgView) {
				gid := f.pick(v.groups)
				f.m.touchGroup(gid)
				f.note("touch-group %s", gid)
			},
		},
		{
			name: "assign-group-role",
			ready: func(v fuzzOrgView) bool {
				for _, gid := range v.groups {
					if len(v.roles[gid]) < len(fuzzableRoleTypes) {
						return true
					}
				}
				return false
			},
			apply: func(f *fuzzRun, v fuzzOrgView) {
				var cands []string
				for _, gid := range v.groups {
					if len(v.roles[gid]) < len(fuzzableRoleTypes) {
						cands = append(cands, gid)
					}
				}
				gid := f.pick(cands)
				held := map[string]bool{}
				for _, rt := range v.roles[gid] {
					held[rt] = true
				}
				var free []string
				for _, rt := range fuzzableRoleTypes {
					if !held[rt] {
						free = append(free, rt)
					}
				}
				rt := f.pick(free)
				f.m.assignGroupRole(gid, mockOktaGroupRole{AssignmentID: f.id("gra"), Type: rt, Label: rt})
				f.note("assign-group-role %s -> %s", rt, gid)
			},
		},
		{
			name: "revoke-group-role",
			ready: func(v fuzzOrgView) bool {
				for _, gid := range v.groups {
					if len(v.roles[gid]) > 0 {
						return true
					}
				}
				return false
			},
			apply: func(f *fuzzRun, v fuzzOrgView) {
				var withRoles []string
				for _, gid := range v.groups {
					if len(v.roles[gid]) > 0 {
						withRoles = append(withRoles, gid)
					}
				}
				gid := f.pick(withRoles)
				rt := f.pick(v.roles[gid])
				f.m.revokeGroupRole(gid, rt)
				f.note("revoke-group-role %s <- %s", rt, gid)
			},
		},
	}
}

func fuzzEnvInt(name string, def int) int {
	if s := os.Getenv(name); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return def
}

func TestSourceCacheChurnFuzz(t *testing.T) {
	ctx, err := logging.Init(t.Context())
	require.NoError(t, err)

	seed := int64(fuzzEnvInt("BATON_FUZZ_SEED", 20260711))
	rounds := fuzzEnvInt("BATON_FUZZ_ROUNDS", 8)
	t.Logf("churn fuzz: seed=%d rounds=%d (override with BATON_FUZZ_SEED / BATON_FUZZ_ROUNDS)", seed, rounds)

	mock := newMockOkta(t)

	// Seed org: shape mirrors the scripted test so every leg has data from
	// round zero.
	for i := 1; i <= 4; i++ {
		mock.addUser(&mockOktaUser{
			ID: fmt.Sprintf("u%d", i), FirstName: "User", LastName: fmt.Sprintf("N%d", i),
			Email: fmt.Sprintf("u%d@x.test", i),
		})
	}
	mock.addGroup(&mockOktaGroup{ID: "g1", Name: "Group One", Members: []string{"u1", "u2"}})
	mock.addGroup(&mockOktaGroup{ID: "g2", Name: "Group Two", Members: []string{"u3"}})
	mock.addGroup(&mockOktaGroup{ID: "g3", Name: "Empty"})
	mock.assignGroupRole("g1", mockOktaGroupRole{AssignmentID: "gra-seed", Type: "USER_ADMIN", Label: "Group Administrator"})

	h := newSyncHarness(ctx, t, mock)
	f := &fuzzRun{t: t, m: mock, rng: rand.New(rand.NewSource(seed))}
	ops := fuzzOps()

	prev := h.runSync("fuzz-cold", "")

	for round := 1; round <= rounds; round++ {
		nOps := 1 + f.rng.Intn(3)
		f.log = f.log[:0]
		for i := 0; i < nOps; i++ {
			// Re-view after each mutation so ops in the same round compose
			// against current state, exactly as real churn would.
			v := mock.fuzzView()
			var ready []fuzzOp
			for _, op := range ops {
				if op.ready(v) {
					ready = append(ready, op)
				}
			}
			require.NotEmpty(t, ready)
			ready[f.rng.Intn(len(ready))].apply(f, v)
		}

		// ~1 round in 6 also invalidates every group's validator, so mass
		// invalidation is fuzzed IN COMBINATION with churn, not only in
		// isolation.
		if f.rng.Intn(6) == 0 {
			for _, gid := range mock.fuzzView().groups {
				mock.touchGroup(gid)
			}
			f.note("mass-invalidation")
		}

		warm := h.runSync(fmt.Sprintf("fuzz-warm-%02d", round), prev)
		control := h.runSync(fmt.Sprintf("fuzz-control-%02d", round), "")

		wSnap := h.snapshot(warm)
		cSnap := h.snapshot(control)
		if !assertSnapshotsEqual(t, cSnap, wSnap) {
			t.Fatalf("round %d diverged (seed=%d); mutations this round:\n  %s",
				round, seed, joinLines(f.log))
		}
		prev = warm
	}
}

func assertSnapshotsEqual(t *testing.T, control, warm map[string]string) bool {
	t.Helper()
	ok := true
	for k, cv := range control {
		wv, found := warm[k]
		if !found {
			t.Errorf("warm sync MISSING %s", k)
			ok = false
		} else if wv != cv {
			t.Errorf("warm sync DIFFERS at %s:\n  control: %s\n  warm:    %s", k, cv, wv)
			ok = false
		}
	}
	for k := range warm {
		if _, found := control[k]; !found {
			t.Errorf("warm sync EXTRA %s: %s", k, warm[k])
			ok = false
		}
	}
	return ok
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
