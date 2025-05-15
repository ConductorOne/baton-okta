package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	mapset "github.com/deckarep/golang-set/v2"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Generic for requesting events from the event log and handling them.
// Multiple filters may be called for the same event if multiple match said event.
type EventFilter struct {
	// Required, will only get events that match at least one of the event types.
	EventTypes mapset.Set[string]
	// Optional, will only match events with the given actor type.
	ActorType string
	// Optional, will only match events which contain the given target types.
	// May contain additional targets.
	TargetTypes mapset.Set[string]
	// Required, will be called for each event that matches the filter.
	EventHandler func(*oktaSDK.LogEvent, map[string][]*oktaSDK.LogTarget, *v2.Event) error
}

func filterJoiner(joiner string, filters ...string) string {
	if len(filters) == 0 {
		return ""
	} else if len(filters) == 1 {
		return filters[0]
	}
	return fmt.Sprintf(`(%s)`, strings.Join(filters, joiner))
}

func filterMaker(left string, right string) string {
	return fmt.Sprintf(`%s eq "%s"`, left, right)
}

func (filter *EventFilter) Filter() string {
	eventFilters := []string{}
	for _, eventType := range filter.EventTypes.ToSlice() {
		eventFilters = append(eventFilters, filterMaker("eventType", eventType))
	}
	eventFilter := filterJoiner(" or ", eventFilters...)

	actorFilter := ""
	if filter.ActorType != "" {
		actorFilter = filterMaker("actor.type", filter.ActorType)
	}

	targetFilters := []string{}
	for _, targetType := range filter.TargetTypes.ToSlice() {
		targetFilters = append(targetFilters, filterMaker("target.type", targetType))
	}
	targetFilter := filterJoiner(" and ", targetFilters...)

	filters := []string{}
	for _, filter := range []string{eventFilter, actorFilter, targetFilter} {
		if filter != "" {
			filters = append(filters, filter)
		}
	}

	return filterJoiner(" and ", filters...)
}

func (filter *EventFilter) Matches(event *oktaSDK.LogEvent) bool {
	// is the event type in our set?
	if !filter.EventTypes.Contains(event.EventType) {
		return false
	}

	// if we have actor types, is the actor type in our set?
	if filter.ActorType != "" && filter.ActorType != event.Actor.Type {
		return false
	}

	// if we have target types, is at least one of the target types in our set?
	if filter.TargetTypes.Cardinality() > 0 {
		targetSet := mapset.NewSet[string]()
		for _, target := range event.Target {
			targetSet.Add(target.Type)
		}

		if filter.TargetTypes.Intersect(targetSet).Cardinality() == 0 {
			return false
		}
	}

	return true
}

func (filter *EventFilter) Handle(event *oktaSDK.LogEvent) (*v2.Event, error) {
	targetMap := make(map[string][]*oktaSDK.LogTarget)
	for _, target := range event.Target {
		targetMap[target.Type] = append(targetMap[target.Type], target)
	}

	rv := &v2.Event{
		Id:         event.Uuid,
		OccurredAt: timestamppb.New(*event.Published),
	}

	err := filter.EventHandler(event, targetMap, rv)
	if err != nil {
		return nil, err
	}

	return rv, nil
}
