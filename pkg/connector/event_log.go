package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	oktaV5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (connector *Okta) newListLogEventsRequest(ctx context.Context, earliestEvent *timestamppb.Timestamp, pToken *pagination.StreamToken, filters ...string) *oktaV5.ApiListLogEventsRequest {
	request := connector.clientV5.SystemLogAPI.ListLogEvents(ctx)

	size := pToken.Size
	if size == 0 || size > defaultLimit {
		request = request.Limit(int32(defaultLimit))
	} else {
		request = request.Limit(int32(size))
	}

	after := pToken.Cursor
	if after != "" {
		request = request.After(after)
	}

	if earliestEvent != nil {
		request = request.Since(earliestEvent.AsTime())
	}

	if len(filters) > 0 {
		request = request.Filter(strings.Join(filters, " or "))
	}

	return &request
}

func (connector *Okta) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	// MJP this will eventually come from config/request?
	activeFilters := []EventFilter{
		UsageFilter,
		GroupChangeFilter,
		ApplicationLifecycleFilter,
		ApplicationMembershipFilter,
		RoleMembershipFilter,
		UserLifecycleFilter,
		CreateGrantFilter,
	}

	// Map from event type to possible filter matches
	filterMap := make(map[string][]*EventFilter)
	for _, filter := range activeFilters {
		for _, eventType := range filter.EventTypes.ToSlice() {
			filterMap[eventType] = append(filterMap[eventType], &filter)
		}
	}

	filters := []string{}
	for _, filter := range activeFilters {
		filters = append(filters, filter.Filter())
	}

	apiRequest := connector.newListLogEventsRequest(ctx, earliestEvent, pToken, filters...)
	logs, resp, err := apiRequest.Execute()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to list events: %w", err)
	}

	// MJP each log is not guaranteed to result in a v2.Event anymore, but it's still likely?
	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		relevantFilters := filterMap[*log.EventType]
		for _, filter := range relevantFilters {
			if filter.Matches(&log) {
				event, err := filter.Handle(l, &log)
				// MJP we don't want to stop, we should just log the error and continue
				if err != nil {
					l.Error("error handling event", zap.Error(err), zap.String("event_type", *log.EventType))
				} else {
					rv = append(rv, event)
				}
			}
		}
	}

	after, annos, err := parseRespV5WithAfter(resp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	streamState := &pagination.StreamState{Cursor: after, HasMore: false}
	// (johnallers)The Okta API docs specify that the cursor should be empty if there are no more results, but I did not see this in testing.
	// Instead, the response provided the same cursor value as was in the request.
	if resp.HasNextPage() && after != pToken.Cursor {
		streamState.HasMore = true
	}

	return rv, streamState, annos, nil
}
