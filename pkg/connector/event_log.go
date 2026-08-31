package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// activeFilters is every filter requested from the Okta System Log. A filter that
// is not listed here is never queried, so its event types are silently ignored.
// MJP this will eventually come from config/request?
var activeFilters = []EventFilter{
	UsageFilter,
	GroupChangeFilter,
	ApplicationLifecycleFilter,
	ApplicationMembershipFilter,
	ApplicationMembershipRevokeFilter,
	RoleMembershipFilter,
	RoleMembershipRevokeFilter,
	UserLifecycleFilter,
	CreateGrantFilter,
	CreateRevokeFilter,
}

func (connector *Okta) createQueryParams(earliestEvent *timestamppb.Timestamp, pToken *pagination.StreamToken, filters ...string) *query.Params {
	qp := queryParams(pToken.Size, pToken.Cursor)
	if earliestEvent != nil {
		qp.Since = earliestEvent.AsTime().Format(time.RFC3339)
	}

	if len(filters) == 0 {
		return qp
	} else if len(filters) == 1 {
		qp.Filter = filters[0]
		return qp
	}

	qp.Filter = strings.Join(filters, " or ")

	return qp
}

func (connector *Okta) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

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

	qp := connector.createQueryParams(earliestEvent, pToken, filters...)

	logs, resp, err := connector.client.LogEvent.GetLogs(ctx, qp)
	if err != nil {
		// Route through the shared handler like every other call site; bare, this
		// returned an SDK error carrying no grpc code, no status, and no prefix.
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to list system log events: %w", handleOktaResponseError(resp, err))
	}

	// MJP each log is not guaranteed to result in a v2.Event anymore, but it's still likely?
	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		relevantFilters := filterMap[log.EventType]
		for _, filter := range relevantFilters {
			if filter.Matches(log) {
				event, err := filter.Handle(l, log)
				// MJP we don't want to stop, we should just log the error and continue
				switch {
				case err != nil:
					l.Error("error handling event", zap.Error(err), zap.String("event_type", log.EventType))
				case event != nil:
					rv = append(rv, event)
				default:
					// The handler matched but had nothing to emit, and logged its reason
					// at the skip site.
					l.Debug("skipped event", zap.String("event_type", log.EventType))
				}
			}
		}
	}

	after, annos, err := parseResp(resp)
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
