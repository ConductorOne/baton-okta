package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// usageEventFeedID identifies the feed carrying SSO usage. It is split from the
// main feed because sign-ins far outnumber every other System Log event, so a
// shared cursor would make change events wait behind usage volume.
const usageEventFeedID = "okta_usage_events"

// usageFilters and changeFilters are every filter requested from the Okta System
// Log, one list per feed. A filter that is listed in neither is never queried, so
// its event types are silently ignored.
// MJP this will eventually come from config/request?
var (
	usageFilters = []EventFilter{
		UsageFilter,
	}
	changeFilters = []EventFilter{
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
)

var _ connectorbuilder.EventFeedsLimited = (*Okta)(nil)

// EventFeeds keeps the change feed on the legacy feed ID so cursors stored by C1
// before the split, and requests that name no feed, still resolve to it.
func (o *Okta) EventFeeds(ctx context.Context) []connectorbuilder.EventFeed {
	return []connectorbuilder.EventFeed{
		newEventFeed(o, connectorbuilder.LegacyBatonFeedId, changeFilters,
			v2.EventType_EVENT_TYPE_RESOURCE_CHANGE,
			v2.EventType_EVENT_TYPE_CREATE_GRANT,
			v2.EventType_EVENT_TYPE_CREATE_REVOKE,
		),
		newEventFeed(o, usageEventFeedID, usageFilters,
			v2.EventType_EVENT_TYPE_USAGE,
		),
	}
}

type eventFeed struct {
	connector *Okta
	metadata  *v2.EventFeedMetadata
	filters   []EventFilter
	// filterMap maps an Okta event type to the filters that may handle it.
	filterMap map[string][]*EventFilter
}

func newEventFeed(connector *Okta, id string, filters []EventFilter, eventTypes ...v2.EventType) *eventFeed {
	filterMap := make(map[string][]*EventFilter)
	for i := range filters {
		filter := &filters[i]
		for _, eventType := range filter.EventTypes.ToSlice() {
			filterMap[eventType] = append(filterMap[eventType], filter)
		}
	}

	return &eventFeed{
		connector: connector,
		metadata: v2.EventFeedMetadata_builder{
			Id:                  id,
			SupportedEventTypes: eventTypes,
		}.Build(),
		filters:   filters,
		filterMap: filterMap,
	}
}

func (f *eventFeed) EventFeedMetadata(ctx context.Context) *v2.EventFeedMetadata {
	return f.metadata
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

func (f *eventFeed) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	filters := make([]string, 0, len(f.filters))
	for _, filter := range f.filters {
		filters = append(filters, filter.Filter())
	}

	qp := f.connector.createQueryParams(earliestEvent, pToken, filters...)

	logs, resp, err := f.connector.client.LogEvent.GetLogs(ctx, qp)
	if err != nil {
		// Route through the shared handler like every other call site; bare, this
		// returned an SDK error carrying no grpc code, no status, and no prefix.
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to list system log events: %w", handleOktaResponseError(resp, err))
	}

	// MJP each log is not guaranteed to result in a v2.Event anymore, but it's still likely?
	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		relevantFilters := f.filterMap[log.EventType]
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
