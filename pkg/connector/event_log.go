package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	oktaSDK "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *Okta) newListLogEventsRequest(ctx context.Context, earliestEvent *timestamppb.Timestamp, pageSize int, filters ...string) *oktaSDK.ApiListLogEventsRequest {
	request := c.clientV5.SystemLogAPI.ListLogEvents(ctx)

	if pageSize == 0 || pageSize > defaultLimit {
		request = request.Limit(int32(defaultLimit))
	} else {
		request = request.Limit(int32(pageSize)) //nolint:gosec // Safe
	}

	if earliestEvent != nil {
		request = request.Since(earliestEvent.AsTime())
	}

	if len(filters) > 0 {
		request = request.Filter(strings.Join(filters, " or "))
	}

	return &request
}

func (c *Okta) ListEvents(
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

	var logs []oktaSDK.LogEvent
	var resp *oktaSDK.APIResponse
	var err error

	if pToken.Cursor == "" {
		apiRequest := c.newListLogEventsRequest(ctx, earliestEvent, pToken.Size, filters...)
		logs, resp, err = apiRequest.Execute()
		if err != nil {
			anno, err := wrapErrorV5(resp, err, errors.New("okta-connectorv2: failed to list events"))
			return nil, nil, anno, err
		}
	} else {
		prevResp, err := deserializeOktaResponseV5(pToken.Cursor) //nolint:bodyclose // just a dummy response
		if err != nil {
			return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to deserialize cursor: %w", err)
		}
		prevAPIResponse := oktaSDK.NewAPIResponse(prevResp, c.clientV5, nil)
		if prevAPIResponse.HasNextPage() {
			l.Debug("okta-connectorv2: getting next page for ListLogEvents", zap.String("next_page", prevAPIResponse.NextPage()))
			resp, err = prevAPIResponse.Next(&logs)
			if err != nil {
				anno, err := wrapErrorV5(resp, err, errors.New("okta-connectorv2: failed to get next page for ListLogEvents"))
				return nil, nil, anno, err
			}
		} else {
			// (jallers) we don't expect this to happen
			l.Warn("okta-connectorv2: no next page for ListLogEvents", zap.String("cursor", pToken.Cursor))
		}
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

	nextCursor, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	l.Debug("okta-connectorv2: processed logs", zap.Any("log_count", len(logs)), zap.Any("next_cursor", nextCursor))

	streamState := &pagination.StreamState{Cursor: nextCursor, HasMore: false}
	// Okta event logs are a stream and will always have a next page. We are at the end of the
	// stream if there are no more logs. Alternatively, we could check if the "after" parameter
	// in the Link header of the response is the same as the "after" parameter in the current request.
	if resp.HasNextPage() && len(logs) > 0 {
		streamState.HasMore = true
	}

	return rv, streamState, annos, nil
}
