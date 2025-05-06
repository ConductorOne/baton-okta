package connector

import (
	"context"
	"fmt"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func parseTarget(logEvent *oktaSDK.LogEvent) (*oktaSDK.LogTarget, bool) {
	targetAppType := "AppInstance"
	for _, target := range logEvent.Target {
		if target.Type == targetAppType {
			return target, true
		}
	}
	return nil, false
}

func targetMap(logEvent *oktaSDK.LogEvent) (map[string][]*oktaSDK.LogTarget, error) {
	rv := make(map[string][]*oktaSDK.LogTarget)
	for _, target := range logEvent.Target {
		rv[target.Type] = append(rv[target.Type], target)
	}
	return rv, nil
}

func (connector *Okta) listOktaSSOEvents(ctx context.Context, earliestEvent *timestamppb.Timestamp, pToken *pagination.StreamToken) ([]*oktaSDK.LogEvent, *oktaSDK.Response, error) {
	qp := queryParams(pToken.Size, pToken.Cursor)
	if earliestEvent != nil {
		qp.Since = earliestEvent.AsTime().Format(time.RFC3339)
	}
	qp.Filter = `eventType eq "user.authentication.sso" and actor.type eq "User" and target.type eq "AppInstance"`

	logs, resp, err := connector.client.LogEvent.GetLogs(ctx, qp)
	if err != nil {
		return nil, nil, err
	}

	return logs, resp, nil
}

func (connector *Okta) listOktaResourceAccessEvents(ctx context.Context, earliestEvent *timestamppb.Timestamp, pToken *pagination.StreamToken) ([]*oktaSDK.LogEvent, *oktaSDK.Response, error) {
	qp := queryParams(pToken.Size, pToken.Cursor)
	if earliestEvent != nil {
		qp.Since = earliestEvent.AsTime().Format(time.RFC3339)
	}
	qp.Filter = `eventType eq "group.user_membership.add" and target.type eq "UserGroup"`

	logs, resp, err := connector.client.LogEvent.GetLogs(ctx, qp)
	if err != nil {
		return nil, nil, err
	}

	return logs, resp, nil
}

func (connector *Okta) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	logs, resp, err := connector.listOktaResourceAccessEvents(ctx, earliestEvent, pToken)
	if err != nil {
		return nil, nil, nil, err
	}

	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		targetMap, err := targetMap(log)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(targetMap["UserGroup"]) != 1 {
			continue
		}
		userGroup := targetMap["UserGroup"][0]
		rv = append(rv, &v2.Event{
			Id:         log.Uuid,
			OccurredAt: timestamppb.New(*log.Published),
			Event: &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: userGroup.Type,
						Resource:     userGroup.Id,
					},
				},
			},
		})
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
