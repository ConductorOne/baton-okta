package connector

import (
	"context"
	"fmt"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
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

func (connector *Okta) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	logs, resp, err := connector.listOktaSSOEvents(ctx, earliestEvent, pToken)
	if err != nil {
		return nil, nil, nil, err
	}

	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		parsedTarget, isAppInstance := parseTarget(log)
		if !isAppInstance {
			continue
		}
		userTrait, err := resource.NewUserTrait(resource.WithEmail(log.Actor.AlternateId, true))
		if err != nil {
			return nil, nil, nil, err
		}

		rv = append(rv, &v2.Event{
			Id:         log.Uuid,
			OccurredAt: timestamppb.New(*log.Published),
			Event: &v2.Event_UsageEvent{
				UsageEvent: &v2.UsageEvent{
					TargetResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeApp.Id,
							Resource:     parsedTarget.Id,
						},
						DisplayName: parsedTarget.DisplayName,
					},
					ActorResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeUser.Id,
							Resource:     log.Actor.Id,
						},
						DisplayName: log.Actor.DisplayName,
						Annotations: annotations.New(userTrait),
					},
				},
			},
			Annotations: nil,
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
