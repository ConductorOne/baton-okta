package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	usageFilter           = `eventType eq "user.authentication.sso" and actor.type eq "User" and target.type eq "AppInstance"`
	groupMembershipFilter = `eventType eq "group.user_membership.add" and target.type eq "UserGroup"`
)

func targetMap(logEvent *oktaSDK.LogEvent) (map[string][]*oktaSDK.LogTarget, error) {
	rv := make(map[string][]*oktaSDK.LogTarget)
	for _, target := range logEvent.Target {
		rv[target.Type] = append(rv[target.Type], target)
	}
	return rv, nil
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

	filter := strings.Join(filters, ") or (")
	qp.Filter = fmt.Sprintf(`(%s)`, filter)

	return qp
}

func (connector *Okta) ListEvents(
	ctx context.Context,
	earliestEvent *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	qp := connector.createQueryParams(earliestEvent, pToken, groupMembershipFilter, usageFilter)

	logs, resp, err := connector.client.LogEvent.GetLogs(ctx, qp)
	if err != nil {
		return nil, nil, nil, err
	}

	rv := make([]*v2.Event, 0, len(logs))
	for _, log := range logs {
		targetMap, err := targetMap(log)
		if err != nil {
			return nil, nil, nil, err
		}

		event := &v2.Event{
			Id:         log.Uuid,
			OccurredAt: timestamppb.New(*log.Published),
		}
		switch log.EventType {
		case "user.authentication.sso":
			if len(targetMap["AppInstance"]) != 1 {
				continue
			}
			appInstance := targetMap["AppInstance"][0]
			userTrait, err := resource.NewUserTrait(resource.WithEmail(log.Actor.AlternateId, true))
			if err != nil {
				return nil, nil, nil, err
			}
			event.Event = &v2.Event_UsageEvent{
				UsageEvent: &v2.UsageEvent{
					TargetResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: appInstance.Type,
							Resource:     appInstance.Id,
						},
						DisplayName: appInstance.DisplayName,
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
			}
		case "group.user_membership.add":
			if len(targetMap["UserGroup"]) != 1 {
				continue
			}
			userGroup := targetMap["UserGroup"][0]
			event.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeGroup.Id,
						Resource:     userGroup.Id,
					},
				},
			}
		default:
			continue
		}

		rv = append(rv, event)
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
