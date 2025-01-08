package connector

import (
	"net/http"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	oktaRequestIDHeader          = "X-Okta-Request-Id"
	oktaRateLimitLimitHeader     = "X-Rate-Limit-Limit"
	oktaRateLimitRemainingHeader = "X-Rate-Limit-Remaining"
	oktaRateLimitResetHeader     = "X-Rate-Limit-Reset"
)

func extractRateLimitData(resp *http.Response) (*v2.RateLimitDescription, error) {
	iLimit, iRemaining, iReset, hasLimit := getRateLimit(resp)

	if !hasLimit {
		return emptyRateLimitDescription(), nil
	}

	return &v2.RateLimitDescription{
		Limit:     iLimit,
		Remaining: iRemaining,
		ResetAt:   &timestamppb.Timestamp{Seconds: iReset},
	}, nil
}

func getRateLimit(resp *http.Response) (int64, int64, int64, bool) {
	if resp == nil {
		return 0, 0, 0, false
	}
	limit := resp.Header.Get(oktaRateLimitLimitHeader)
	remaining := resp.Header.Get(oktaRateLimitRemainingHeader)
	reset := resp.Header.Get(oktaRateLimitResetHeader)

	if limit == "" || remaining == "" || reset == "" {
		return 0, 0, 0, false
	}

	iLimit, err := strconv.ParseInt(limit, 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}

	iRemaining, err := strconv.ParseInt(remaining, 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}

	iReset, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}

	return iLimit, iRemaining, iReset, true
}

func emptyRateLimitDescription() *v2.RateLimitDescription {
	return &v2.RateLimitDescription{
		Limit:     0,
		Remaining: 0,
		ResetAt:   &timestamppb.Timestamp{Seconds: 0},
	}
}
