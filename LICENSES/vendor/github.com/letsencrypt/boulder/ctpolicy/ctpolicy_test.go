package ctpolicy

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/ctconfig"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

type mockPub struct{}

func (mp *mockPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	return &pubpb.Result{Sct: []byte{0}}, nil
}

type mockFailPub struct{}

func (mp *mockFailPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	return nil, errors.New("BAD")
}

type mockSlowPub struct{}

func (mp *mockSlowPub) SubmitToSingleCTWithResult(ctx context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	<-ctx.Done()
	return nil, errors.New("timed out")
}

func TestGetGoogleSCTs(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	missingSCTErr := berrors.MissingSCTs
	testCases := []struct {
		name       string
		mock       pubpb.PublisherClient
		groups     []ctconfig.CTGroup
		ctx        context.Context
		result     core.SCTDERs
		errRegexp  *regexp.Regexp
		berrorType *berrors.ErrorType
	}{
		{
			name: "basic success case",
			mock: &mockPub{},
			groups: []ctconfig.CTGroup{
				{
					Name: "a",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:    context.Background(),
			result: core.SCTDERs{[]byte{0}, []byte{0}},
		},
		{
			name: "basic failure case",
			mock: &mockFailPub{},
			groups: []ctconfig.CTGroup{
				{
					Name: "a",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:        context.Background(),
			errRegexp:  regexp.MustCompile("CT log group \".\": all submissions failed"),
			berrorType: &missingSCTErr,
		},
		{
			name: "parent context timeout failure case",
			mock: &mockSlowPub{},
			groups: []ctconfig.CTGroup{
				{
					Name: "a",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []ctconfig.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:       expired,
			errRegexp: regexp.MustCompile("CT log group \".\": context deadline exceeded"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctp := New(tc.mock, tc.groups, nil, nil, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0}, time.Time{})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.errRegexp != nil {
				if !tc.errRegexp.MatchString(err.Error()) {
					t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
				}
				if tc.berrorType != nil {
					test.AssertErrorIs(t, err, *tc.berrorType)
				}
			}
		})
	}
}

func TestGetOperatorSCTs(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	missingSCTErr := berrors.MissingSCTs
	testCases := []struct {
		name       string
		mock       pubpb.PublisherClient
		groups     loglist.List
		ctx        context.Context
		result     core.SCTDERs
		expectErr  string
		berrorType *berrors.ErrorType
	}{
		{
			name: "basic success case",
			mock: &mockPub{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:    context.Background(),
			result: core.SCTDERs{[]byte{0}, []byte{0}},
		},
		{
			name: "basic failure case",
			mock: &mockFailPub{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:        context.Background(),
			expectErr:  "failed to get 2 SCTs, got error(s):",
			berrorType: &missingSCTErr,
		},
		{
			name: "parent context timeout failure case",
			mock: &mockSlowPub{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:       expired,
			expectErr: "failed to get 2 SCTs before ctx finished",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctp := New(tc.mock, nil, nil, tc.groups, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0}, time.Time{})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.expectErr != "" {
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("Error %q did not match expected %q", err, tc.expectErr)
				}
				if tc.berrorType != nil {
					test.AssertErrorIs(t, err, *tc.berrorType)
				}
			}
		})
	}
}

type failOne struct {
	badURL string
}

func (mp *failOne) SubmitToSingleCTWithResult(_ context.Context, req *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	if req.LogURL == mp.badURL {
		return nil, errors.New("BAD")
	}
	return &pubpb.Result{Sct: []byte{0}}, nil
}

type slowPublisher struct{}

func (sp *slowPublisher) SubmitToSingleCTWithResult(_ context.Context, req *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	time.Sleep(time.Second)
	return &pubpb.Result{Sct: []byte{0}}, nil
}

func TestGetSCTsMetrics(t *testing.T) {
	ctp := New(&failOne{badURL: "abc"}, []ctconfig.CTGroup{
		{
			Name: "a",
			Logs: []ctconfig.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
		{
			Name: "b",
			Logs: []ctconfig.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
	}, nil, nil, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "ghi", "group": "a"}, 1)
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "ghi", "group": "b"}, 1)
}

func TestGetSCTsFailMetrics(t *testing.T) {
	// When an entire log group fails, we should increment the "winner of SCT
	// race" stat for that group under the fictional log "all_failed".
	ctp := New(&failOne{badURL: "abc"}, []ctconfig.CTGroup{
		{
			Name: "a",
			Logs: []ctconfig.LogDescription{
				{URI: "abc", Key: "def"},
			},
		},
	}, nil, nil, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	if err == nil {
		t.Fatal("GetSCTs should have failed")
	}
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "all_failed", "group": "a"}, 1)

	// Same thing, but for when an entire log group times out.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ctp = New(&slowPublisher{}, []ctconfig.CTGroup{
		{
			Name: "a",
			Logs: []ctconfig.LogDescription{
				{URI: "abc", Key: "def"},
			},
		},
	}, nil, nil, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
	_, err = ctp.GetSCTs(ctx, []byte{0}, time.Time{})
	if err == nil {
		t.Fatal("GetSCTs should have failed")
	}
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "timeout", "group": "a"}, 1)
}

// A mock publisher that counts submissions
type countEm struct {
	count int
}

func (ce *countEm) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	ce.count++
	return &pubpb.Result{Sct: []byte{0}}, nil
}

func TestStagger(t *testing.T) {
	countingPub := &countEm{}
	ctp := New(countingPub, []ctconfig.CTGroup{
		{
			Name:    "a",
			Stagger: cmd.ConfigDuration{Duration: 500 * time.Millisecond},
			Logs: []ctconfig.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
	}, nil, nil, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	if countingPub.count != 1 {
		t.Errorf("wrong number of requests to publisher. got %d, expected 1", countingPub.count)
	}
}
