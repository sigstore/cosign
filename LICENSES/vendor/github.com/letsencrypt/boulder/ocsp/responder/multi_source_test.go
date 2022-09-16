package responder

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
)

const expectedFreshness = 61 * time.Hour

type ok struct{}

func (src ok) Response(context.Context, *ocsp.Request) (*Response, error) {
	return &Response{
		Response: &ocsp.Response{
			Status:     ocsp.Good,
			ThisUpdate: time.Now().Add(-10 * time.Hour),
		},
		Raw: nil,
	}, nil
}

type revoked struct{}

func (src revoked) Response(context.Context, *ocsp.Request) (*Response, error) {
	return &Response{
		Response: &ocsp.Response{
			Status:     ocsp.Revoked,
			ThisUpdate: time.Now().Add(-10 * time.Hour),
		},
		Raw: nil,
	}, nil
}

type stale struct{}

func (src stale) Response(context.Context, *ocsp.Request) (*Response, error) {
	return &Response{
		Response: &ocsp.Response{
			Status:     ocsp.Good,
			ThisUpdate: time.Now().Add(-70 * time.Hour),
		},
		Raw: nil,
	}, nil
}

type fail struct{}

func (src fail) Response(context.Context, *ocsp.Request) (*Response, error) {
	return nil, errors.New("failure")
}

// timeout is a Source that will not return until its chan is closed.
type timeout struct {
	ch <-chan struct{}
}

func (src timeout) Response(context.Context, *ocsp.Request) (*Response, error) {
	<-src.ch
	return nil, errors.New("failure")
}

func TestMultiSource(t *testing.T) {
	type testCase struct {
		primary        Source
		secondary      Source
		expectedError  bool
		expectedStatus int // only checked if expectedError is false
	}
	ignored := 99
	cases := map[string]testCase{
		"ok-ok":           {ok{}, ok{}, false, ocsp.Good},
		"ok-fail":         {ok{}, fail{}, false, ocsp.Good},
		"ok-revoked":      {ok{}, revoked{}, false, ocsp.Good},
		"ok-stale":        {ok{}, stale{}, false, ocsp.Good},
		"ok-timeout":      {ok{}, timeout{}, false, ocsp.Good},
		"fail-ok":         {fail{}, ok{}, true, ignored},
		"fail-fail":       {fail{}, fail{}, true, ignored},
		"fail-revoked":    {fail{}, revoked{}, true, ignored},
		"fail-stale":      {fail{}, stale{}, true, ignored},
		"fail-timeout":    {fail{}, timeout{}, true, ignored},
		"revoked-ok":      {revoked{}, ok{}, false, ocsp.Revoked},
		"revoked-fail":    {revoked{}, fail{}, false, ocsp.Revoked},
		"revoked-revoked": {revoked{}, revoked{}, false, ocsp.Revoked},
		"revoked-stale":   {revoked{}, stale{}, false, ocsp.Revoked},
		"revoked-timeout": {revoked{}, timeout{}, false, ocsp.Revoked},
		"stale-ok":        {stale{}, ok{}, false, ocsp.Good},
		"stale-fail":      {stale{}, fail{}, false, ocsp.Good},
		"stale-revoked":   {stale{}, revoked{}, false, ocsp.Good},
		"stale-stale":     {stale{}, stale{}, false, ocsp.Good},
		"stale-timeout":   {stale{}, timeout{}, false, ocsp.Good},
		"timeout-ok":      {timeout{}, ok{}, true, ignored},
		"timeout-fail":    {timeout{}, fail{}, true, ignored},
		"timeout-revoked": {timeout{}, revoked{}, true, ignored},
		"timeout-stale":   {timeout{}, stale{}, true, ignored},
		"timeout-timeout": {timeout{}, timeout{}, true, ignored},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src, err := NewMultiSource(tc.primary, tc.secondary, expectedFreshness, metrics.NoopRegisterer, blog.NewMock())
			test.AssertNotError(t, err, "failed to create multiSource")

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			resp, err := src.Response(ctx, &ocsp.Request{})
			if err != nil {
				if !tc.expectedError {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			if tc.expectedError {
				t.Errorf("expected error, got none")
			}
			if resp.Status != tc.expectedStatus {
				t.Errorf("expected response status %d, got %d", tc.expectedStatus, resp.Status)
			}
		})
	}
}

func TestSecondaryTimeout(t *testing.T) {
	ch := make(chan struct{})
	src, err := NewMultiSource(&ok{}, &timeout{ch: ch}, expectedFreshness, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	starting_goroutines := runtime.NumGoroutine()

	for i := 0; i < 1000; i++ {
		_, err = src.Response(ctx, &ocsp.Request{})
		test.AssertNotError(t, err, "unexpected error")
	}

	close(ch)
	// Wait for the goroutines to exit
	time.Sleep(40 * time.Millisecond)
	goroutine_diff := runtime.NumGoroutine() - starting_goroutines
	if goroutine_diff > 0 {
		t.Fatalf("expected no lingering goroutines. found %d", goroutine_diff)
	}
}

func TestPrimaryStale(t *testing.T) {
	err := features.Set(map[string]bool{
		"ROCSPStage2": true,
	})
	test.AssertNotError(t, err, "setting features")

	src, err := NewMultiSource(stale{}, ok{}, expectedFreshness, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create multiSource")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err := src.Response(ctx, &ocsp.Request{})
	test.AssertNotError(t, err, "getting response")

	age := time.Since(resp.ThisUpdate)
	if age > expectedFreshness {
		t.Errorf("expected response to be fresh, but it was %s old", age)
	}
}
