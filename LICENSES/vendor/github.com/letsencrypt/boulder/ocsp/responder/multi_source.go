package responder

import (
	"context"
	"errors"
	"time"

	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rocsp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type multiSource struct {
	primary           Source
	secondary         Source
	expectedFreshness time.Duration
	counter           *prometheus.CounterVec
	log               blog.Logger
}

// NewMultiSource creates a source that combines a primary and a secondary source.
//
// It performs lookups using both the primary and secondary Sources.
// It always waits for a response from the primary. If the primary response is
// stale (older than expectedFreshness), it will wait for a "better" response
// from the secondary.
//
// The secondary response will be served only if (a) it has the same status as
// the primary response (good or revoked), and (b) it is fresher than the
// primary response.
//
// A stale response from the primary will still be served if there is no
// better response available from the secondary (due to error, timeout, etc).
func NewMultiSource(primary, secondary Source, expectedFreshness time.Duration, stats prometheus.Registerer, log blog.Logger) (*multiSource, error) {
	if primary == nil || secondary == nil {
		return nil, errors.New("must provide both primary and secondary sources")
	}
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_multiplex_responses",
		Help: "Count of OCSP requests/responses by action taken by the multiSource",
	}, []string{"result"})
	stats.MustRegister(counter)

	return &multiSource{
		primary:           primary,
		secondary:         secondary,
		expectedFreshness: expectedFreshness,
		counter:           counter,
		log:               log,
	}, nil
}

// Response implements the Source interface.
func (src *multiSource) Response(ctx context.Context, req *ocsp.Request) (*Response, error) {
	primaryChan := getResponse(ctx, src.primary, req)

	// Use a separate context for the secondary source. This prevents cancellations
	// from reaching the backend layer (Redis) and causing connections to be closed
	// unnecessarily.
	// https://blog.uptrace.dev/posts/go-context-timeout.html
	secondaryChan := getResponse(context.Background(), src.secondary, req)

	var primaryResponse *Response

	// If the primary source returns first, check the output and return
	// it. If the secondary source wins, then wait for the primary so the
	// results from the secondary can be verified. It is important that we
	// never return a response from the secondary source that is good if the
	// primary has a revoked status. If the secondary source wins the race and
	// passes these checks, return its response instead.
	select {
	case <-ctx.Done():
		src.counter.WithLabelValues("primary_timed_out").Inc()
		return nil, ctx.Err()

	case r := <-primaryChan:
		// If there was an error requesting from the primary, don't bother
		// waiting for the secondary, because we wouldn't be able to
		// check the secondary's status against the (more reliable) primary's
		// status.
		if r.err != nil {
			src.counter.WithLabelValues("primary_error").Inc()
			return nil, r.err
		}
		primaryResponse = r.resp
	}

	// The primary response was fresh enough to serve, go ahead and serve it.
	if time.Since(primaryResponse.ThisUpdate) < src.expectedFreshness {
		src.checkSecondary(primaryResponse, secondaryChan)
		src.counter.WithLabelValues("primary_result").Inc()
		return primaryResponse, nil
	}

	// The primary response was too stale to (ideally) serve. This will be
	// a common path once we stop ocsp-updater from writing updated blobs
	// to MariaDB. Try to serve from the secondary.
	var secondaryResponse *Response
	select {
	case <-ctx.Done():
		src.counter.WithLabelValues("timed_out_awaiting_secondary").Inc()
		// Best-effort: return the primary response even though it's stale.
		return primaryResponse, nil

	case secondaryResult := <-secondaryChan:
		if secondaryResult.err != nil {
			if errors.Is(secondaryResult.err, rocsp.ErrRedisNotFound) {
				// This case will happen for several hours after first issuance.
				src.counter.WithLabelValues("primary_stale_secondary_not_found").Inc()
			} else {
				src.counter.WithLabelValues("primary_stale_secondary_error").Inc()
			}

			// Best-effort: return the primary response even though it's stale.
			return primaryResponse, nil
		}
		secondaryResponse = secondaryResult.resp
	}

	// If the secondary response status doesn't match primary, return
	// primary response. For instance this will happen for several hours
	// after any revocation.
	if secondaryResponse.Status != primaryResponse.Status {
		src.counter.WithLabelValues("primary_stale_status_wins").Inc()
		return primaryResponse, nil
	}

	// ROCSP Stage 2 enables serving responses from Redis
	if features.Enabled(features.ROCSPStage2) {
		src.counter.WithLabelValues("secondary").Inc()
		return secondaryResponse, nil
	}

	src.counter.WithLabelValues("primary").Inc()
	return primaryResponse, nil
}

// checkSecondary updates the src.counter metrics when we're planning to return
// a primary response. It checks if the secondary result has already arrived
// (without blocking on it) and updates the metrics accordingly.
func (src *multiSource) checkSecondary(primaryResponse *Response, secondaryChan <-chan responseResult) {
	select {
	case secondaryResult := <-secondaryChan:
		if secondaryResult.err != nil {
			if errors.Is(secondaryResult.err, rocsp.ErrRedisNotFound) {
				// This case will happen for several hours after first issuance.
				src.counter.WithLabelValues("primary_good_secondary_not_found").Inc()
			} else {
				src.counter.WithLabelValues("primary_good_secondary_error").Inc()
			}
		}
		src.counter.WithLabelValues("primary_good_secondary_good").Inc()
	default:
		src.counter.WithLabelValues("primary_good_secondary_slow").Inc()
	}
}

type responseResult struct {
	resp *Response
	err  error
}

// getResponse provides a thin wrapper around an underlying Source's Response
// method, calling it in a goroutine and passing the result back on a channel.
func getResponse(ctx context.Context, src Source, req *ocsp.Request) chan responseResult {
	// Use a buffer so the following goroutine can exit as soon as it's done,
	// rather than blocking on a reader (which would introduce a risk that the
	// other never reads, leaking the goroutine).
	responseChan := make(chan responseResult, 1)

	go func() {
		defer close(responseChan)

		resp, err := src.Response(ctx, req)
		responseChan <- responseResult{resp, err}
	}()

	return responseChan
}
