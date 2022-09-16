package grpc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
)

const (
	returnOverhead         = 20 * time.Millisecond
	meaningfulWorkOverhead = 100 * time.Millisecond
	clientRequestTimeKey   = "client-request-time"
)

// NoCancelInterceptor is a gRPC interceptor that creates a new context,
// separate from the original context, that has the same deadline but does
// not propagate cancellation. This is used by SA.
//
// Because this interceptor throws away annotations on the context, it
// breaks tracing for events that get the modified context. To minimize that
// impact, this interceptor should always be last.
func NoCancelInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); ok {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	} else {
		ctx = context.Background()
	}
	defer cancel()
	return handler(ctx, req)
}

// serverInterceptor is a gRPC interceptor that adds Prometheus
// metrics to requests handled by a gRPC server, and wraps Boulder-specific
// errors for transmission in a grpc/metadata trailer (see bcodes.go).
type serverInterceptor struct {
	metrics serverMetrics
	clk     clock.Clock
}

func newServerInterceptor(metrics serverMetrics, clk clock.Clock) serverInterceptor {
	return serverInterceptor{
		metrics: metrics,
		clk:     clk,
	}
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		return nil, berrors.InternalServerError("passed nil *grpc.UnaryServerInfo")
	}

	// Extract the grpc metadata from the context. If the context has
	// a `clientRequestTimeKey` field, and it has a value, then observe the RPC
	// latency with Prometheus.
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md[clientRequestTimeKey]) > 0 {
		err := si.observeLatency(md[clientRequestTimeKey][0])
		if err != nil {
			return nil, err
		}
	}

	// Shave 20 milliseconds off the deadline to ensure that if the RPC server times
	// out any sub-calls it makes (like DNS lookups, or onwards RPCs), it has a
	// chance to report that timeout to the client. This allows for more specific
	// errors, e.g "the VA timed out looking up CAA for example.com" (when called
	// from RA.NewCertificate, which was called from WFE.NewCertificate), as
	// opposed to "RA.NewCertificate timed out" (causing a 500).
	// Once we've shaved the deadline, we ensure we have we have at least another
	// 100ms left to do work; otherwise we abort early.
	deadline, ok := ctx.Deadline()
	// Should never happen: there was no deadline.
	if !ok {
		deadline = time.Now().Add(100 * time.Second)
	}
	deadline = deadline.Add(-returnOverhead)
	remaining := time.Until(deadline)
	if remaining < meaningfulWorkOverhead {
		return nil, status.Errorf(codes.DeadlineExceeded, "not enough time left on clock: %s", remaining)
	}
	var cancel func()
	ctx, cancel = context.WithDeadline(ctx, deadline)
	defer cancel()

	resp, err := handler(ctx, req)
	if err != nil {
		err = wrapError(ctx, err)
	}
	return resp, err
}

// splitMethodName is borrowed directly from
// `grpc-ecosystem/go-grpc-prometheus/util.go` and is used to extract the
// service and method name from the `method` argument to
// a `UnaryClientInterceptor`.
func splitMethodName(fullMethodName string) (string, string) {
	fullMethodName = strings.TrimPrefix(fullMethodName, "/") // remove leading slash
	if i := strings.Index(fullMethodName, "/"); i >= 0 {
		return fullMethodName[:i], fullMethodName[i+1:]
	}
	return "unknown", "unknown"
}

// observeLatency is called with the `clientRequestTimeKey` value from
// a request's gRPC metadata. This string value is converted to a timestamp and
// used to calculate the latency between send and receive time. The latency is
// published to the server interceptor's rpcLag prometheus histogram. An error
// is returned if the `clientReqTime` string is not a valid timestamp.
func (si *serverInterceptor) observeLatency(clientReqTime string) error {
	// Convert the metadata request time into an int64
	reqTimeUnixNanos, err := strconv.ParseInt(clientReqTime, 10, 64)
	if err != nil {
		return berrors.InternalServerError("grpc metadata had illegal %s value: %q - %s",
			clientRequestTimeKey, clientReqTime, err)
	}
	// Calculate the elapsed time since the client sent the RPC
	reqTime := time.Unix(0, reqTimeUnixNanos)
	elapsed := si.clk.Since(reqTime)
	// Publish an RPC latency observation to the histogram
	si.metrics.rpcLag.Observe(elapsed.Seconds())
	return nil
}

// clientInterceptor is a gRPC interceptor that adds Prometheus
// metrics to sent requests, and disables FailFast. We disable FailFast because
// non-FailFast mode is most similar to the old AMQP RPC layer: If a client
// makes a request while all backends are briefly down (e.g. for a restart), the
// request doesn't necessarily fail. A backend can service the request if it
// comes back up within the timeout. Under gRPC the same effect is achieved by
// retries up to the Context deadline.
type clientInterceptor struct {
	timeout time.Duration
	metrics clientMetrics
	clk     clock.Clock
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*.
func (ci *clientInterceptor) intercept(
	ctx context.Context,
	fullMethod string,
	req,
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption) error {
	// This should not occur but fail fast with a clear error if it does (e.g.
	// because of buggy unit test code) instead of a generic nil panic later!
	if ci.metrics.inFlightRPCs == nil {
		return berrors.InternalServerError("clientInterceptor has nil inFlightRPCs gauge")
	}

	localCtx, cancel := context.WithTimeout(ctx, ci.timeout)
	defer cancel()
	// Disable fail-fast so RPCs will retry until deadline, even if all backends
	// are down.
	opts = append(opts, grpc.WaitForReady(true))

	// Convert the current unix nano timestamp to a string for embedding in the grpc metadata
	nowTS := strconv.FormatInt(ci.clk.Now().UnixNano(), 10)

	// Create a grpc/metadata.Metadata instance for the request metadata.
	// Initialize it with the request time.
	reqMD := metadata.New(map[string]string{clientRequestTimeKey: nowTS})
	// Configure the localCtx with the metadata so it gets sent along in the request
	localCtx = metadata.NewOutgoingContext(localCtx, reqMD)

	// Create a grpc/metadata.Metadata instance for a grpc.Trailer.
	respMD := metadata.New(nil)
	// Configure a grpc Trailer with respMD. This allows us to wrap error
	// types in the server interceptor later on.
	opts = append(opts, grpc.Trailer(&respMD))

	// Split the method and service name from the fullMethod.
	// UnaryClientInterceptor's receive a `method` arg of the form
	// "/ServiceName/MethodName"
	service, method := splitMethodName(fullMethod)
	// Slice the inFlightRPC inc/dec calls by method and service
	labels := prometheus.Labels{
		"method":  method,
		"service": service,
	}

	// Increment the inFlightRPCs gauge for this method/service
	ci.metrics.inFlightRPCs.With(labels).Inc()
	// And defer decrementing it when we're done
	defer ci.metrics.inFlightRPCs.With(labels).Dec()
	// Handle the RPC
	begin := ci.clk.Now()
	err := invoker(localCtx, fullMethod, req, reply, cc, opts...)
	if err != nil {
		err = unwrapError(err, respMD)
		if status.Code(err) == codes.DeadlineExceeded {
			return deadlineDetails{
				service: service,
				method:  method,
				latency: ci.clk.Since(begin),
			}
		}
	}
	return err
}

// CancelTo408Interceptor calls the underlying invoker, checks to see if the
// resulting error was a gRPC Canceled error (because this client cancelled
// the request, likely because the ACME client itself canceled the HTTP
// request), and converts that into a Problem which can be "returned" to the
// (now missing) client, and into our logs. This should be the outermost client
// interceptor, and should only be enabled in the WFEs.
func CancelTo408Interceptor(ctx context.Context, fullMethod string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	err := invoker(ctx, fullMethod, req, reply, cc, opts...)
	if err != nil && status.Code(err) == codes.Canceled {
		return probs.Canceled(err.Error())
	}
	return err
}

// deadlineDetails is an error type that we use in place of gRPC's
// DeadlineExceeded errors in order to add more detail for debugging.
type deadlineDetails struct {
	service string
	method  string
	latency time.Duration
}

func (dd deadlineDetails) Error() string {
	return fmt.Sprintf("%s.%s timed out after %d ms",
		dd.service, dd.method, int64(dd.latency/time.Millisecond))
}
