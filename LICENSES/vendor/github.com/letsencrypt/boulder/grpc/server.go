package grpc

import (
	"crypto/tls"
	"errors"
	"net"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/honeycombio/beeline-go/wrappers/hnygrpc"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// CodedError is a alias required to appease go vet
var CodedError = status.Errorf

var errNilTLS = errors.New("boulder/grpc: received nil tls.Config")

// NewServer creates a gRPC server that uses the provided *tls.Config, and
// verifies that clients present a certificate that (a) is signed by one of
// the configured ClientCAs, and (b) contains at least one
// subjectAlternativeName matching the accepted list from GRPCServerConfig.
func NewServer(c *cmd.GRPCServerConfig, tlsConfig *tls.Config, metrics serverMetrics, clk clock.Clock, interceptors ...grpc.UnaryServerInterceptor) (*grpc.Server, net.Listener, error) {
	if tlsConfig == nil {
		return nil, nil, errNilTLS
	}
	acceptedSANs := make(map[string]struct{})
	for _, name := range c.ClientNames {
		acceptedSANs[name] = struct{}{}
	}

	creds, err := bcreds.NewServerCredentials(tlsConfig, acceptedSANs)
	if err != nil {
		return nil, nil, err
	}

	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}

	si := newServerInterceptor(metrics, clk)
	allInterceptors := []grpc.UnaryServerInterceptor{
		si.intercept,
		si.metrics.grpcMetrics.UnaryServerInterceptor(),
		hnygrpc.UnaryServerInterceptor(),
	}
	allInterceptors = append(allInterceptors, interceptors...)
	options := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(allInterceptors...),
	}
	if c.MaxConnectionAge.Duration > 0 {
		options = append(options,
			grpc.KeepaliveParams(keepalive.ServerParameters{
				MaxConnectionAge: c.MaxConnectionAge.Duration,
			}))
	}
	return grpc.NewServer(options...), l, nil
}

// serverMetrics is a struct type used to return a few registered metrics from
// `NewServerMetrics`
type serverMetrics struct {
	grpcMetrics *grpc_prometheus.ServerMetrics
	rpcLag      prometheus.Histogram
}

// NewServerMetrics registers metrics with a registry. It must be called a
// maximum of once per registry, or there will be conflicting names.
// It constructs and registers a *grpc_prometheus.ServerMetrics with timing
// histogram enabled as well as a prometheus Histogram for RPC latency.
func NewServerMetrics(stats registry) serverMetrics {
	// Create the grpc prometheus server metrics instance and register it
	grpcMetrics := grpc_prometheus.NewServerMetrics()
	grpcMetrics.EnableHandlingTimeHistogram()
	stats.MustRegister(grpcMetrics)

	// rpcLag is a prometheus histogram tracking the difference between the time
	// the client sent an RPC and the time the server received it. Create and
	// register it.
	rpcLag := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "grpc_lag",
			Help: "Delta between client RPC send time and server RPC receipt time",
		})
	stats.MustRegister(rpcLag)

	return serverMetrics{
		grpcMetrics: grpcMetrics,
		rpcLag:      rpcLag,
	}
}
