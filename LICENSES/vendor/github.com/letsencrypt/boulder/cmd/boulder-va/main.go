package notmain

import (
	"flag"
	"os"
	"time"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/honeycombio/beeline-go"
	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/va"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

type Config struct {
	VA struct {
		cmd.ServiceConfig

		UserAgent string

		IssuerDomain string

		PortConfig cmd.PortConfig

		// CAADistributedResolverConfig specifies the HTTP client setup and interfaces
		// needed to resolve CAA addresses over multiple paths
		CAADistributedResolver struct {
			Timeout     cmd.ConfigDuration
			MaxFailures int
			Proxies     []string
		}

		// The number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries    int
		DNSResolver string
		// Deprecated, replaced by singular DNSResolver above.
		DNSResolvers              []string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool

		RemoteVAs                   []cmd.GRPCClientConfig
		MaxRemoteValidationFailures int

		Features map[string]bool

		AccountURIPrefixes []string
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig

	Common struct {
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.VA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	if *grpcAddr != "" {
		c.VA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.VA.DebugAddr = *debugAddr
	}

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.VA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	pc := &cmd.PortConfig{
		HTTPPort:  80,
		HTTPSPort: 443,
		TLSPort:   443,
	}
	if c.VA.PortConfig.HTTPPort != 0 {
		pc.HTTPPort = c.VA.PortConfig.HTTPPort
	}
	if c.VA.PortConfig.HTTPSPort != 0 {
		pc.HTTPSPort = c.VA.PortConfig.HTTPSPort
	}
	if c.VA.PortConfig.TLSPort != 0 {
		pc.TLSPort = c.VA.PortConfig.TLSPort
	}

	var dnsTimeout time.Duration
	if c.VA.DNSTimeout != "" {
		dnsTimeout, err = time.ParseDuration(c.VA.DNSTimeout)
	} else {
		dnsTimeout, err = time.ParseDuration(c.Common.DNSTimeout)
	}
	cmd.FailOnError(err, "Couldn't parse DNS timeout")
	dnsTries := c.VA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	clk := cmd.Clock()

	var servers bdns.ServerProvider
	if c.VA.DNSResolver != "" {
		servers, err = bdns.StartDynamicProvider(c.VA.DNSResolver, 60*time.Second)
		cmd.FailOnError(err, "Couldn't start dynamic DNS server resolver")
	} else {
		servers, err = bdns.NewStaticProvider(c.VA.DNSResolvers)
		cmd.FailOnError(err, "Couldn't parse static DNS server(s)")
	}

	var resolver bdns.Client
	if !(c.VA.DNSAllowLoopbackAddresses || c.Common.DNSAllowLoopbackAddresses) {
		resolver = bdns.New(
			dnsTimeout,
			servers,
			scope,
			clk,
			dnsTries,
			logger)
	} else {
		resolver = bdns.NewTest(
			dnsTimeout,
			servers,
			scope,
			clk,
			dnsTries,
			logger)
	}

	tlsConfig, err := c.VA.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")

	clientMetrics := bgrpc.NewClientMetrics(scope)
	var remotes []va.RemoteVA
	if len(c.VA.RemoteVAs) > 0 {
		for _, rva := range c.VA.RemoteVAs {
			rva := rva
			vaConn, err := bgrpc.ClientSetup(&rva, tlsConfig, clientMetrics, clk)
			cmd.FailOnError(err, "Unable to create remote VA client")
			remotes = append(
				remotes,
				va.RemoteVA{
					VAClient: vapb.NewVAClient(vaConn),
					Address:  rva.ServerAddress,
				},
			)
		}
	}

	vai, err := va.NewValidationAuthorityImpl(
		pc,
		resolver,
		remotes,
		c.VA.MaxRemoteValidationFailures,
		c.VA.UserAgent,
		c.VA.IssuerDomain,
		scope,
		clk,
		logger,
		c.VA.AccountURIPrefixes)
	cmd.FailOnError(err, "Unable to create VA server")

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.VA.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup VA gRPC server")
	vapb.RegisterVAServer(grpcSrv, vai)
	cmd.FailOnError(err, "Unable to register VA gRPC server")
	vapb.RegisterCAAServer(grpcSrv, vai)
	cmd.FailOnError(err, "Unable to register CAA gRPC server")
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		servers.Stop()
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "VA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-va", main)
	// We register under two different names, because it's convenient for the
	// remote VAs to show up under a different program name when looking at logs.
	cmd.RegisterCommand("boulder-remoteva", main)
}
