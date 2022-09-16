package notmain

import (
	"flag"
	"os"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/honeycombio/beeline-go"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type Config struct {
	SA struct {
		cmd.ServiceConfig
		DB         cmd.DBConfig
		ReadOnlyDB cmd.DBConfig
		Redis      *rocsp_config.RedisConfig
		Issuers    map[string]int

		Features map[string]bool

		// Max simultaneous SQL queries caused by a single RPC.
		ParallelismPerRPC int
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
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

	err = features.Set(c.SA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	if *grpcAddr != "" {
		c.SA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.SA.DebugAddr = *debugAddr
	}

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.SA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	dbMap, err := sa.InitWrappedDb(c.SA.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	dbReadOnlyURL, err := c.SA.ReadOnlyDB.URL()
	cmd.FailOnError(err, "Couldn't load read-only DB URL")

	var dbReadOnlyMap *db.WrappedMap
	if dbReadOnlyURL == "" {
		dbReadOnlyMap = dbMap
	} else {
		dbReadOnlyMap, err = sa.InitWrappedDb(c.SA.ReadOnlyDB, scope, logger)
		cmd.FailOnError(err, "While initializing dbMap")
	}

	clk := cmd.Clock()

	shortIssuers, err := rocsp_config.LoadIssuers(c.SA.Issuers)
	cmd.FailOnError(err, "loading issuers")

	parallel := c.SA.ParallelismPerRPC
	if parallel < 1 {
		parallel = 1
	}
	sai, err := sa.NewSQLStorageAuthority(dbMap, dbReadOnlyMap, shortIssuers, clk, logger, scope, parallel)
	cmd.FailOnError(err, "Failed to create SA impl")

	tls, err := c.SA.TLS.Load()
	cmd.FailOnError(err, "TLS config")
	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, listener, err := bgrpc.NewServer(c.SA.GRPC, tls, serverMetrics, clk, bgrpc.NoCancelInterceptor)
	cmd.FailOnError(err, "Unable to setup SA gRPC server")
	sapb.RegisterStorageAuthorityServer(grpcSrv, sai)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
	cmd.FailOnError(err, "SA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-sa", main)
}
