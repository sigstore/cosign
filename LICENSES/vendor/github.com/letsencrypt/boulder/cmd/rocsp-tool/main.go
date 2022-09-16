package notmain

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/ocsp/helper"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type Config struct {
	ROCSPTool struct {
		DebugAddr string
		Redis     rocsp_config.RedisConfig

		// If using load-from-db, this provides credentials to connect to the DB
		// and the CA. Otherwise, it's optional.
		LoadFromDB *LoadFromDBConfig
	}
	Syslog cmd.SyslogConfig
}

// LoadFromDBConfig provides the credentials and configuration needed to load
// data from the certificateStatuses table in the DB and get it signed.
type LoadFromDBConfig struct {
	// Credentials to connect to the DB.
	DB cmd.DBConfig
	// Credentials to request OCSP signatures from the CA.
	GRPCTLS cmd.TLSConfig
	// Timeouts and hostnames for the CA.
	OCSPGeneratorService cmd.GRPCClientConfig
	// How fast to process rows.
	Speed ProcessingSpeed
}

type ProcessingSpeed struct {
	// If using load-from-db, this limits how many items per second we
	// scan from the DB. We might go slower than this depending on how fast
	// we read rows from the DB, but we won't go faster. Defaults to 2000.
	RowsPerSecond int
	// If using load-from-db, this controls how many parallel requests to
	// boulder-ca for OCSP signing we can make. Defaults to 100.
	ParallelSigns int
	// If using load-from-db, the LIMIT on our scanning queries. We have to
	// apply a limit because MariaDB will cut off our response at some
	// threshold of total bytes transferred (1 GB by default). Defaults to 10000.
	ScanBatchSize int
}

func init() {
	cmd.RegisterCommand("rocsp-tool", main)
}

func main() {
	err := main2()
	if err != nil {
		cmd.FailOnError(err, "")
	}
}

func main2() error {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	startFromID := flag.Int64("start-from-id", 0, "For load-from-db, the first ID in the certificateStatus table to scan")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}
	rand.Seed(time.Now().UnixNano())

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	if err != nil {
		return fmt.Errorf("reading JSON config file: %w", err)
	}

	_, logger := cmd.StatsAndLogging(c.Syslog, c.ROCSPTool.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()
	redisClient, err := rocsp_config.MakeClient(&c.ROCSPTool.Redis, clk, metrics.NoopRegisterer)
	if err != nil {
		return fmt.Errorf("making client: %w", err)
	}

	var db *db.WrappedMap
	var ocspGenerator capb.OCSPGeneratorClient
	var scanBatchSize int
	if c.ROCSPTool.LoadFromDB != nil {
		lfd := c.ROCSPTool.LoadFromDB
		db, err = sa.InitWrappedDb(lfd.DB, nil, logger)
		if err != nil {
			return fmt.Errorf("connecting to DB: %w", err)
		}

		ocspGenerator, err = configureOCSPGenerator(lfd.GRPCTLS,
			lfd.OCSPGeneratorService, clk, metrics.NoopRegisterer)
		if err != nil {
			return fmt.Errorf("configuring gRPC to CA: %w", err)
		}
		setDefault(&lfd.Speed.RowsPerSecond, 2000)
		setDefault(&lfd.Speed.ParallelSigns, 100)
		setDefault(&lfd.Speed.ScanBatchSize, 10000)
		scanBatchSize = lfd.Speed.ScanBatchSize
	}

	if len(flag.Args()) < 1 {
		helpExit()
	}

	ctx := context.Background()
	cl := client{
		redis:         redisClient,
		db:            db,
		ocspGenerator: ocspGenerator,
		clk:           clk,
		scanBatchSize: scanBatchSize,
		logger:        logger,
	}
	switch flag.Arg(0) {
	case "get":
		for _, serial := range flag.Args()[1:] {
			resp, err := cl.redis.GetResponse(ctx, serial)
			if err != nil {
				return err
			}
			parsed, err := ocsp.ParseResponse(resp, nil)
			if err != nil {
				logger.Infof("parsing error on %x: %s", resp, err)
				continue
			} else {
				logger.Infof("%s", helper.PrettyResponse(parsed))
			}
		}
	case "store":
		err := cl.storeResponsesFromFiles(ctx, flag.Args()[1:])
		if err != nil {
			return err
		}
	case "load-from-db":
		if c.ROCSPTool.LoadFromDB == nil {
			return fmt.Errorf("config field LoadFromDB was missing")
		}
		err = cl.loadFromDB(ctx, c.ROCSPTool.LoadFromDB.Speed, *startFromID)
		if err != nil {
			return fmt.Errorf("loading OCSP responses from DB: %w", err)
		}
	case "scan-responses":
		results := cl.redis.ScanResponses(ctx, "*")
		for r := range results {
			if r.Err != nil {
				cmd.FailOnError(err, "while scanning")
			}
			logger.Infof("%s: %s\n", r.Serial, base64.StdEncoding.EncodeToString(r.Body))
		}
	default:
		logger.Errf("unrecognized subcommand %q\n", flag.Arg(0))
		helpExit()
	}
	return nil
}

func helpExit() {
	fmt.Fprintf(os.Stderr, "Usage: %s [store|copy-from-db|scan-metadata|scan-responses] --config path/to/config.json\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  store -- for each filename on command line, read the file as an OCSP response and store it in Redis")
	fmt.Fprintln(os.Stderr, "  get -- for each serial on command line, fetch that serial's response and pretty-print it")
	fmt.Fprintln(os.Stderr, "  load-from-db -- scan the database for all OCSP entries for unexpired certificates, and store in Redis")
	fmt.Fprintln(os.Stderr, "  scan-metadata -- scan Redis for metadata entries. For each entry, print the serial and the age in hours")
	fmt.Fprintln(os.Stderr, "  scan-responses -- scan Redis for OCSP response entries. For each entry, print the serial and base64-encoded response")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	os.Exit(1)
}

func configureOCSPGenerator(tlsConf cmd.TLSConfig, grpcConf cmd.GRPCClientConfig, clk clock.Clock, stats prometheus.Registerer) (capb.OCSPGeneratorClient, error) {
	tlsConfig, err := tlsConf.Load()
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}
	clientMetrics := bgrpc.NewClientMetrics(stats)
	caConn, err := bgrpc.ClientSetup(&grpcConf, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	return capb.NewOCSPGeneratorClient(caConn), nil
}

// setDefault sets the target to a default value, if it is zero.
func setDefault(target *int, def int) {
	if *target == 0 {
		*target = def
	}
}
