package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/honeycombio/beeline-go"
	"github.com/letsencrypt/boulder/core"
)

// PasswordConfig contains a path to a file containing a password.
type PasswordConfig struct {
	PasswordFile string
}

// Pass returns a password, extracted from the PasswordConfig's PasswordFile
func (pc *PasswordConfig) Pass() (string, error) {
	// Make PasswordConfigs optional, for backwards compatibility.
	if pc.PasswordFile == "" {
		return "", nil
	}
	contents, err := ioutil.ReadFile(pc.PasswordFile)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(contents), "\n"), nil
}

// ServiceConfig contains config items that are common to all our services, to
// be embedded in other config structs.
type ServiceConfig struct {
	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
	GRPC      *GRPCServerConfig
	TLS       TLSConfig
}

// DBConfig defines how to connect to a database. The connect string may be
// stored in a file separate from the config, because it can contain a password,
// which we want to keep out of configs.
type DBConfig struct {
	DBConnect string
	// A file containing a connect URL for the DB.
	DBConnectFile string

	// MaxOpenConns sets the maximum number of open connections to the
	// database. If MaxIdleConns is greater than 0 and MaxOpenConns is
	// less than MaxIdleConns, then MaxIdleConns will be reduced to
	// match the new MaxOpenConns limit. If n < 0, then there is no
	// limit on the number of open connections.
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of connections in the idle
	// connection pool. If MaxOpenConns is greater than 0 but less than
	// MaxIdleConns, then MaxIdleConns will be reduced to match the
	// MaxOpenConns limit. If n < 0, no idle connections are retained.
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may
	// be reused. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's age.
	ConnMaxLifetime ConfigDuration

	// ConnMaxIdleTime sets the maximum amount of time a connection may
	// be idle. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's idle
	// time.
	ConnMaxIdleTime ConfigDuration
}

// URL returns the DBConnect URL represented by this DBConfig object, either
// loading it from disk or returning a default value. Leading and trailing
// whitespace is stripped.
func (d *DBConfig) URL() (string, error) {
	if d.DBConnectFile != "" {
		url, err := ioutil.ReadFile(d.DBConnectFile)
		return strings.TrimSpace(string(url)), err
	}
	return d.DBConnect, nil
}

// DSNAddressAndUser returns the Address and User of the DBConnect DSN from
// this object.
func (d *DBConfig) DSNAddressAndUser() (string, string, error) {
	dsnStr, err := d.URL()
	if err != nil {
		return "", "", fmt.Errorf("failed to load DBConnect URL: %s", err)
	}
	config, err := mysql.ParseDSN(dsnStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse DSN from the DBConnect URL: %s", err)
	}
	return config.Addr, config.User, nil
}

type SMTPConfig struct {
	PasswordConfig
	Server   string
	Port     string
	Username string
}

// PAConfig specifies how a policy authority should connect to its
// database, what policies it should enforce, and what challenges
// it should offer.
type PAConfig struct {
	DBConfig
	Challenges map[core.AcmeChallenge]bool
}

// CheckChallenges checks whether the list of challenges in the PA config
// actually contains valid challenge names
func (pc PAConfig) CheckChallenges() error {
	if len(pc.Challenges) == 0 {
		return errors.New("empty challenges map in the Policy Authority config is not allowed")
	}
	for c := range pc.Challenges {
		if !c.IsValid() {
			return fmt.Errorf("Invalid challenge in PA config: %s", c)
		}
	}
	return nil
}

// HostnamePolicyConfig specifies a file from which to load a policy regarding
// what hostnames to issue for.
type HostnamePolicyConfig struct {
	HostnamePolicyFile string
}

// TLSConfig represents certificates and a key for authenticated TLS.
type TLSConfig struct {
	CertFile   *string
	KeyFile    *string
	CACertFile *string
}

// Load reads and parses the certificates and key listed in the TLSConfig, and
// returns a *tls.Config suitable for either client or server use.
func (t *TLSConfig) Load() (*tls.Config, error) {
	if t == nil {
		return nil, fmt.Errorf("nil TLS section in config")
	}
	if t.CertFile == nil {
		return nil, fmt.Errorf("nil CertFile in TLSConfig")
	}
	if t.KeyFile == nil {
		return nil, fmt.Errorf("nil KeyFile in TLSConfig")
	}
	if t.CACertFile == nil {
		return nil, fmt.Errorf("nil CACertFile in TLSConfig")
	}
	caCertBytes, err := ioutil.ReadFile(*t.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert from %q: %s", *t.CACertFile, err)
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caCertBytes); !ok {
		return nil, fmt.Errorf("parsing CA certs from %s failed", *t.CACertFile)
	}
	cert, err := tls.LoadX509KeyPair(*t.CertFile, *t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading key pair from %q and %q: %s",
			*t.CertFile, *t.KeyFile, err)
	}
	return &tls.Config{
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		// Set the only acceptable TLS version to 1.2 and the only acceptable cipher suite
		// to ECDHE-RSA-CHACHA20-POLY1305.
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
	}, nil
}

// SyslogConfig defines the config for syslogging.
type SyslogConfig struct {
	StdoutLevel int
	SyslogLevel int
}

// ConfigDuration is just an alias for time.Duration that allows
// serialization to YAML as well as JSON.
type ConfigDuration struct {
	time.Duration
}

// ErrDurationMustBeString is returned when a non-string value is
// presented to be deserialized as a ConfigDuration
var ErrDurationMustBeString = errors.New("cannot JSON unmarshal something other than a string into a ConfigDuration")

// UnmarshalJSON parses a string into a ConfigDuration using
// time.ParseDuration.  If the input does not unmarshal as a
// string, then UnmarshalJSON returns ErrDurationMustBeString.
func (d *ConfigDuration) UnmarshalJSON(b []byte) error {
	s := ""
	err := json.Unmarshal(b, &s)
	if err != nil {
		var jsonUnmarshalTypeErr *json.UnmarshalTypeError
		if errors.As(err, &jsonUnmarshalTypeErr) {
			return ErrDurationMustBeString
		}
		return err
	}
	dd, err := time.ParseDuration(s)
	d.Duration = dd
	return err
}

// MarshalJSON returns the string form of the duration, as a byte array.
func (d ConfigDuration) MarshalJSON() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// UnmarshalYAML uses the same format as JSON, but is called by the YAML
// parser (vs. the JSON parser).
func (d *ConfigDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	d.Duration = dur
	return nil
}

// GRPCClientConfig contains the information needed to talk to the gRPC service
type GRPCClientConfig struct {
	ServerAddress string
	Timeout       ConfigDuration
}

// GRPCServerConfig contains the information needed to run a gRPC service
type GRPCServerConfig struct {
	Address string `json:"address"`
	// ClientNames is a list of allowed client certificate subject alternate names
	// (SANs). The server will reject clients that do not present a certificate
	// with a SAN present on the `ClientNames` list.
	ClientNames []string `json:"clientNames"`
	// MaxConnectionAge specifies how long a connection may live before the server sends a GoAway to the
	// client. Because gRPC connections re-resolve DNS after a connection close,
	// this controls how long it takes before a client learns about changes to its
	// backends.
	// https://pkg.go.dev/google.golang.org/grpc/keepalive#ServerParameters
	MaxConnectionAge ConfigDuration
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// BeelineConfig provides config options for the Honeycomb beeline-go library,
// which are passed to its beeline.Init() method.
type BeelineConfig struct {
	// WriteKey is the API key needed to send data Honeycomb. This can be given
	// directly in the JSON config for local development, or as a path to a
	// separate file for production deployment.
	WriteKey PasswordConfig
	// Dataset is the event collection, e.g. Staging or Prod.
	Dataset string
	// SampleRate is the (positive integer) denominator of the sample rate.
	// Default: 1 (meaning all traces are sent). Set higher to send fewer traces.
	SampleRate uint32
	// Mute disables honeycomb entirely; useful in test environments.
	Mute bool
	// Many other fields of beeline.Config are omitted as they are not yet used.
}

// makeSampler constructs a SamplerHook which will deterministically decide if
// any given span should be sampled based on its TraceID, which is shared by all
// spans within a trace. If a trace_id can't be found, the span will be sampled.
// A sample rate of 0 defaults to a sample rate of 1 (i.e. all events are sent).
func makeSampler(rate uint32) func(fields map[string]interface{}) (bool, int) {
	if rate == 0 {
		rate = 1
	}
	upperBound := math.MaxUint32 / rate

	return func(fields map[string]interface{}) (bool, int) {
		id, ok := fields["trace.trace_id"].(string)
		if !ok {
			return true, 1
		}
		h := fnv.New32()
		h.Write([]byte(id))
		return h.Sum32() < upperBound, int(rate)
	}
}

// Load converts a BeelineConfig to a beeline.Config, loading the api WriteKey
// and setting the ServiceName automatically.
func (bc *BeelineConfig) Load() (beeline.Config, error) {
	exec, err := os.Executable()
	if err != nil {
		return beeline.Config{}, fmt.Errorf("failed to get executable name: %w", err)
	}

	writekey, err := bc.WriteKey.Pass()
	if err != nil {
		return beeline.Config{}, fmt.Errorf("failed to get write key: %w", err)
	}

	return beeline.Config{
		WriteKey:    writekey,
		Dataset:     bc.Dataset,
		ServiceName: path.Base(exec),
		SamplerHook: makeSampler(bc.SampleRate),
		Mute:        bc.Mute,
	}, nil
}
