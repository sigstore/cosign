package probers

import (
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

var (
	// Registry is the global mapping of all `Configurer` types. Types
	// are added to this mapping on import by including a call to
	// `Register` in their `init` function.
	Registry = make(map[string]Configurer)
)

// Prober is the interface for `Prober` types.
type Prober interface {
	// Name returns a name that uniquely identifies the monitor that
	// configured this `Prober`.
	Name() string

	// Kind returns a name that uniquely identifies the `Kind` of
	// `Prober`.
	Kind() string

	// Probe attempts the configured request or query, Each `Prober`
	// must treat the duration passed to it as a timeout.
	Probe(time.Duration) (bool, time.Duration)
}

// Configurer is the interface for `Configurer` types.
type Configurer interface {
	// UnmarshalSettings unmarshals YAML as bytes to a `Configurer`
	// object.
	UnmarshalSettings([]byte) (Configurer, error)

	// MakeProber constructs a `Prober` object from the contents of the
	// bound `Configurer` object. If the `Configurer` cannot be
	// validated, an error appropriate for end-user consumption is
	// returned instead.
	MakeProber() (Prober, error)
}

// Settings is exported as a temporary receiver for the `settings` field
// of `MonConf`. `Settings` is always marshaled back to bytes and then
// unmarshalled into the `Configurer` specified by the `Kind` field of
// the `MonConf`.
type Settings map[string]interface{}

// GetConfigurer returns the probe configurer specified by name from
// `Registry`.
func GetConfigurer(kind string) (Configurer, error) {
	// normalize
	name := strings.Trim(strings.ToLower(kind), " ")
	// check if exists
	if _, ok := Registry[name]; ok {
		return Registry[name], nil
	}
	return nil, fmt.Errorf("%s is not a registered Prober type", kind)
}

// Register is called by the `init` function of every `Configurer` to
// add the caller to the global `Registry` map. If the caller attempts
// to add a `Configurer` to the registry using the same name as a prior
// `Configurer` Observer will exit after logging an error.
func Register(kind string, c Configurer) {
	// normalize
	name := strings.Trim(strings.ToLower(kind), " ")
	// check for name collision
	if _, exists := Registry[name]; exists {
		cmd.Fail(fmt.Sprintf(
			"problem registering configurer %s: name collision", kind))
	}
	Registry[name] = c
}
