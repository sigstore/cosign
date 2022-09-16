package probers

import (
	"errors"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v3"
)

type MockConfigurer struct {
	Valid    bool               `yaml:"valid"`
	ErrMsg   string             `yaml:"errmsg"`
	PName    string             `yaml:"pname"`
	PKind    string             `yaml:"pkind"`
	PTook    cmd.ConfigDuration `yaml:"ptook"`
	PSuccess bool               `yaml:"psuccess"`
}

func (c MockConfigurer) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf MockConfigurer
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (c MockConfigurer) MakeProber() (probers.Prober, error) {
	if !c.Valid {
		return nil, errors.New("could not be validated")
	}
	return MockProber{c.PName, c.PKind, c.PTook, c.PSuccess}, nil
}

func init() {
	probers.Register("MockConf", MockConfigurer{})
}
