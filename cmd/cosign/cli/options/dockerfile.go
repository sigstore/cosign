package options

import (
	"github.com/spf13/cobra"
)

// ResolveDockerfileOptions is the top level wrapper for the `verify blob` command.
type ResolveDockerfileOptions struct {
	Output string
}

var _ Interface = (*ResolveDockerfileOptions)(nil)

// AddFlags implements Interface
func (o *ResolveDockerfileOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Output, "output", "",
		"output an updated Dockerfile to file")
}