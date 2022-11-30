// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"fmt"
	"os"

	"github.com/kkourt/tetragon-rtconf/containerd"
	"github.com/spf13/cobra"
)

var (
	DefaultTetragonHookFilename = "/opt/tetragon/oci-hook"
	TetragonHookFilename        = DefaultTetragonHookFilename
)

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "tetragon-rtconf",
		Short: "Tetragon's little helper for configuring OCI hooks",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		SilenceUsage: true,
	}
	rootCmd.AddCommand(
		containerd.NewCommand(),
	)

	pflags := rootCmd.PersistentFlags()
	pflags.StringVar(&TetragonHookFilename, "tetragon-oci-hook", TetragonHookFilename, "pathname of hook executable")

	return rootCmd
}

func main() {
	rootCmd := newRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
