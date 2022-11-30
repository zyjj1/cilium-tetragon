// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package containerd

import (
	"fmt"

	containerdconf "github.com/containerd/containerd/services/server/config"
	"github.com/pelletier/go-toml"

	"github.com/spf13/cobra"
)

type conf struct {
	dryRun         bool
	containerdConf string
}

func defaultConf() conf {
	return conf{
		containerdConf: "/etc/containerd/config.toml",
	}
}

func NewCommand() *cobra.Command {
	conf := defaultConf()
	cmd := &cobra.Command{
		Use:   "containerd",
		Short: "Configure containerd",
		RunE: func(cmd *cobra.Command, args []string) error {
			return addHook(&conf)
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	// flags.BoolVar(&conf.dryRun, "dry-run", conf.dryRun, "do a trial run with no changes made")
	flags.StringVar(&conf.containerdConf, "config-file", conf.containerdConf, "containerd configuration file")
	return cmd
}

func addHook(cnf *conf) error {
	cdConf := containerdconf.Config{}
	file, err := toml.LoadFile(cnf.containerdConf)
	if err != nil {
		return err
	}

	if err := file.Unmarshal(&cdConf); err != nil {
		return err
	}

	/*
		f, err := os.CreateTemp("", "containerd-config.*.toml")
		if err != nil {
			return err
		}
	*/

	bytes, err := toml.Marshal(&cdConf)
	if err != nil {
		return err
	}

	fmt.Println(string(bytes))

	return nil
}
