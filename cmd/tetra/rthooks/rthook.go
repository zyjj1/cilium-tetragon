package rthooks

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/spf13/cobra"
)

type addContainerConf struct {
	podID       string
	containerID string
	rootDir     string
	annotations map[string]string
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "rthooks",
		Short:        "trigger runtime hooks (for testing/debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	cnf := addContainerConf{}
	add := &cobra.Command{
		Use:   "create-container <containerID> <rootDir>",
		Short: "trigger create-container hook",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				createContainer(ctx, cli, &cnf)
			})
		},
	}

	flags := add.Flags()
	flags.StringVar(&cnf.podID, "pod-id", "", "pod uuid")
	flags.StringVar(&cnf.containerID, "container-id", "", "container id")
	flags.StringVar(&cnf.rootDir, "root-dir", "", "container root directory")
	flags.StringToStringVar(&cnf.annotations, "annotations", map[string]string{}, "container annotations")

	ret.AddCommand(add)
	return ret
}

func createContainer(ctx context.Context, client tetragon.FineGuidanceSensorsClient, cnf *addContainerConf) {
	// _, err := client.EnableSensor(ctx, &tetragon.EnableSensorRequest{Name: sensor})

	req := &tetragon.RuntimeHookRequest{
		Event: &tetragon.RuntimeHookRequest_CreateContainer{
			CreateContainer: &tetragon.CreateContainer{
				PodID:       cnf.podID,
				ContainerID: cnf.containerID,
				RootDir:     cnf.rootDir,
				Annotations: cnf.annotations,
			},
		},
	}

	_, err := client.RuntimeHook(ctx, req)
	if err != nil {
		fmt.Printf("triggering create-container hook failed: %s", err)
	}
}
