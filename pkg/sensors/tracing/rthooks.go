// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/rthooks"

	corev1 "k8s.io/api/core/v1"
)

func init() {
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: createContainerHook,
	})
}

func createContainerHook(ctx context.Context, arg *rthooks.CreateContainerArg) error {
	var pod *corev1.Pod
	var err error

	// Because we are still creating the container, its status is not available at the k8s API.
	// Instead, we use the PodID.
	for i := 0; i < 30; i++ {
		pod, err = arg.Watcher.FindPodOnly(arg.Req.PodID)
		if err == nil {
			break
		}
		logger.GetLogger().WithError(err).Infof("failed to get pod info from watcher (%T): will retry.", arg.Watcher)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to get pod info: bailing out.")
		return err
	}

	logger.GetLogger().Infof("got pod=%s", pod)
	return nil
}
