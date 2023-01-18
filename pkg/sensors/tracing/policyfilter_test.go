// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestPolicyFilter(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)

	tus.LoadSensor(ctx, t, base.GetInitialSensor())
	sm := tus.StartTestSensorManager(ctx, t)

	whenceStr := fmt.Sprintf("%d", whenceBogusValue)

	spec := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 7 /* whence */},
			{Index: 5 /* fd */},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{MatchArgs: []v1alpha1.ArgSelector{{
				Index:    7,
				Operator: "Equal",
				Values:   []string{whenceStr},
			}}},
		},
	}

	policyConf := config.GenericTracingConfNamespaced{
		Metadata: config.MetadataNamespaced{
			Name:      "lseek-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{spec},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &policyConf)
	require.NoError(t, err)

	defer cancel()
}
