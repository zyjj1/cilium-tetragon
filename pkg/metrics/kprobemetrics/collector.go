// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- MissedProbes.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	lock.Lock()
	defer lock.Unlock()

	for key, stat := range missedStats {
		ch <- MissedProbes.MustMetric(stat.missed, stat.policy, key.attach)
	}
}

// bpfZeroCollector implements prometheus.Collector. It collects "zero" metrics.
// It's intended to be used when BPF metrics are not collected, but we still want
// Prometheus metrics to be exposed.
type bpfZeroCollector struct {
	bpfCollector
}

func NewBPFZeroCollector() prometheus.Collector {
	return &bpfZeroCollector{
		bpfCollector: bpfCollector{},
	}
}

func (c *bpfZeroCollector) Describe(ch chan<- *prometheus.Desc) {
	c.bpfCollector.Describe(ch)
}

func (c *bpfZeroCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- MissedProbes.MustMetric(0, "policy", "attach")
}
