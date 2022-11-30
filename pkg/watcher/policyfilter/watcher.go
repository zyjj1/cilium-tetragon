// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodMatcher = func(pod *Pod) bool

type policyID = uint64
type podID = uuid.UUID
type cgroupID = uint64

type Container struct {
	Name     string
	ID       string
	cgroupID *uint64
}

type Pod struct {
	Name      string
	Namespace string
	PodID     uuid.UUID
}

type Policy struct {
	ID         policyID
	podMatcher PodMatcher
	pods       map[podID]Pod
}

func NewPod(*corev1.Pod) *Pod {
	return nil
}

type PolicyManagerConf struct {
	log logrus.FieldLogger
}

func NewPolicyManager(podInformer cache.SharedIndexInformer) *PolicyManager {
	podInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
			},
			UpdateFunc: func(_, newObj interface{}) {
				// NB(kkourt): because we only support namespace filters, we
				// do nothing in the update function. Once we add support for k8s
				// labels, we would need deal with pod labels changing.
			},
			DeleteFunc: func(obj interface{}) {
			},
		})
	return nil
}
