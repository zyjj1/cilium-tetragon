// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import "k8s.io/client-go/tools/cache"

type cmd interface{}
type managerHandle = chan<- cmd

type Manager struct {
	podInformer cache.SharedIndexInformer
	handle      managerHandle
	policies    map[policyID]Policy
}

func NewManager(podInformer cache.SharedIndexInformer) *Manager {
	podInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
			},
			UpdateFunc: func(_, newObj interface{}) {
				// NB(kkourt): because we only support namespace filters, we
				// do nothing in the update function. Once we add support for k8s
				// labels, however, we would need deal with pod labels changing.
			},
			DeleteFunc: func(obj interface{}) {
			},
		})
	return nil
}
