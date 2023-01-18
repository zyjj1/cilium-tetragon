package policyfilter

import "sync"

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

var (
	glblState      *State
	setGlobalState sync.Once
)
