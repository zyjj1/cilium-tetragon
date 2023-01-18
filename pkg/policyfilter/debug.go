// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

const debugInfo = true

func (s *State) Debug(args ...interface{}) {
	if debugInfo {
		s.log.Info(args...)
	} else {
		s.log.Debug(args...)
	}
}

func (s *State) Debugf(fmt string, args ...interface{}) {
	if debugInfo {
		s.log.Infof(fmt, args...)
	} else {
		s.log.Debugf(fmt, args...)
	}
}
