// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
)

func TestMain(m *testing.M) {
	flag.StringVar(&option.Config.HubbleLib,
		"bpf-lib", option.Config.HubbleLib,
		"tetragon lib directory (location of btf file and bpf objs).")
	flag.Parse()

	// setup a custom bpffs path to pin objects
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	dirPath, err := os.MkdirTemp(defaults.DefaultMapRoot, "test-policy-filter-*")
	if err != nil {
		panic(err)
	}
	dir := filepath.Base(dirPath)
	bpf.SetMapPrefix(dir)

	ec := m.Run()

	// cleanup bpffs path
	os.RemoveAll(dirPath)

	os.Exit(ec)
}
