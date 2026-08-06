// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import "testing"

func TestCSBTaskHelperDependencies(t *testing.T) {
	deps := Get(Linux, AMD64).PseudoSyscallDeps
	for _, name := range []string{"syz_csb_thread_create_join", "syz_csb_fork_wait", "syz_csb_vfork_wait"} {
		if len(deps[name]) == 0 {
			t.Errorf("missing dependencies for %s", name)
		}
	}
}

func TestCSBExitHelperDependencies(t *testing.T) {
	for _, name := range []string{"syz_csb_exit", "syz_csb_exit_group"} {
		deps := Get(Linux, AMD64).PseudoSyscallDeps[name]
		if len(deps) == 0 || deps[0] != "clone" {
			t.Errorf("%s dependencies = %v", name, deps)
		}
	}
}

func TestCSBQueuedSignalDependencies(t *testing.T) {
	deps := Get(Linux, AMD64).PseudoSyscallDeps["syz_csb_rt_sigqueueinfo"]
	if len(deps) != 2 || deps[1] != "rt_sigqueueinfo" {
		t.Fatalf("dependencies = %v", deps)
	}
}
