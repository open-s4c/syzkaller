// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import "testing"

func TestUnsafeCSBSyscallsAreNotProbed(t *testing.T) {
	unsafe := map[string]map[string]bool{
		"syz_csb_exit":         {"exit": true},
		"syz_csb_exit_group":   {"exit_group": true},
		"syz_csb_rt_sigreturn": {"rt_sigreturn": true},
	}
	for name, calls := range unsafe {
		deps := Get(Linux, AMD64).PseudoSyscallDeps[name]
		for _, dep := range deps {
			if calls[dep] {
				t.Errorf("%s must not probe %s directly", name, dep)
			}
		}
	}
}
