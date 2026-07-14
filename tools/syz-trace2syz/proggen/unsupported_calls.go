// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

var (
	// unsupportedCalls lists system calls that we should skip when parsing.
	// Some of these are unsupported or not worth executing.
	unsupportedCalls = map[string]bool{
		// Process termination cannot be replayed inside a repeatable CSB operation.
		"exit":       true,
		"exit_group": true,
		// Unsafe to set process properties.
		"arch_prctl": true,
		// Not interesting coverage
		// "getcwd": true,
		// "getcpu": true,
		// Cannot evaluate sigset
		"rt_sigreturn":    true,
		"rt_sigqueueinfo": true,
		"rt_sigsuspend":   true,
		// Require function pointers which are not recovered by strace
		"rt_sigaction": true,
		// io_ syscalls pass resource via pointers [io_ctx], which is not supported yet
		"io_setup":      true,
		"io_getevents":  true,
		"io_pgetevents": true,
		"io_destroy":    true,
		"io_submit":     true,
		"io_cancel":     true,
	}
)
