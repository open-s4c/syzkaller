// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

var (
	// unsupportedCalls lists system calls that we should skip when parsing.
	// Some of these are unsupported or not worth executing.
	unsupportedCalls = map[string]bool{
		// Unsafe to set process properties.
		"arch_prctl": true,
		// Not interesting coverage
		// "getcwd": true,
		// "getcpu": true,
		// Cannot evaluate sigset
		"rt_sigreturn":    true,
		"rt_sigqueueinfo": true,
		"rt_sigsuspend":   true,
	}
)
