// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"

	"github.com/google/syzkaller/prog"
)

var missedFDResources = make(map[uint64]bool)

type csbFDPolicy struct {
	returnFDs          bool
	copyoutFDs         bool
	fixedReturnArg     int
	overwritesCopyouts bool
}

var csbFDPolicies = map[string]csbFDPolicy{
	"dup":   {returnFDs: true, fixedReturnArg: -1},
	"dup3":  {returnFDs: true, fixedReturnArg: 1},
	"pipe":  {copyoutFDs: true, fixedReturnArg: -1, overwritesCopyouts: true},
	"pipe2": {copyoutFDs: true, fixedReturnArg: -1, overwritesCopyouts: true},
}

type csbDiscardedFDCleanup struct {
	initialReturn    bool
	rerunReturn      bool
	overwriteCopyout bool
}

func csbDiscardedFDCleanupFor(call prog.ExecCall, later []prog.ExecCall) csbDiscardedFDCleanup {
	policy, ok := csbFDPolicies[call.Meta.CallName]
	if !ok {
		return csbDiscardedFDCleanup{}
	}
	resultStored := call.Index != prog.ExecNoCopyout
	preserveFixed := policy.fixedReturnArg >= 0 && policy.fixedReturnArg < len(call.Args) &&
		(resultStored || execArgUsed(call.Args[policy.fixedReturnArg], later))
	return csbDiscardedFDCleanup{
		initialReturn:    policy.returnFDs && !resultStored && !preserveFixed,
		rerunReturn:      policy.returnFDs && call.Props.Rerun > 0 && !preserveFixed,
		overwriteCopyout: policy.overwritesCopyouts && call.Props.Rerun > 0,
	}
}

func (ctx *context) emitCSBOverwriteFDCleanup(w *bytes.Buffer, call prog.ExecCall, statusVar string) {
	fmt.Fprintf(w, "\tif (%s != -1) {\n", statusVar)
	for _, copyout := range call.Copyout {
		ptrOffset := ""
		if valInMMapRange(ctx, copyout.Addr) {
			ptrOffset = "+PTR_OFFSET"
		}
		fmt.Fprintf(w, "\t\tNONFAILING({ uint64 fd = *(uint%d*)(0x%xul%s); "+
			"if (fd > 2) close((int)fd); });\n", copyout.Size*8, copyout.Addr, ptrOffset)
	}
	fmt.Fprintf(w, "\t}\n")
}

func resetCSBFDResources() {
	missedFDResources = make(map[uint64]bool)
}

func trackCSBFDResources(call prog.ExecCall) {
	if call.Index != prog.ExecNoCopyout {
		missedFDResources[call.Index] = true
	}
	if policy := csbFDPolicies[call.Meta.CallName]; policy.copyoutFDs {
		for _, copyout := range call.Copyout {
			missedFDResources[copyout.Index] = true
		}
	}
}

func markCSBFDResourceClosed(call prog.ExecCall, callName string) {
	if callName != "close" || len(call.Args) == 0 {
		return
	}
	if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
		missedFDResources[fdRes] = false
	}
}

func execArgUsed(arg prog.ExecArg, calls []prog.ExecCall) bool {
	matches := func(other prog.ExecArg) bool {
		switch arg := arg.(type) {
		case prog.ExecArgResult:
			other, ok := other.(prog.ExecArgResult)
			return ok && other.Index == arg.Index
		case prog.ExecArgConst:
			other, ok := other.(prog.ExecArgConst)
			return ok && other.Value == arg.Value
		default:
			return false
		}
	}
	for _, call := range calls {
		for _, arg := range call.Args {
			if matches(arg) {
				return true
			}
		}
		for _, copyin := range call.Copyin {
			if matches(copyin.Arg) {
				return true
			}
		}
	}
	return false
}
