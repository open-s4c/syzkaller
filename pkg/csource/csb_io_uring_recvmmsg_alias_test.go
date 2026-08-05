// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func testCSBSCMRightsRingAlias(t *testing.T, receive string, seed int64) {
	t.Helper()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{target.SyscallMap[receive]: true})
	recv := target.Generate(rand.NewSource(seed), 1, ct)
	var received *prog.ResultArg
	prog.ForeachArg(recv.Calls[len(recv.Calls)-1], func(arg prog.Arg, _ *prog.ArgCtx) {
		if result, ok := arg.(*prog.ResultArg); ok && result.Dir() == prog.DirOut && result.Type().Name() == "fd" {
			received = result
		}
	})
	if received == nil {
		t.Fatalf("generated %s has no SCM_RIGHTS output", receive)
	}
	p, err := target.Deserialize([]byte("r0 = socket$unix(0x1, 0x1, 0x0)\n"+
		"r1 = io_uring_setup(0x1, &(0x7f0000000000))\n"+
		"mmap(&(0x7f0000001000/0x1000)=nil, 0x1000, 0x3, 0x1, r1, 0x10000000)\n"+
		""), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	recv.Calls[len(recv.Calls)-1].Args[0] = prog.MakeResultArg(
		recv.Calls[len(recv.Calls)-1].Meta.Args[0].Type, prog.DirIn, p.Calls[0].Ret, 0)
	p.Calls = append(p.Calls, recv.Calls...)
	enterCT := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{target.SyscallMap["io_uring_enter"]: true})
	enterProg := target.Generate(rand.NewSource(0), 1, enterCT)
	enter := enterProg.Calls[len(enterProg.Calls)-1]
	enter.Args[0] = prog.MakeResultArg(enter.Meta.Args[0].Type, prog.DirIn, received, 0)
	enter.Args[1].(*prog.ConstArg).Val = 1
	p.Calls = append(p.Calls, enter)
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "/*to_submit=*/0") {
		t.Fatalf("generated C source does not guard a ring received through %s", receive)
	}
}

func TestCSBRequiresRecvmmsgRingAliasTracking(t *testing.T) {
	testCSBSCMRightsRingAlias(t, "recvmmsg$unix", 0)
}
