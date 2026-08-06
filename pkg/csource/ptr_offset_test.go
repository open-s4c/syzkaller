// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func TestPtrOffsetChecksumAddresses(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{opts: Options{CSB: true}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch)}
	addr := target.DataOffset
	var out bytes.Buffer
	ctx.generateCsumInet(&out, addr+8, prog.ExecArgCsum{Chunks: []prog.ExecCsumChunk{
		{Kind: prog.ExecArgCsumChunkData, Value: addr, Size: 4},
		{Kind: prog.ExecArgCsumChunkConst, Value: addr, Size: 2},
	}}, 1)
	// Only the data source and checksum destination are addresses; the equal constant is data.
	if got := strings.Count(out.String(), "+PTR_OFFSET"); got != 2 {
		t.Fatalf("got %d offsets, want 2:\n%s", got, out.String())
	}
}

func TestValInMMapRange(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{opts: Options{CSB: true}, target: target, sysTarget: targets.Get(target.OS, target.Arch)}
	min := target.DataOffset
	max := min + target.NumPages*target.PageSize
	tests := []struct {
		value uint64
		want  bool
	}{
		{min - 1, false}, {min, true}, {max - 1, true}, {max, false}, {max + 0x1000, false},
	}
	for _, test := range tests {
		if got := ctx.sourceDialect().pointerOffset(test.value) != ""; got != test.want {
			t.Errorf("pointerOffset(%#x) present=%v, want %v", test.value, got, test.want)
		}
	}
}

func TestDataMmapProgOffsetsGuards(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p := target.DataMmapProg()
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{p: p, target: target, sysTarget: targets.Get(target.OS, target.Arch), opts: Options{CSB: true}}
	var calls strings.Builder
	for _, call := range decoded.Calls {
		calls.WriteString(ctx.fmtCallBody(call, false, 0, -1, false, true))
	}
	if got := strings.Count(calls.String(), "+PTR_OFFSET"); got != 3 {
		t.Fatalf("data mmap and guards are not all relocated: %d offsets", got)
	}
}

func TestPtrOffsetBitfieldDestination(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{opts: Options{CSB: true}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch)}
	var out bytes.Buffer
	ctx.copyin(&out, new(int), prog.ExecCopyin{Addr: target.DataOffset, Arg: prog.ExecArgConst{
		Size: 2, Value: target.DataOffset, BitfieldLength: 4,
	}})
	// The destination is an address; the numerically equal bitfield value is data.
	if got := strings.Count(out.String(), "+PTR_OFFSET"); got != 1 {
		t.Fatalf("got %d offsets, want 1:\n%s", got, out.String())
	}
}

func TestPtrOffsetUsesPointerEncoding(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{p: &prog.Prog{Target: target}, opts: Options{CSB: true}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch)}
	addr := target.DataOffset
	for _, test := range []struct {
		name string
		arg  prog.ExecArgConst
		want int
	}{
		{"scalar", prog.ExecArgConst{Size: 8, Value: addr}, 1},
		{"pointer", prog.ExecArgConst{IsPointer: true, Size: 8, Value: addr}, 2},
		{"null pointer", prog.ExecArgConst{IsPointer: true, Size: 8}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			ctx.copyin(&out, new(int), prog.ExecCopyin{Addr: addr, Arg: test.arg})
			if got := strings.Count(out.String(), "+PTR_OFFSET"); got != test.want {
				t.Fatalf("got %d offsets, want %d:\n%s", got, test.want, out.String())
			}
		})
	}

	meta := target.SyscallMap["close"]
	for _, arg := range []prog.ExecArgConst{{Size: 8, Value: addr}, {IsPointer: true, Size: 8, Value: addr}} {
		got := ctx.fmtCallBody(prog.ExecCall{Meta: meta, Args: []prog.ExecArg{arg}}, false, 0, -1, false, false)
		if strings.Contains(got, "+PTR_OFFSET") != arg.IsPointer {
			t.Fatalf("direct argument relocation does not match pointer encoding: %s", got)
		}
	}
}

func TestSourceDialectBoundary(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	newContext := func(csb bool) *context {
		return &context{opts: Options{CSB: csb}, target: target,
			sysTarget: targets.Get(target.OS, target.Arch)}
	}
	if got := newContext(false).sourceDialect().pseudoCallName("syz_csb_exit"); got != "syz_csb_exit" {
		t.Fatalf("upstream dialect rewrote helper name to %q", got)
	}
	if got := newContext(true).sourceDialect().pseudoCallName("syz_csb_exit"); got != "UNIQUE_FUNC(syz_csb_exit)" {
		t.Fatalf("CSB dialect helper name is not namespaced: %q", got)
	}
	if got := newContext(false).sourceDialect().pointerOffset(target.DataOffset); got != "" {
		t.Fatalf("upstream dialect relocated an address: %q", got)
	}
	if got := newContext(true).sourceDialect().pointerOffset(target.DataOffset); got != "+PTR_OFFSET" {
		t.Fatalf("CSB dialect did not relocate an address: %q", got)
	}
}
