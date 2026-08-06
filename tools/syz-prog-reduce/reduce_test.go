// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func testProg(t *testing.T, text string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReduceProgSamplesDynamicMotifs(t *testing.T) {
	p := testProg(t, repeatedEquivalentCallsProg(10))
	reduced, stats := reduceProg(p, reduceOptions{
		MaxCalls:          0,
		MaxMotifInstances: 3,
		MaxLiveResources:  0,
		KeepFirst:         1,
		KeepLast:          1,
		IncludeConsts:     true,
	})
	if len(reduced.Calls) != 6 {
		t.Fatalf("got %d calls, want 6\n%s", len(reduced.Calls), reduced.Serialize())
	}
	if stats.Motifs != 2 {
		t.Fatalf("got %d motifs, want 2", stats.Motifs)
	}
	if _, err := reduced.SerializeForExec(); err != nil {
		t.Fatalf("reduced program is not executable: %v\n%s", err, reduced.Serialize())
	}
}

func TestUsedResourcesIncludesInOutDependencies(t *testing.T) {
	p := testProg(t, "r0 = test$res2()\nmutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n")
	producer := p.Calls[0].Ret
	consumer := prog.MakeResultArg(p.Calls[1].Args[0].Type(), prog.DirInOut, producer, 0)
	call := p.Calls[1]
	call.Args[0] = consumer

	resources := usedResources(call)
	if len(resources) != 1 || resources[0].Res != producer {
		t.Fatalf("inout dependency not tracked: %#v", resources)
	}
	if dependenciesAvailable(call, map[*prog.ResultArg]bool{}) {
		t.Fatal("call with unavailable inout dependency was accepted")
	}
}

func TestReduceProgKeepsEverySyscallVariantWithDependencies(t *testing.T) {
	p := testProg(t, ""+
		"r0 = test$res2()\n"+
		"mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n"+
		"r1 = mutate5(&(0x7f0000000080)='./file\\x00', 0x0)\n"+
		"mutate6(r1, &(0x7f00000000c0)=\"abcd\", 0x4)\n")
	reduced, _ := reduceProg(p, reduceOptions{
		MaxCalls:          1,
		MaxMotifInstances: 1,
		MaxLiveResources:  1,
		IncludeConsts:     true,
	})
	variants := make(map[string]bool)
	for _, call := range reduced.Calls {
		variants[call.Meta.Name] = true
	}
	for _, name := range []string{"test$res2", "mutate5", "mutate6"} {
		if !variants[name] {
			t.Fatalf("missing syscall variant %q:\n%s", name, reduced.Serialize())
		}
	}
	if _, err := reduced.SerializeForExec(); err != nil {
		t.Fatalf("reduced program is not executable: %v\n%s", err, reduced.Serialize())
	}
}

func TestReduceProgRestoresMotifFrequenciesWithRerun(t *testing.T) {
	p := testProg(t, repeatedEquivalentCallsProg(10))
	reduced, stats := reduceProg(p, reduceOptions{
		MaxCalls:          0,
		MaxMotifInstances: 3,
		MaxLiveResources:  0,
		KeepFirst:         1,
		KeepLast:          1,
		IncludeConsts:     true,
	})
	weighted := make(map[string]int)
	for _, call := range reduced.Calls {
		weighted[call.Meta.Name] += 1 + call.Props.Rerun
	}
	if weighted["test"] != 10 || weighted["test$int"] != 10 {
		t.Fatalf("weighted calls = %v, want test=10 test$int=10\n%s", weighted, reduced.Serialize())
	}
	if stats.WeightedCalls != len(p.Calls) {
		t.Fatalf("weighted calls = %d, want %d", stats.WeightedCalls, len(p.Calls))
	}
}

func TestReduceProgReducesArgumentDistinctMotifs(t *testing.T) {
	p := testProg(t, repeatedFilesProg(4))
	reduced, stats := reduceProg(p, reduceOptions{
		MaxCalls:          0,
		MaxMotifInstances: 1,
		MaxLiveResources:  0,
		IncludeConsts:     true,
	})
	if len(reduced.Calls) != 2 {
		t.Fatalf("kept %d calls, want one dependency-valid motif instance:\n%s",
			len(reduced.Calls), reduced.Serialize())
	}
	for _, call := range reduced.Calls {
		if call.Props.Rerun != 0 {
			t.Fatalf("argument-distinct call was weighted:\n%s", reduced.Serialize())
		}
	}
	if stats.WeightedCalls != len(reduced.Calls) {
		t.Fatalf("weighted calls = %d, want %d", stats.WeightedCalls, len(reduced.Calls))
	}
	if _, err := reduced.SerializeForExec(); err != nil {
		t.Fatalf("reduced program is not executable: %v\n%s", err, reduced.Serialize())
	}
}

func TestReduceProgDoesNotCombineFailNthAndRerun(t *testing.T) {
	p := testProg(t, ""+
		"test() (fail_nth: 1)\n"+
		"test()\n"+
		"test() (fail_nth: 2)\n"+
		"test()\n")
	reduced, stats := reduceProg(p, reduceOptions{
		MaxCalls:          0,
		MaxMotifInstances: 1,
		MaxLiveResources:  0,
		IncludeConsts:     true,
	})
	weighted := 0
	for _, call := range reduced.Calls {
		if call.Props.FailNth > 0 && call.Props.Rerun > 0 {
			t.Fatalf("call combines fail_nth and rerun:\n%s", reduced.Serialize())
		}
		weighted += 1 + call.Props.Rerun
	}
	if weighted != len(reduced.Calls) || stats.WeightedCalls != len(reduced.Calls) {
		t.Fatalf("weighted calls = %d/%d, want %d\n%s", weighted, stats.WeightedCalls,
			len(reduced.Calls), reduced.Serialize())
	}
	if _, err := reduced.SerializeForExec(); err != nil {
		t.Fatalf("reduced program is not executable: %v\n%s", err, reduced.Serialize())
	}
}

func TestReduceProgSamplesAsyncCallsWithoutRerun(t *testing.T) {
	p := testProg(t, ""+
		"test() (async)\n"+
		"test() (async)\n"+
		"test()\n")
	reduced, stats := reduceProg(p, reduceOptions{
		MaxMotifInstances: 1,
		IncludeConsts:     true,
	})
	if len(reduced.Calls) != 1 {
		t.Fatalf("kept %d calls, want one sampled asynchronous call:\n%s",
			len(reduced.Calls), reduced.Serialize())
	}
	for _, call := range reduced.Calls {
		if call.Props.Rerun != 0 {
			t.Fatalf("asynchronous call was collapsed into rerun:\n%s", reduced.Serialize())
		}
	}
	if stats.WeightedCalls != len(reduced.Calls) {
		t.Fatalf("weighted calls = %d, want %d", stats.WeightedCalls, len(reduced.Calls))
	}
}

func TestReduceProgSamplesCopiedInCallsWithoutRerun(t *testing.T) {
	p := testProg(t, ""+
		"r0 = test$res2()\n"+
		"mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n"+
		"mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n")
	reduced, stats := reduceProg(p, reduceOptions{
		MaxMotifInstances: 1,
		IncludeConsts:     true,
	})
	if len(reduced.Calls) != 2 {
		t.Fatalf("kept %d calls, want producer and one sampled copied-in call:\n%s",
			len(reduced.Calls), reduced.Serialize())
	}
	for _, call := range reduced.Calls {
		if call.Props.Rerun != 0 {
			t.Fatalf("copied-in call was collapsed into rerun:\n%s", reduced.Serialize())
		}
	}
	if stats.WeightedCalls != len(reduced.Calls) {
		t.Fatalf("weighted calls = %d, want %d", stats.WeightedCalls, len(reduced.Calls))
	}
}

func TestReadProgSanitizesAbsoluteFilenames(t *testing.T) {
	oldOS, oldArch := *flagOS, *flagArch
	defer func() {
		*flagOS, *flagArch = oldOS, oldArch
	}()
	*flagOS, *flagArch = "linux", "amd64"

	path := filepath.Join(t.TempDir(), "abs.prog")
	if err := os.WriteFile(path, []byte("openat(0xffffffffffffff9c, &(0x7f0000000000)='/etc/ld.so.cache\\x00', 0x0, 0x0)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := readProg(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.Calls[0].Args[1].(*prog.PointerArg).Res.(*prog.DataArg).Data())
	if got != "./etc/ld.so.cache\x00" {
		t.Fatalf("filename = %q, want sanitized absolute path", got)
	}
}

func repeatedFilesProg(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "r%d = mutate5(&(0x%x)='./file-%d\\x00', 0x0)\n", i, 0x7f0000000000+i*0x80, i)
		fmt.Fprintf(&b, "mutate6(r%d, &(0x%x)=\"abcd\", 0x4)\n", i, 0x7f0000000040+i*0x80)
	}
	return b.String()
}

func repeatedEquivalentCallsProg(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("test()\n")
		b.WriteString("test$int(0x1, 0x2, 0x3, 0x4, 0x5)\n")
	}
	return b.String()
}
