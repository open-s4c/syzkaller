// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type testCall struct {
	name string
	tid  int64
}

func makeTestProg(calls ...testCall) *prog.Prog {
	p := &prog.Prog{}
	for _, call := range calls {
		p.Calls = append(p.Calls, &prog.Call{
			Meta: &prog.Syscall{
				Name:     call.name,
				CallName: call.name,
			},
			StraceTid: call.tid,
		})
	}
	return p
}

func callNames(p *prog.Prog) []string {
	var names []string
	for _, call := range p.Calls {
		names = append(names, call.Meta.Name)
	}
	return names
}

func TestIsPollLike(t *testing.T) {
	for _, name := range []string{"epoll_pwait", "epoll_wait", "poll", "ppoll", "select"} {
		if !isPollLike(name) {
			t.Fatalf("%s should be poll-like", name)
		}
	}
	for _, name := range []string{"read", "write", "openat"} {
		if isPollLike(name) {
			t.Fatalf("%s should not be poll-like", name)
		}
	}
}

func TestFilterOutPollsKeepsLastPollInEachSequence(t *testing.T) {
	p := makeTestProg(
		testCall{"poll", 1},
		testCall{"ppoll", 1},
		testCall{"read", 1},
		testCall{"epoll_wait", 2},
		testCall{"write", 2},
		testCall{"select", 3},
	)

	got := callNames(filterOutPolls(p))
	want := []string{"ppoll", "read", "epoll_wait", "write", "select"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGetOutPrefix(t *testing.T) {
	oldProg := *flagProg
	t.Cleanup(func() {
		*flagProg = oldProg
	})

	tests := []struct {
		path string
		want string
	}{
		{filepath.Join("some", "program_trace_openat_write_0.prog"), "trace"},
		{filepath.Join("some", "thread_trace_openat_write_0.prog"), "trace"},
		{filepath.Join("some", "trace_openat_write_0.prog"), "trace_openat"},
		{filepath.Join("some", "trace.prog"), "trace.prog"},
	}
	for _, test := range tests {
		*flagProg = test.path
		if got := getOutPrefix(); got != test.want {
			t.Fatalf("getOutPrefix(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}

func TestGenSyscallHist(t *testing.T) {
	p := makeTestProg(
		testCall{"openat", 1},
		testCall{"write", 1},
		testCall{"openat", 2},
	)

	got := genSyscallHist(p)
	want := map[string]int{"openat": 2, "write": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildThreadListSortsDescendingAndIndexesCalls(t *testing.T) {
	syscallIDxPerTid = make(map[int64][]int)
	p := makeTestProg(
		testCall{"read", 3},
		testCall{"write", 1},
		testCall{"openat", 3},
		testCall{"close", 2},
	)

	gotThreads := buildThreadList(p)
	wantThreads := []int64{3, 2, 1}
	if !reflect.DeepEqual(gotThreads, wantThreads) {
		t.Fatalf("threads %v, want %v", gotThreads, wantThreads)
	}

	wantIndices := map[int64][]int{
		1: {1},
		2: {3},
		3: {0, 2},
	}
	if !reflect.DeepEqual(syscallIDxPerTid, wantIndices) {
		t.Fatalf("indices %v, want %v", syscallIDxPerTid, wantIndices)
	}
}

func TestReadProgAllowsAbsoluteFilenames(t *testing.T) {
	oldOS, oldArch, oldProg, oldStrict := *flagOS, *flagArch, *flagProg, *flagStrict
	defer func() {
		*flagOS = oldOS
		*flagArch = oldArch
		*flagProg = oldProg
		*flagStrict = oldStrict
	}()

	progFile := filepath.Join(t.TempDir(), "abs.prog")
	data := []byte("openat(0xffffffffffffff9c, &(0x7f0000000000)='/etc/ld.so.cache\\x00', 0x0, 0x0)\n")
	if err := os.WriteFile(progFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	*flagOS = "linux"
	*flagArch = "amd64"
	*flagProg = progFile
	*flagStrict = false

	p := readProg()
	if len(p.Calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(p.Calls))
	}
	if got := string(p.Serialize()); !strings.Contains(got, "'./etc/ld.so.cache\\x00'") {
		t.Fatalf("filename was not sanitized:\n%s", got)
	}
}

func TestProcessThreadComponentsMatchesSerialTIDs(t *testing.T) {
	oldJobs := *flagJobs
	defer func() { *flagJobs = oldJobs }()
	*flagJobs = 2
	p := makeTestProg(
		testCall{name: "socket", tid: 2},
		testCall{name: "ioctl", tid: 2},
		testCall{name: "listen", tid: 1},
		testCall{name: "read", tid: 1},
	)
	syscallIDxPerTid = make(map[int64][]int)
	threads := buildThreadList(p)
	cache := newCache()
	prog.PrepareDependencyIndex(p, cache)
	for _, tid := range threads {
		var got []extractedComponent
		processThreadComponents(p, tid, syscallIDxPerTid[tid], cache, func(batch []extractedComponent) {
			if len(batch) > *flagJobs {
				t.Fatalf("batch contains %d results, want at most %d", len(batch), *flagJobs)
			}
			got = append(got, batch...)
		})
		want := serialExtractComponents(p, tid, syscallIDxPerTid[tid])
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("TID %d results differ\nstreamed: %#v\nserial:   %#v", tid, got, want)
		}
	}
}

func TestProcessComponentsMatchesSerialExtraction(t *testing.T) {
	oldMinCalls, oldJobs := *flagMinCalls, *flagJobs
	defer func() {
		*flagMinCalls = oldMinCalls
		*flagJobs = oldJobs
	}()
	*flagMinCalls = 1
	*flagJobs = 4

	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(""+
		"<2>r0 = socket(0x111, 0x1000, 0x10000)\n"+
		"<2>ioctl(r0, 0x333, 0x0)\n"+
		"<1>listen(r0)\n"+
		"<1>test$res1(0xffff)\n"+
		"<1>r1 = mutate5(&(0x7f0000000000)='./same-file\\x00', 0x0)\n"+
		"<1>mutate9(&(0x7f0000000040)='./same-file\\x00')\n"+
		"<1>mutate9(&(0x7f0000000100)='./other-file\\x00')\n"+
		"<1>mutate6(r1, &(0x7f0000000140)=\"abcd\", 0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	callIndices := []int{2, 3, 4, 5, 6, 7}
	components := prog.RelatedCallComponentsForThread(p, 1, callIndices, newCache())
	got := processComponents(p, components)
	want := serialExtractComponents(p, 1, callIndices)

	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i].names, want[i].names) {
			t.Fatalf("result %d names = %v, want %v", i, got[i].names, want[i].names)
		}
		gotProg, wantProg := string(got[i].data), string(want[i].data)
		if gotProg != wantProg {
			t.Fatalf("result %d program differs\ngot:\n%s\nwant:\n%s", i, gotProg, wantProg)
		}
	}
}

func TestProcessComponentsPreservesSmallReduction(t *testing.T) {
	oldMinCalls, oldJobs := *flagMinCalls, *flagJobs
	defer func() {
		*flagMinCalls = oldMinCalls
		*flagJobs = oldJobs
	}()
	*flagMinCalls = 5
	*flagJobs = 1

	p := makeTestProg(
		testCall{"call0", 1},
		testCall{"call1", 1},
		testCall{"call2", 1},
		testCall{"call3", 1},
		testCall{"call4", 1},
		testCall{"call5", 1},
	)
	keep := []int{0, 1, 2, 3}
	results := processComponents(p, []prog.RelatedCallComponent{{KeepCalls: keep}})
	if results[0].data == nil {
		t.Fatal("small reduction was dropped, want the original 6 calls")
	}
	if got := results[0].calls; got != 6 {
		t.Fatalf("small reduction produced %d calls, want the original 6", got)
	}

	*flagMinCalls = 1
	keep = []int{0, 1, 2}
	results = processComponents(p, []prog.RelatedCallComponent{{KeepCalls: keep, FilterCalls: true}})
	if got := results[0].calls; got != 3 {
		t.Fatalf("large reduction produced %d calls, want 3", got)
	}
}

func TestProcessComponentsKeepsShortVariedCalls(t *testing.T) {
	oldMinCalls, oldJobs := *flagMinCalls, *flagJobs
	defer func() {
		*flagMinCalls = oldMinCalls
		*flagJobs = oldJobs
	}()
	// CSB historically passed 10. It remains accepted for compatibility, but
	// must not discard short dependency components; multidiff handles deduplication.
	*flagMinCalls = 10
	*flagJobs = 2

	p := makeTestProg(
		testCall{"futex", 1},
		testCall{"mprotect", 1},
		testCall{"sched_yield", 1},
		testCall{"getpid", 1},
	)
	components := []prog.RelatedCallComponent{
		{KeepCalls: []int{0}, FilterCalls: true},
		{KeepCalls: []int{1}, FilterCalls: true},
		{KeepCalls: []int{2}, FilterCalls: true},
		{KeepCalls: []int{3}, FilterCalls: true},
	}
	results := processComponents(p, components)
	for i, result := range results {
		if result.data == nil {
			t.Fatalf("short component %d (%s) was dropped", i, p.Calls[i].Meta.Name)
		}
		if result.calls != 1 {
			t.Fatalf("short component %d contains %d calls, want 1", i, result.calls)
		}
	}
}

func TestShapeSelectorBoundsRepeatedComponents(t *testing.T) {
	selector := newShapeSelector(8)
	for i := range 1000 {
		selector.add(extractedComponent{
			data:  []byte(fmt.Sprintf("getpid(%d)\n", i)),
			calls: 1,
			names: []string{"getpid"},
			shape: "call:getpid",
		})
	}
	got := selector.selected()
	if len(got) != 8 {
		t.Fatalf("retained %d repeated components, want 8", len(got))
	}
	if string(got[0].data) != "getpid(0)\n" || string(got[1].data) != "getpid(1)\n" {
		t.Fatalf("first representatives changed: %q, %q", got[0].data, got[1].data)
	}
	if string(got[len(got)-1].data) != "getpid(999)\n" {
		t.Fatalf("last representative = %q, want occurrence 999", got[len(got)-1].data)
	}
}

func TestShapeSelectorPreservesEveryShape(t *testing.T) {
	selector := newShapeSelector(3)
	want := []string{"futex", "mprotect", "sched_yield", "getpid"}
	for _, name := range want {
		for i := range 20 {
			selector.add(extractedComponent{
				data:  []byte(fmt.Sprintf("%s(%d)\n", name, i)),
				calls: 1,
				names: []string{name},
				shape: "call:" + name,
			})
		}
	}
	counts := make(map[string]int)
	for _, component := range selector.selected() {
		counts[component.shape]++
	}
	for _, name := range want {
		if got := counts["call:"+name]; got != 3 {
			t.Fatalf("shape %s retained %d representatives, want 3", name, got)
		}
	}
}

func TestShapeSelectorIsDeterministic(t *testing.T) {
	selectData := func() []string {
		selector := newShapeSelector(8)
		for i := range 100 {
			selector.add(extractedComponent{
				data:  []byte(fmt.Sprintf("socket(0x%x)\n", i*17)),
				shape: "call:socket",
			})
		}
		var ret []string
		for _, component := range selector.selected() {
			ret = append(ret, string(component.data))
		}
		return ret
	}
	if first, second := selectData(), selectData(); !reflect.DeepEqual(first, second) {
		t.Fatalf("selection changed between runs:\n%q\n%q", first, second)
	}
}

func TestComponentShapeIncludesResourceTopology(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	parse := func(source string) *prog.Prog {
		p, err := target.Deserialize([]byte(source), prog.NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	linked := parse("r0 = test$res0()\ntest$res1(r0)\n")
	literal := parse("r0 = test$res0()\ntest$res1(0xffff)\n")
	if componentShape(linked) == componentShape(literal) {
		t.Fatal("resource reference and literal resource have the same shape")
	}
	linkedAgain := parse("r0 = test$res0()\ntest$res1(r0)\n")
	if componentShape(linked) != componentShape(linkedAgain) {
		t.Fatal("identical dependency topology produced different shapes")
	}
}

func TestComponentShapeIgnoresScalarConstants(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	parse := func(value string) *prog.Prog {
		p, err := target.Deserialize([]byte("test$int("+value+", 0x2, 0x3, 0x4, 0x5)\n"), prog.NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if componentShape(parse("0x1")) != componentShape(parse("0x99")) {
		t.Fatal("scalar-only variants were assigned different shapes")
	}
}

func serialExtractComponents(p *prog.Prog, tid int64, callIndices []int) []extractedComponent {
	cache := newCache()
	processedCalls := make([]bool, len(p.Calls))
	nonStartCalls := make([]bool, len(p.Calls))
	var results []extractedComponent

	for _, callIndex := range callIndices {
		if nonStartCalls[callIndex] || p.Calls[callIndex].StraceTid != tid {
			continue
		}
		pF, pCallsOut, keepCalls := generateMinimizedProg(p, callIndex, processedCalls, cache)
		nonStartCalls = prog.Sliceor(prog.Sliceor(pCallsOut, keepCalls), nonStartCalls)
		processedCalls = pCallsOut

		pF = filterOutPolls(pF)
		var result extractedComponent
		if len(pF.Calls) != 0 {
			result.data = pF.Serialize()
			result.calls = len(pF.Calls)
			result.names = stat.TopKNames(genSyscallHist(pF), *flagTopCalls)
			result.shape = componentShape(pF)
		}
		results = append(results, result)
	}
	return results
}
