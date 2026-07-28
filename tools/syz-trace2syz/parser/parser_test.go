// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import (
	"fmt"
	"reflect"
	"testing"

	_ "github.com/google/syzkaller/sys"
)

func parseTestData(t *testing.T, data []byte) *TraceTree {
	t.Helper()
	tree, _, err := ParseData(data, true, -1)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestParseLoopBasic(t *testing.T) {
	tests := []string{
		`open() = 3
		fstat() = 0`,
		`open() = 0x73ffddabc
		fstat() = 0`,
		`open() = -1 ENOSPEC (something)
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed> , 2) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 0x44277ffff
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = ?
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(1,  <unfinished ...>
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open([0x1, 0x2], NULL, {tv_sec=5, tv_nsec=0}, 8 <unfinished ...>
		<... rt_sigtimedwait resumed> )   = 10 (SIGUSR1)
		fstat() = 0`,
		`open(0, 536892418, {c_cc[VMIN]=1, c_cc[VTIME]=0} <unfinished ...>
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(-19) = 0
		 fstat() = 0`,
		`open(1 + 2) = 0
		 fstat() = 0`,
		`open(3 - 1) = 0
		 fstat() = 0`,
		`open(1075599392, 0x20000000) = -1 EBADF (Bad file descriptor)
		 fstat() = 0`,
		`open() = -1 EIO (Input/output error)
		 fstat() = 0`,
		`open(113->114) = -1 EIO (Input/output error)
		 fstat() = 0`,
	}

	for _, test := range tests {
		tree := parseTestData(t, []byte(test))
		if tree.RootPid != -1 {
			t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
		}

		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 2 {
			t.Fatalf("expected 2 calls. Got %d instead", len(calls))
		}
		if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
			t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
		}
	}
}

func TestParseSplitFieldValue(t *testing.T) {
	data := []byte(`1 bpf(0x10, {query={target_fd=14, attach_type=0x6, query_flags=0, attach_flags=0, prog_ids= <unfinished ...>
2 close(3) = 0
1 <... bpf resumed>[], prog_cnt= <unfinished ...>
1 <... bpf resumed>64 => 0}}, 32) = 0`)
	for _, splitThreads := range []bool{false, true} {
		t.Run(fmt.Sprint(splitThreads), func(t *testing.T) {
			tree, trace, err := ParseData(data, splitThreads, -1)
			if err != nil {
				t.Fatal(err)
			}
			callIndex := 1
			if splitThreads {
				if tree.RootPid != 1 {
					t.Fatalf("root PID: got %d, want 1", tree.RootPid)
				}
				trace = tree.TraceMap[1]
				callIndex = 0
			} else if got := []string{trace.Calls[0].CallName, trace.Calls[1].CallName}; !reflect.DeepEqual(got, []string{"close", "bpf"}) {
				t.Fatalf("calls: got %v, want [close bpf]", got)
			}
			call := trace.Calls[callIndex]
			query := call.Args[1].(*GroupType).Elems[0].(*GroupType)
			if call.CallName != "bpf" || len(query.Elems) != 6 {
				t.Fatalf("split query parsed as %#v", call)
			}
		})
	}
}

func TestParseSplitFieldValueNoPID(t *testing.T) {
	tree := parseTestData(t, []byte(`bpf(0x10, {query={prog_ids= <unfinished ...>
<... bpf resumed>[], prog_cnt=1}}, 32) = 0`))
	if call := tree.TraceMap[-1].Calls[0]; call.CallName != "bpf" {
		t.Fatalf("split call parsed as %#v", call)
	}
}

func TestEvaluateExpressions(t *testing.T) {
	type ExprTest struct {
		line         string
		expectedEval uint64
	}
	tests := []ExprTest{
		{"open(0x1) = 0", 1},
		{"open(1) = 0", 1},
		{"open(0x1|0x2) = 0", 3},
		{"open(0x1|2) = 0", 3},
		{"open(1 << 5) = 0", 32},
		{"open(1 << 5|1) = 0", 33},
		{"open(1 & 0) = 0", 0},
		{"open(1 + 2) = 0", 3},
		{"open(1-2) = 0", ^uint64(0)},
		{"open(4 >> 1) = 0", 2},
		{"open(0700) = 0", 448},
		{"open(0) = 0", 0},
	}
	for i, test := range tests {
		tree := parseTestData(t, []byte(test.line))
		if tree.RootPid != -1 {
			t.Fatalf("failed test: %d. Incorrect Root Pid: %d", i, tree.RootPid)
		}
		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 1 {
			t.Fatalf("failed test: %d. Expected 1 call. Got %d instead", i, len(calls))
		}
		arg, ok := calls[0].Args[0].(Constant)
		if !ok {
			t.Fatalf("first argument expected to be constant. Got: %s", arg.String())
		}
		if arg.Val() != test.expectedEval {
			t.Fatalf("expected %v != %v", test.expectedEval, arg.Val())
		}
	}
}

func TestParseEmptyStatxFlags(t *testing.T) {
	line := `1 statx(3, "a, ,b", , 0x1101, {}) = 0`
	if got := normalizeStraceLine(line); got != `1 statx(3, "a, ,b", 0, 0x1101, {}) = 0` {
		t.Fatalf("normalized as %q", got)
	}
	quoted := `1 write(1, " statx(3, x, , y)", 18) = 18`
	if got := normalizeStraceLine(quoted); got != quoted {
		t.Fatalf("quoted payload normalized as %q", got)
	}
	tree := parseTestData(t, []byte(`1 statx(3, ".", , 0x1101, {}) = 0`))
	call := tree.TraceMap[tree.RootPid].Calls[0]
	arg, ok := call.Args[2].(Constant)
	if !ok || arg.Val() != 0 {
		t.Fatalf("empty statx flags parsed as %#v, want constant zero", call.Args[2])
	}
}

func TestParseTruncatedSchedAffinity(t *testing.T) {
	formats := []string{"[0, 1, 2, ...]", "[0 1 2 ...]"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			testParseTruncatedSchedAffinity(t, format)
		})
	}
}

func testParseTruncatedSchedAffinity(t *testing.T, cpus string) {
	data := []byte(fmt.Sprintf(`901717 sched_setaffinity(901734, 8192, %s <unfinished ...>
901717 <... sched_setaffinity resumed>) = 0
901717 close(3) = 0`, cpus))
	tests := []struct {
		name         string
		splitThreads bool
	}{
		{"merged", false},
		{"split", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree, trace, err := ParseData(data, test.splitThreads, -1)
			if err != nil {
				t.Fatal(err)
			}
			if test.splitThreads {
				trace = tree.TraceMap[901717]
			}
			if len(trace.Calls) != 2 {
				t.Fatalf("got %d calls, want resumed affinity and following call", len(trace.Calls))
			}
			call := trace.Calls[0]
			if call.CallName != "sched_setaffinity" || call.Paused || call.Ret != 0 {
				t.Fatalf("unexpected resumed call: %#v", call)
			}
			cpus, ok := call.Args[2].(*GroupType)
			if !ok || len(cpus.Elems) != 3 {
				t.Fatalf("CPU list parsed as %#v, want three known CPUs", call.Args[2])
			}
		})
	}
}

func TestParseLoopPid(t *testing.T) {
	data := `1  open() = 3
			 1  fstat() = 0`

	tree := parseTestData(t, []byte(data))
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
	}

	calls := tree.TraceMap[tree.RootPid].Calls
	if len(calls) != 2 {
		t.Fatalf("Expect 2 calls. Got %d instead", len(calls))
	}
	if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
		t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
	}
}

func TestSkippedLeadingRecordPreservesRootPid(t *testing.T) {
	tree := parseTestData(t, []byte(`1 --- SIGCHLD {si_signo=SIGCHLD} ---
2 close(3) = 0
1 getpid() = 1`))
	if tree.RootPid != 1 || len(tree.TraceMap[1].Calls) != 1 {
		t.Fatalf("root PID %d, root calls %v", tree.RootPid, tree.TraceMap[1])
	}
}

func TestSkippedOnlyRootRecordFallsBack(t *testing.T) {
	tree := parseTestData(t, []byte(`1 +++ exited with 0 +++
2 getpid() = 2`))
	if tree.RootPid != 2 {
		t.Fatalf("root PID %d, want 2", tree.RootPid)
	}
}

func TestUnsplitRootPid(t *testing.T) {
	data := []byte("7 read(3,  <unfinished ...>\n8 getpid() = 8\n7 <... read resumed>\"x\", 1) = 1\n")
	_, trace, err := ParseData(data, false, -1)
	if err != nil {
		t.Fatal(err)
	}
	if trace.RootPid != 7 {
		t.Fatalf("root PID = %d, want 7", trace.RootPid)
	}
}

func TestParseLoop1Child(t *testing.T) {
	data1Child := `1 open() = 3
				   1 clone() = 2
                   2 read() = 16`

	tree := parseTestData(t, []byte(data1Child))
	if len(tree.TraceMap) != 2 {
		t.Fatalf("Incorrect Root Pid. Expected: 2, Got %d", tree.RootPid)
	}
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 1, Got %d", tree.RootPid)
	}
	if tree.Ptree[tree.RootPid][0] != 2 {
		t.Fatalf("Expected child to have pid: 2. Got %d", tree.Ptree[tree.RootPid][0])
	} else {
		if len(tree.TraceMap[2].Calls) != 1 {
			t.Fatalf("Child trace should have only 1 call. Got %d", len(tree.TraceMap[2].Calls))
		}
	}
}

func TestParseForkChildren(t *testing.T) {
	data := `1 fork() = 2
2 read() = 1
1 vfork() = 3
3 write() = 1
1 fork() = -1`
	tree := parseTestData(t, []byte(data))
	children := tree.Ptree[tree.RootPid]
	if !reflect.DeepEqual(children, []int64{2, 3}) {
		t.Fatalf("got children %v, want [2 3]", children)
	}
}

func TestParseLoop2Childs(t *testing.T) {
	data2Childs := `1 open() = 3
                    1 clone() = 2
                    2 read() = 16
                    1 clone() = 3
                    3 open() = 3`
	tree := parseTestData(t, []byte(data2Childs))
	if len(tree.TraceMap) != 3 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)
	}
	if len(tree.Ptree[tree.RootPid]) != 2 {
		t.Fatalf("Expected Pid 1 to have 2 children: Got %d", len(tree.Ptree[tree.RootPid]))
	}
}

func TestParseLoop1Grandchild(t *testing.T) {
	data1Grandchild := `1 open() = 3
						1 clone() = 2
						2 clone() = 3
						3 open() = 4`
	tree := parseTestData(t, []byte(data1Grandchild))
	if len(tree.Ptree[tree.RootPid]) != 1 {
		t.Fatalf("Expect RootPid to have 1 child. Got %d", tree.RootPid)
	}
	if len(tree.Ptree[2]) != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)

	}
}

func TestParseGroupType(t *testing.T) {
	type irTest struct {
		test string
	}
	tests := []irTest{
		{`open({1, 2, 3}) = 0`},
		{`open([1, 2, 3]) = 0`},
		{`open([1 2 3]) = 0`},
	}
	for _, test := range tests {
		tree := parseTestData(t, []byte(test.test))
		call := tree.TraceMap[tree.RootPid].Calls[0]
		_, ok := call.Args[0].(*GroupType)
		if !ok {
			t.Fatalf("Expected Group type. Got: %#v", call.Args[0])
		}
	}
}

func TestParseBPFFilterMacros(t *testing.T) {
	tree := parseTestData(t, []byte(
		`1 seccomp(1, 0, [BPF_STMT(code=BPF_LD|BPF_W|BPF_ABS, k=4), `+
			`BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|13), BPF_JUMP(0x15, 1, 0, 1)]) = 0`))
	filter, ok := tree.TraceMap[1].Calls[0].Args[2].(*GroupType)
	if !ok || len(filter.Elems) != 3 {
		t.Fatalf("filter parsed as %#v, want three instructions", filter)
	}
	if got, want := filter.String(),
		"[[0x20,0x0,0x0,0x4,],[0x6,0x0,0x0,0x5000d,],[0x15,0x0,0x1,0x1,],]"; got != want {
		t.Fatalf("filter = %q, want %q", got, want)
	}
}

func TestSkipUnusableRecords(t *testing.T) {
	tree := parseTestData(t, []byte(`1 open() = 3
1 ????( <unfinished ...>
1 <... ???? resumed>) = ?
2 nanosleep({tv_sec=0}, <unfinished ...>) = ?
2 nanosleep({tv_sec=0})   = ? ERESTART_RESTARTBLOCK (Interrupted by signal)
1 close(3) = 0`))
	if calls := tree.TraceMap[1].Calls; len(calls) != 2 {
		t.Fatalf("got %d surrounding calls, want 2", len(calls))
	}
	if _, ok := tree.TraceMap[2]; ok {
		t.Fatal("terminal unfinished call was not skipped")
	}
}

func TestUnusableMarkersInArgumentsAreParsed(t *testing.T) {
	for _, line := range []string{
		`1 write(1, "????(", 5) = 5`,
		`1 write(1, "<unfinished ...>", 16) = ?`,
		`1 write(1, "---", 3) = 3`,
		`1 write(1, "x) = ERESTART", 13) = 13`,
		`1 openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3</tmp/ERESTART-file>`,
	} {
		if shouldSkip(line) {
			t.Errorf("skipped syscall argument in %q", line)
		}
	}
	tree := parseTestData(t, []byte(`1 write(1, "ERESTART", 8) = 8`))
	if calls := tree.TraceMap[1].Calls; len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
}

func TestRestartedResumedRecordIsSkipped(t *testing.T) {
	if !shouldSkip(`1 <... wait4 resumed>) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)`) {
		t.Fatal("resumed restart record was not skipped")
	}
	if !shouldSkip(`1 <... resuming interrupted wait4 ...>) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)`) {
		t.Fatal("alternate resumed restart record was not skipped")
	}
	if !shouldSkip(`1 read(3</tmp/a)>, "x", 1) = ? ERESTARTSYS (To be restarted)`) {
		t.Fatal("restart after decoded fd annotation was not skipped")
	}
	if !shouldSkip(`1 nanosleep(1 << 5) = ? ERESTARTSYS (To be restarted)`) {
		t.Fatal("restart after shift expression was not skipped")
	}
}
