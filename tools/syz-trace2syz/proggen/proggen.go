// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package proggen

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

func ReadFile(filename string) ([]byte, int, error) {
	var status string
	var outBuffer []byte
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		return nil, 0, err
	}
	defer file.Close()

	file.Seek(0, 0)
	numLines, err := lineCounter(file)
	curLine := 0
	if err != nil || numLines < 1 {
		log.Fatal(err)
		return nil, 0, err
	}

	file.Seek(0, 0)
	scanner := bufio.NewScanner(file)
	// maxCapacity := int(64 << 20)
	// buf := make([]byte, maxCapacity)
	// scanner.Buffer(buf, maxCapacity)
	scanner.Buffer(nil, 64<<20)
	for scanner.Scan() {
		if curLine%1000 == 0 {
			status = fmt.Sprintf("-- Progress [%03.1f/100%%] --", (100.0 * float32(curLine) / float32(numLines)))
			fmt.Fprintf(os.Stderr, "%s\r", status)
		}
		readBytes := scanner.Bytes()
		outBuffer = append(outBuffer, readBytes...)
		outBuffer = append(outBuffer, byte('\n'))
		curLine++
	}
	fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil, 0, err
	}

	return outBuffer, numLines, nil
}

// TranslationStats records source calls while their generated calls are known.
type TranslationStats struct {
	Input       map[string]int
	Represented map[string]int
	Helpers     map[string]map[string]int
}

func NewTranslationStats() *TranslationStats {
	return &TranslationStats{
		Input:       make(map[string]int),
		Represented: make(map[string]int),
		Helpers:     make(map[string]map[string]int),
	}
}

func (stats *TranslationStats) Merge(other *TranslationStats) {
	for name, count := range other.Input {
		stats.Input[name] += count
	}
	for name, count := range other.Represented {
		stats.Represented[name] += count
	}
	for helper, sources := range other.Helpers {
		if stats.Helpers[helper] == nil {
			stats.Helpers[helper] = make(map[string]int)
		}
		for source, count := range sources {
			stats.Helpers[helper][source] += count
		}
	}
}

func ParseFile(filename string, target *prog.Target, splitThreads bool, argLength, madviseSetup bool) ([]*prog.Prog, error) {
	progs, _, err := ParseFileWithStats(filename, target, splitThreads, argLength, madviseSetup)
	return progs, err
}

func ParseFileWithStats(filename string, target *prog.Target, splitThreads bool,
	argLength, madviseSetup bool) ([]*prog.Prog, *TranslationStats, error) {
	fmt.Fprintf(os.Stderr, "Reading file to memory\n")
	// data, err := os.ReadFile(filename)
	data, numLines, err := ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading file: %v", err)
	}
	stats := NewTranslationStats()
	progs, err := parseData(data, target, splitThreads, argLength, madviseSetup, numLines, stats)
	return progs, stats, err
}

func ParseData(data []byte, target *prog.Target, splitThreads, argLength, madviseSetup bool,
	numLines int) ([]*prog.Prog, error) {
	return parseData(data, target, splitThreads, argLength, madviseSetup, numLines, NewTranslationStats())
}

func parseData(data []byte, target *prog.Target, splitThreads, argLength, madviseSetup bool,
	numLines int, stats *TranslationStats) ([]*prog.Prog, error) {
	fmt.Fprintf(os.Stderr, "Parsing data into syscalls\n")
	tree, trace, err := parser.ParseData(data, splitThreads, numLines)
	if err != nil {
		return nil, err
	}
	if tree == nil && splitThreads {
		return nil, nil
	}

	if trace == nil && !splitThreads {
		return nil, nil
	}
	var progs []*prog.Prog
	if splitThreads {
		parseTree(tree, tree.RootPid, target, &progs, argLength, madviseSetup, true, stats)
	} else {
		progs = append(progs, genProg(trace, target, argLength, false, madviseSetup, true, stats))
	}
	return progs, nil
}

// parseTree groups system calls in the trace by process id.
// The tree preserves process hierarchy i.e. parent->[]child
func parseTree(tree *parser.TraceTree, pid int64, target *prog.Target, progs *[]*prog.Prog,
	argLength, madviseSetup, skipBootstrapExec bool, stats *TranslationStats) {
	log.Logf(2, "parsing trace pid %v", pid)
	if p := genProg(tree.TraceMap[pid], target, argLength, false, madviseSetup, skipBootstrapExec, stats); p != nil {
		*progs = append(*progs, p)
	}
	for _, childPid := range tree.Ptree[pid] {
		if tree.TraceMap[childPid] != nil {
			parseTree(tree, childPid, target, progs, argLength, madviseSetup, false, stats)
		}
	}
}

// Context stores metadata related to a syzkaller program
type context struct {
	builder           *prog.Builder
	target            *prog.Target
	selectors         []callSelector
	returnCache       returnCache
	currentStraceCall *parser.Syscall
	currentSyzCall    *prog.Call
	randomized        bool
	madviseSetup      bool
}

// genProg converts a trace to one of our programs.
func genProg(trace *parser.Trace, target *prog.Target, argLength, randomized, madviseSetup,
	skipBootstrapExec bool, statsArg ...*TranslationStats) *prog.Prog {
	var status string
	stats := NewTranslationStats()
	if len(statsArg) != 0 {
		stats = statsArg[0]
	}
	retCache := newRCache()
	ctx := &context{
		builder:      prog.MakeProgGen(target),
		target:       target,
		selectors:    newSelectors(target, retCache),
		returnCache:  retCache,
		randomized:   randomized,
		madviseSetup: madviseSetup,
	}
	fmt.Fprintf(os.Stderr, "Parsing syscalls into syzlang\n")
	numCalls := len(trace.Calls)
	// Skip only the root bootstrap; a later successful exec ends that TID's original workload.
	bootstrapExecSkipped := false
	var rootPID int64
	if len(trace.Calls) != 0 {
		rootPID = trace.Calls[0].Pid
	}
	// Bounded exec lifecycle calls do not replace the benchmark process, so
	// continue translating calls from the traced replacement image.
	for sIdx, sCall := range trace.Calls {
		if sIdx%1000 == 0 {
			status = fmt.Sprintf("-- Progress [%03.1f/100%%] --", (100.0 * float32(sIdx) / float32(numCalls)))
			fmt.Fprintf(os.Stderr, "%s\r", status)
		}
		if sCall.Paused {
			// Probably a case where the call was killed by a signal like the following
			// 2179  wait4(2180,  <unfinished ...>
			// 2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			// 2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			continue
		}
		stats.Input[sCall.CallName]++
		if skipBootstrapExec && !bootstrapExecSkipped && sCall.Pid == rootPID && isSuccessfulExec(sCall) {
			bootstrapExecSkipped = true
			continue
		}
		if shouldSkip(sCall) {
			continue
		}
		ctx.currentStraceCall = sCall
		calls := ctx.genCalls()
		if len(calls) == 0 {
			continue
		}
		stats.Represented[sCall.CallName]++
		for _, call := range calls {
			if strings.HasPrefix(call.Meta.CallName, "syz_") {
				if stats.Helpers[call.Meta.CallName] == nil {
					stats.Helpers[call.Meta.CallName] = make(map[string]int)
				}
				stats.Helpers[call.Meta.CallName][sCall.CallName]++
			}
			if err := ctx.builder.Append(call, argLength); err != nil {
				fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
				log.Fatalf("%v", err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	p, err := ctx.builder.Finalize()
	if err != nil {
		log.Fatalf("error validating program: %v", err)
	}
	return p
}

// genCalls routes sanitized syscalls to bounded generators that may emit setup and replay calls.
func (ctx *context) genCalls() []*prog.Call {
	if minArgs := sanitizedCallMinArgs[ctx.currentStraceCall.CallName]; len(ctx.currentStraceCall.Args) < minArgs {
		return nil
	}
	if isExec(ctx.currentStraceCall) && ctx.currentStraceCall.Ret < 0 {
		return nil
	}
	if name := execLifecycleCall(ctx.currentStraceCall); name != "" {
		return singleCall(ctx.genDefaultSafeCall(name))
	}
	switch ctx.currentStraceCall.CallName {
	case "madvise":
		return ctx.genMadviseCalls()
	case "mmap":
		return singleCall(ctx.genMmapCall())
	case "mprotect":
		return singleCall(ctx.genMprotectCall())
	case "msync":
		return singleCall(ctx.genMsyncCall())
	case "munmap":
		return ctx.genMunmapCalls()
	case "mremap":
		return ctx.genMremapCalls()
	case "futex":
		return singleCall(ctx.genFutexCall())
	case "rt_sigprocmask":
		return singleCall(ctx.genRtSigprocmaskCall())
	case "rt_sigtimedwait":
		return singleCall(ctx.genRtSigtimedwaitCall())
	case "set_robust_list":
		return singleCall(ctx.genSetRobustListCall())
	case "set_tid_address":
		return singleCall(ctx.genDefaultSafeCall("set_tid_address"))
	case "sched_setaffinity":
		if ctx.currentStraceCall.Ret < 0 {
			return nil
		}
		return singleCall(ctx.genDefaultSafeCall("syz_reapply_affinity"))
	case "wait", "wait4":
		return singleCall(ctx.genWait4Call())
	case "clone", "clone3":
		return singleCall(ctx.genCloneLifecycleCall())
	case "fork":
		return singleCall(ctx.genTaskLifecycleCall("syz_csb_fork_wait"))
	case "vfork":
		return singleCall(ctx.genTaskLifecycleCall("syz_csb_vfork_wait"))
	default:
		return singleCall(ctx.genCall())
	}
}

var sanitizedCallMinArgs = map[string]int{
	"futex":          2,
	"madvise":        3,
	"mmap":           3,
	"mprotect":       3,
	"mremap":         3,
	"msync":          3,
	"munmap":         2,
	"rt_sigprocmask": 1,
}

// genCloneLifecycleCall preserves the task kind while replacing its workload with a bounded helper.
func (ctx *context) genCloneLifecycleCall() *prog.Call {
	name := "syz_csb_fork_wait"
	if cloneCreatesThread(ctx.currentStraceCall) {
		name = "syz_csb_thread_create_join"
	} else if cloneUsesVfork(ctx.currentStraceCall) {
		name = "syz_csb_vfork_wait"
	}
	return ctx.genTaskLifecycleCall(name)
}

func (ctx *context) genTaskLifecycleCall(name string) *prog.Call {
	// A bounded helper cannot safely reproduce the original failure mode.
	if ctx.currentStraceCall.Ret < 0 {
		return nil
	}
	call := ctx.genDefaultSafeCall(name)
	if call != nil {
		// Synthetic lifecycle helpers return zero rather than a child PID.
		call.StraceRetVal = 0
	}
	return call
}

func cloneCreatesThread(call *parser.Syscall) bool {
	return traceHasCloneFlag(call, "CLONE_THREAD", 0x10000)
}

func cloneUsesVfork(call *parser.Syscall) bool {
	return traceHasCloneFlag(call, "CLONE_VFORK", 0x4000)
}

func traceHasCloneFlag(call *parser.Syscall, name string, value uint64) bool {
	if len(call.Args) == 0 {
		return false
	}
	for _, arg := range call.Args {
		if strings.Contains(fmt.Sprint(arg), name) {
			return true
		}
	}
	flags := call.Args[0]
	// strace prints clone as clone(child_stack=..., flags=..., ...), while
	// clone3 keeps flags in the first field of struct clone_args.
	if call.CallName == "clone" && len(call.Args) > 1 {
		flags = call.Args[1]
	}
	return irHasFlag(flags, value)
}

func irHasFlag(arg parser.IrType, value uint64) bool {
	switch arg := arg.(type) {
	case parser.Constant:
		return arg.Val()&value != 0
	case *parser.GroupType:
		return len(arg.Elems) != 0 && irHasFlag(arg.Elems[0], value)
	default:
		return false
	}
}

func singleCall(call *prog.Call) []*prog.Call {
	if call == nil {
		return nil
	}
	return []*prog.Call{call}
}

func (ctx *context) genCall() *prog.Call {
	log.Logf(3, "parsing call: %s", ctx.currentStraceCall.CallName)
	straceCall := ctx.currentStraceCall
	meta := ctx.Select(straceCall)
	if meta == nil {
		log.Logf(2, "skipping call: %s which has no matching description", ctx.currentStraceCall.CallName)
		return nil
	}
	ctx.currentSyzCall = prog.MakeCall(meta, nil)
	syzCall := ctx.currentSyzCall

	for i := range syzCall.Meta.Args {
		var strArg parser.IrType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		res := ctx.genArg(syzCall.Meta.Args[i].Type, prog.DirIn, strArg)
		syzCall.Args = append(syzCall.Args, res)
	}
	ctx.genResult(syzCall.Meta.Ret, straceCall.Ret)
	syzCall.StraceRetVal = straceCall.Ret
	syzCall.StraceRetValSet = true
	syzCall.StraceTid = straceCall.Pid
	return syzCall
}

const (
	madvisePageSize = 4096
	maxMadviseLen   = 1 << 20

	protRead      = 0x1
	protWrite     = 0x2
	protExec      = 0x4
	mapPrivate    = 0x2
	mapFixed      = 0x10
	mapAnonymous  = 0x20
	mremapMaymove = 0x1

	futexWake        = 0x1
	futexPrivateFlag = 0x80

	wnohang = 0x1
)

var safeMadviseAdvice = map[uint64]bool{
	0:  true, // MADV_NORMAL
	1:  true, // MADV_RANDOM
	2:  true, // MADV_SEQUENTIAL
	3:  true, // MADV_WILLNEED
	4:  true, // MADV_DONTNEED
	8:  true, // MADV_FREE
	10: true, // MADV_DONTFORK
	11: true, // MADV_DOFORK
	12: true, // MADV_MERGEABLE
	13: true, // MADV_UNMERGEABLE
	14: true, // MADV_HUGEPAGE
	15: true, // MADV_NOHUGEPAGE
	16: true, // MADV_DONTDUMP
	17: true, // MADV_DODUMP
	20: true, // MADV_COLD
	21: true, // MADV_PAGEOUT
	22: true, // MADV_POPULATE_READ
	23: true, // MADV_POPULATE_WRITE
}

var isolatedMadviseAdvice = map[uint64]bool{
	4:  true, // MADV_DONTNEED
	8:  true, // MADV_FREE
	20: true, // MADV_COLD
	21: true, // MADV_PAGEOUT
}

func (ctx *context) genMadviseCalls() []*prog.Call {
	straceCall := ctx.currentStraceCall
	meta := ctx.Select(straceCall)
	if meta == nil || len(meta.Args) != 3 {
		return nil
	}
	length := sanitizedPageLength(straceCall.Args[1])
	npages := length / madvisePageSize
	advice := constArgValue(straceCall.Args[2], 0)
	if !safeMadviseAdvice[advice] {
		advice = 0
	}
	isolated := isolatedMadviseAdvice[advice]
	if isolated && !ctx.madviseSetup {
		advice = 0
	}

	addr := ctx.builder.AllocateVMA(npages)
	call := ctx.makeDefaultCallForMeta(meta)
	ctx.setVmaArg(call, 0, addr, length)
	ctx.setConstArg(call, 1, length)
	ctx.setConstArg(call, 2, advice)
	ctx.finishCall(call, straceCall)
	if !isolated || !ctx.madviseSetup {
		return singleCall(call)
	}
	setup := ctx.genFixedMmapSetup(addr, npages)
	if setup == nil {
		return nil
	}
	return []*prog.Call{setup, call}
}

func (ctx *context) genMmapCall() *prog.Call {
	call := ctx.makeDefaultCall("mmap")
	if call == nil {
		return nil
	}
	length := sanitizedPageLength(ctx.currentStraceCall.Args[1])
	npages := length / madvisePageSize
	ctx.setVmaArg(call, 0, ctx.builder.AllocateVMA(npages), length)
	ctx.setConstArg(call, 1, length)
	ctx.setConstArg(call, 2, sanitizedProt(ctx.currentStraceCall.Args[2]))
	ctx.setConstArg(call, 3, mapPrivate|mapAnonymous)
	ctx.setResourceArg(call, 4, ^uint64(0))
	ctx.setConstArg(call, 5, 0)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genMprotectCall() *prog.Call {
	call := ctx.makeDefaultCall("mprotect")
	if call == nil {
		return nil
	}
	length := sanitizedPageLength(ctx.currentStraceCall.Args[1])
	ctx.setVmaArg(call, 0, ctx.builder.AllocateVMA(length/madvisePageSize), length)
	ctx.setConstArg(call, 1, length)
	ctx.setConstArg(call, 2, sanitizedProt(ctx.currentStraceCall.Args[2]))
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genMsyncCall() *prog.Call {
	call := ctx.makeDefaultCall("msync")
	if call == nil {
		return nil
	}
	length := sanitizedPageLength(ctx.currentStraceCall.Args[1])
	ctx.setVmaArg(call, 0, ctx.builder.AllocateVMA(length/madvisePageSize), length)
	ctx.setConstArg(call, 1, length)
	ctx.setConstArg(call, 2, sanitizedMsyncFlags(ctx.currentStraceCall.Args[2]))
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genMunmapCalls() []*prog.Call {
	call := ctx.makeDefaultCall("munmap")
	if call == nil {
		return nil
	}
	length := sanitizedPageLength(ctx.currentStraceCall.Args[1])
	npages := length / madvisePageSize
	addr := ctx.builder.AllocateVMA(npages)
	setup := ctx.genFixedMmapSetup(addr, npages)
	if setup == nil {
		return nil
	}
	ctx.setVmaArg(call, 0, addr, length)
	ctx.setConstArg(call, 1, length)
	ctx.finishCall(call, ctx.currentStraceCall)
	return []*prog.Call{setup, call}
}

func (ctx *context) genMremapCalls() []*prog.Call {
	call := ctx.makeDefaultCall("mremap")
	if call == nil {
		return nil
	}
	oldLength := sanitizedPageLength(ctx.currentStraceCall.Args[1])
	newLength := sanitizedLengthValue(constArgValue(ctx.currentStraceCall.Args[2], oldLength))
	oldPages := oldLength / madvisePageSize
	newPages := newLength / madvisePageSize
	oldAddr := ctx.builder.AllocateVMA(oldPages)
	setup := ctx.genFixedMmapSetup(oldAddr, oldPages)
	if setup == nil {
		return nil
	}
	ctx.setVmaArg(call, 0, oldAddr, oldLength)
	ctx.setConstArg(call, 1, oldLength)
	ctx.setConstArg(call, 2, newLength)
	ctx.setConstArg(call, 3, mremapMaymove)
	ctx.setVmaArg(call, 4, ctx.builder.AllocateVMA(newPages), newLength)
	ctx.finishCall(call, ctx.currentStraceCall)
	return []*prog.Call{setup, call}
}

func (ctx *context) genFixedMmapSetup(addr uint64, npages uint64) *prog.Call {
	call := ctx.makeDefaultCall("mmap")
	if call == nil {
		return nil
	}
	ctx.setVmaArg(call, 0, addr, npages*madvisePageSize)
	ctx.setConstArg(call, 1, npages*madvisePageSize)
	ctx.setConstArg(call, 2, protRead|protWrite)
	ctx.setConstArg(call, 3, mapPrivate|mapAnonymous|mapFixed)
	ctx.setResourceArg(call, 4, ^uint64(0))
	ctx.setConstArg(call, 5, 0)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genFutexCall() *prog.Call {
	call := ctx.makeDefaultCall("futex")
	if call == nil {
		return nil
	}
	op := uint64(futexWake) | constArgValue(ctx.currentStraceCall.Args[1], 0)&futexPrivateFlag
	ctx.setConstArg(call, 1, op)
	ctx.setConstArg(call, 2, 1)
	ctx.setNullPtrArg(call, 3)
	ctx.setNullPtrArg(call, 4)
	ctx.setConstArg(call, 5, 0)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genRtSigprocmaskCall() *prog.Call {
	call := ctx.makeDefaultCall("rt_sigprocmask")
	if call == nil {
		return nil
	}
	how := constArgValue(ctx.currentStraceCall.Args[0], 0)
	if how > 2 {
		how = 0
	}
	ctx.setConstArg(call, 0, how)
	ctx.setConstArg(call, 3, 8)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genRtSigtimedwaitCall() *prog.Call {
	call := ctx.makeDefaultCall("rt_sigtimedwait")
	if call == nil {
		return nil
	}
	ctx.setConstArg(call, 3, 8)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genWait4Call() *prog.Call {
	call := ctx.makeDefaultCall("wait4")
	if call == nil {
		return nil
	}
	ctx.setResourceArg(call, 0, ^uint64(0))
	ctx.setConstArg(call, 2, wnohang)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) genSetRobustListCall() *prog.Call {
	call := ctx.makeDefaultCall("set_robust_list")
	if call == nil {
		return nil
	}
	ctx.setConstArg(call, 1, 24)
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

// genDefaultSafeCall preserves trace metadata while replacing unsafe arguments with syzlang defaults.
func (ctx *context) genDefaultSafeCall(name string) *prog.Call {
	call := ctx.makeDefaultCall(name)
	if call == nil {
		return nil
	}
	ctx.finishCall(call, ctx.currentStraceCall)
	return call
}

func (ctx *context) makeDefaultCall(name string) *prog.Call {
	meta := ctx.target.SyscallMap[name]
	if meta == nil {
		log.Logf(2, "skipping call: %s which has no matching safe description", name)
		return nil
	}
	return ctx.makeDefaultCallForMeta(meta)
}

func (ctx *context) makeDefaultCallForMeta(meta *prog.Syscall) *prog.Call {
	call := prog.MakeCall(meta, nil)
	for _, field := range meta.Args {
		dir := field.Dir(prog.DirIn)
		call.Args = append(call.Args, ctx.builderBackedDefaultArg(field.Type, dir))
	}
	return call
}

func (ctx *context) builderBackedDefaultArg(typ prog.Type, dir prog.Dir) prog.Arg {
	arg := typ.DefaultArg(dir)
	prog.ForeachSubArg(arg, func(arg prog.Arg, _ *prog.ArgCtx) {
		ptr, ok := arg.(*prog.PointerArg)
		if !ok || ptr.Res == nil {
			return
		}
		size := ptr.Res.Size()
		if size == 0 {
			size = 1
		}
		ptr.Address = ctx.builder.Allocate(size, ptr.Res.Type().Alignment())
	})
	return arg
}

func (ctx *context) finishCall(call *prog.Call, straceCall *parser.Syscall) {
	ctx.currentSyzCall = call
	ctx.genResult(call.Meta.Ret, straceCall.Ret)
	call.StraceRetVal = straceCall.Ret
	call.StraceRetValSet = true
	call.StraceTid = straceCall.Pid
}

func (ctx *context) setVmaArg(call *prog.Call, idx int, addr uint64, sizeBytes uint64) {
	field := call.Meta.Args[idx]
	call.Args[idx] = prog.MakeVmaPointerArg(field.Type.(*prog.VmaType), field.Dir(prog.DirIn), addr, sizeBytes)
}

func (ctx *context) setConstArg(call *prog.Call, idx int, val uint64) {
	field := call.Meta.Args[idx]
	call.Args[idx] = prog.MakeConstArg(field.Type, field.Dir(prog.DirIn), val)
}

func (ctx *context) setResourceArg(call *prog.Call, idx int, val uint64) {
	field := call.Meta.Args[idx]
	call.Args[idx] = prog.MakeResultArg(field.Type, field.Dir(prog.DirIn), nil, val)
}

func (ctx *context) setNullPtrArg(call *prog.Call, idx int) {
	field := call.Meta.Args[idx]
	call.Args[idx] = prog.MakeSpecialPointerArg(field.Type.(*prog.PtrType), field.Dir(prog.DirIn), 0)
}

func sanitizedPageLength(arg parser.IrType) uint64 {
	return sanitizedLengthValue(constArgValue(arg, madvisePageSize))
}

func sanitizedLengthValue(length uint64) uint64 {
	if length == 0 {
		length = madvisePageSize
	}
	if length > maxMadviseLen {
		length = maxMadviseLen
	}
	return roundUp(length, madvisePageSize)
}

func sanitizedProt(arg parser.IrType) uint64 {
	prot := constArgValue(arg, protRead|protWrite)
	prot &= protRead | protWrite | protExec
	if prot == 0 {
		return protRead | protWrite
	}
	return prot
}

func sanitizedMsyncFlags(arg parser.IrType) uint64 {
	flags := constArgValue(arg, 4) // MS_SYNC
	flags &= 0x7
	if flags == 0 {
		return 4
	}
	return flags
}

func constArgValue(arg parser.IrType, fallback uint64) uint64 {
	if c, ok := arg.(parser.Constant); ok {
		return c.Val()
	}
	return fallback
}

func roundUp(v, unit uint64) uint64 {
	if v > ^uint64(0)-unit+1 {
		return v
	}
	return ((v + unit - 1) / unit) * unit
}

// execLifecycleCall selects the bounded helper matching the traced exec entry point.
const atEmptyPath = 0x1000

func isExec(call *parser.Syscall) bool {
	return call.CallName == "execve" || call.CallName == "execveat"
}

func isSuccessfulExec(call *parser.Syscall) bool {
	return isExec(call) && call.Ret == 0
}

func execLifecycleCall(call *parser.Syscall) string {
	switch call.CallName {
	case "execve":
		return "syz_csb_execve"
	case "execveat":
		if len(call.Args) > 4 {
			path, pathOK := call.Args[1].(*parser.BufferType)
			flags, flagsOK := call.Args[4].(parser.Constant)
			if pathOK && path.Val == "" && flagsOK && flags.Val()&atEmptyPath != 0 {
				return "syz_csb_fexecve"
			}
		}
		return "syz_csb_execveat"
	default:
		return ""
	}
}

func (ctx *context) Select(syscall *parser.Syscall) *prog.Syscall {
	for _, selector := range ctx.selectors {
		if variant := selector.Select(syscall); variant != nil {
			return variant
		}
	}
	return ctx.target.SyscallMap[syscall.CallName]
}

func (ctx *context) genResult(syzType prog.Type, straceRet int64) {
	if straceRet <= 0 {
		return
	}
	straceExpr := parser.Constant(uint64(straceRet))
	switch syzType.(type) {
	case *prog.ResourceType:
		log.Logf(2, "call: %s returned a resource type with val: %s",
			ctx.currentStraceCall.CallName, straceExpr.String())
		ctx.returnCache.cache(syzType, straceExpr, ctx.currentSyzCall.Ret)
	}
}

func (ctx *context) genArg(syzType prog.Type, dir prog.Dir, traceArg parser.IrType) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "parsing syzType: %s, traceArg is nil. generating default arg...", syzType.Name())
		return syzType.DefaultArg(dir)
	}
	log.Logf(3, "parsing arg of syz type: %s, ir type: %#v", syzType.Name(), traceArg)

	if dir == prog.DirOut {
		switch syzType.(type) {
		case *prog.PtrType, *prog.StructType, *prog.ResourceType, *prog.BufferType:
			// Resource Types need special care. Pointers, Structs can have resource fields e.g. pipe, socketpair
			// Buffer may need special care in out direction
		default:
			return syzType.DefaultArg(dir)
		}
	}

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return ctx.genConst(a, dir, traceArg)
	case *prog.LenType:
		return ctx.genConst(a, dir, traceArg)
	case *prog.ProcType:
		return ctx.parseProc(a, dir, traceArg)
	case *prog.ResourceType:
		return ctx.genResource(a, dir, traceArg)
	case *prog.PtrType:
		return ctx.genPtr(a, dir, traceArg)
	case *prog.BufferType:
		return ctx.genBuffer(a, dir, traceArg)
	case *prog.StructType:
		return ctx.genStruct(a, dir, traceArg)
	case *prog.ArrayType:
		return ctx.genArray(a, dir, traceArg)
	case *prog.UnionType:
		return ctx.genUnionArg(a, dir, traceArg)
	case *prog.VmaType:
		return ctx.genVma(a, dir, traceArg)
	default:
		log.Fatalf("unsupported type: %#v", syzType)
	}
	return nil
}

func (ctx *context) genVma(syzType *prog.VmaType, dir prog.Dir, _ parser.IrType) prog.Arg {
	npages := uint64(1)
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	return prog.MakeVmaPointerArg(syzType, dir, ctx.builder.AllocateVMA(npages), npages)
}

func (ctx *context) genArray(syzType *prog.ArrayType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		for i := 0; i < len(a.Elems); i++ {
			args = append(args, ctx.genArg(syzType.Elem, dir, a.Elems[i]))
		}
	case *parser.BufferType:
		if _, ok := syzType.Elem.(*prog.BufferType); ok {
			args = append(args, ctx.genArg(syzType.Elem, dir, a))
			break
		}
		if ptr, ok := syzType.Elem.(*prog.PtrType); ok {
			if _, ok := ptr.Elem.(*prog.BufferType); ok {
				// The parser flattens a single-element string array to its buffer.
				args = append(args, ctx.genArg(syzType.Elem, dir, a))
				break
			}
		}
		if syzType.Elem.Varlen() || syzType.Elem.Size() != 1 {
			// A parser buffer has no element-width information. Expanding it byte by
			// byte would change the layout of arrays with wider elements.
			return syzType.DefaultArg(dir)
		}
		vals := []byte(a.Val)
		if syzType.Kind == prog.ArrayRangeLen && syzType.RangeBegin == syzType.RangeEnd &&
			uint64(len(vals)) > syzType.RangeBegin {
			vals = vals[:syzType.RangeBegin]
		}
		for _, val := range vals {
			args = append(args, ctx.genArg(syzType.Elem, dir, parser.Constant(val)))
		}
		if syzType.Kind == prog.ArrayRangeLen && syzType.RangeBegin == syzType.RangeEnd {
			for uint64(len(args)) < syzType.RangeBegin {
				args = append(args, syzType.Elem.DefaultArg(dir))
			}
		}
	default:
		log.Fatalf("unsupported type for array: %#v", traceType)
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func (ctx *context) genStruct(syzType *prog.StructType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		// strace nests BPF_PROG_QUERY fields under query={} and may append
		// extra_data for bytes beyond the decoded query structure.
		if syzType.Name() == "bpf_prog_query" && len(a.Elems) != 0 {
			if query, ok := a.Elems[0].(*parser.GroupType); ok {
				a = query
			}
		}
		j := 0
		if ret, recursed := ctx.recurseStructs(syzType, dir, a); recursed {
			return ret
		}
		if syzType.Name() == "argv_array" && len(syzType.Fields) != 0 {
			// strace represents argv as one group, while argv_array wraps the
			// complete array and a trailing NULL sentinel in a struct.
			args = append(args, ctx.genArg(syzType.Fields[0].Type,
				syzType.Fields[0].Dir(dir), a))
			for _, field := range syzType.Fields[1:] {
				args = append(args, field.DefaultArg(field.Dir(dir)))
			}
			return prog.MakeGroupArg(syzType, dir, args)
		}
		for i := range syzType.Fields {
			fldDir := syzType.Fields[i].Dir(dir)
			if prog.IsPad(syzType.Fields[i].Type) {
				args = append(args, syzType.Fields[i].DefaultArg(fldDir))
				continue
			}
			// If the last n fields of a struct are zero or NULL, strace will occasionally omit those values
			// this creates a mismatch in the number of elements in the ir type and in
			// our descriptions. We generate default values for omitted fields
			if j >= len(a.Elems) {
				args = append(args, syzType.Fields[i].DefaultArg(fldDir))
			} else {
				args = append(args, ctx.genArg(syzType.Fields[i].Type, fldDir, a.Elems[j]))
			}
			j++
		}
	case *parser.BufferType:
		// We could have a case like the following:
		// ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0
		// if_hwaddr gets parsed as a BufferType but our syscall descriptions have it as a struct type
		return syzType.DefaultArg(dir)
	case parser.Constant:
		// A zero scalar represents an omitted or NULL struct in some strace output.
		if a.Val() == 0 {
			return syzType.DefaultArg(dir)
		}
		log.Fatalf("unsupported nonzero constant for struct: %#v", a)
	default:
		log.Fatalf("unsupported type for struct: %#v", a)
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

// recurseStructs handles cases where syzType corresponds to struct descriptions like
//
//	sockaddr_storage_in6 {
//	       addr    sockaddr_in6
//	} [size[SOCKADDR_STORAGE_SIZE], align_ptr]
//
// which need to be recursively generated. It returns true if we needed to recurse
// along with the generated argument and false otherwise.
func (ctx *context) recurseStructs(syzType *prog.StructType, dir prog.Dir, traceType *parser.GroupType) (prog.Arg, bool) {
	// only consider structs with one non-padded field
	numFields := 0
	for _, field := range syzType.Fields {
		if prog.IsPad(field.Type) {
			continue
		}
		numFields++
	}
	if numFields != 1 {
		return nil, false
	}
	// the strace group type needs to have more one field (a mismatch)
	if len(traceType.Elems) == 1 {
		return nil, false
	}
	// first field needs to be a struct
	switch t := syzType.Fields[0].Type.(type) {
	case *prog.StructType:
		var args []prog.Arg
		// first element and traceType should have the same number of elements
		if len(t.Fields) != len(traceType.Elems) {
			return nil, false
		}
		args = append(args, ctx.genStruct(t, dir, traceType))
		for _, field := range syzType.Fields[1:] {
			args = append(args, field.DefaultArg(field.Dir(dir)))
		}
		return prog.MakeGroupArg(syzType, dir, args), true
	}
	return nil, false
}

func (ctx *context) genUnionArg(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType) prog.Arg {
	if straceType == nil {
		log.Logf(1, "generating union arg. straceType is nil")
		return syzType.DefaultArg(dir)
	}
	log.Logf(4, "generating union arg: %s %#v", syzType.TypeName, straceType)

	// Unions are super annoying because they sometimes need to be handled case by case
	// We might need to lookinto a matching algorithm to identify the union type that most closely
	// matches our strace type.

	switch syzType.TypeName {
	case "sockaddr_storage":
		return ctx.genSockaddrStorage(syzType, dir, straceType)
	case "sockaddr_nl":
		return ctx.genSockaddrNetlink(syzType, dir, straceType)
	case "ifr_ifru":
		return ctx.genIfrIfru(syzType, dir, straceType)
	}
	return prog.MakeUnionArg(syzType, dir, ctx.genArg(syzType.Fields[0].Type, syzType.Fields[0].Dir(dir), straceType), 0)
}

func (ctx *context) genBuffer(syzType *prog.BufferType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	if dir == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, dir, syzType.Size())
		}
		switch a := traceType.(type) {
		case *parser.BufferType:
			return prog.MakeOutDataArg(syzType, dir, uint64(len(a.Val)))
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := 64
				if ctx.randomized {
					size = rand.Intn(256)
				}
				return prog.MakeOutDataArg(syzType, dir, uint64(size))

			case prog.BufferBlobRange:
				size := int(syzType.RangeBegin) + ((int(syzType.RangeEnd) - int(syzType.RangeBegin)) / 2)
				if ctx.randomized {
					max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
					size = max + int(syzType.RangeBegin)
				}
				return prog.MakeOutDataArg(syzType, dir, uint64(size))
			default:
				log.Fatalf("unexpected buffer type kind: %v. call %v arg %#v", syzType.Kind, ctx.currentSyzCall, traceType)
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *parser.BufferType:
		bufVal = []byte(a.Val)
	case parser.Constant:
		val := a.Val()
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *parser.GroupType:
		bufVal = []byte(a.String())
	default:
		log.Fatalf("unsupported type for buffer: %#v", traceType)
	}
	// strace always drops the null byte for buffer types but we only need to add it back for filenames and strings
	switch syzType.Kind {
	case prog.BufferFilename, prog.BufferString:
		bufVal = append(bufVal, '\x00')
	}
	if !syzType.Varlen() {
		size := syzType.Size()
		for uint64(len(bufVal)) < size {
			bufVal = append(bufVal, 0)
		}
		bufVal = bufVal[:size]
	}
	return prog.MakeDataArg(syzType, dir, bufVal)
}

func (ctx *context) genPtr(syzType *prog.PtrType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		if a.Val() == 0 {
			return prog.MakeSpecialPointerArg(syzType, dir, 0)
		}
		// Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := syzType.Elem.DefaultArg(syzType.ElemDir)
		return ctx.addr(syzType, dir, res.Size(), res)
	default:
		res := ctx.genArg(syzType.Elem, syzType.ElemDir, a)
		return ctx.addr(syzType, dir, res.Size(), res)
	}
}

func (ctx *context) genConst(syzType prog.Type, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		return prog.MakeConstArg(syzType, dir, a.Val())
	case *parser.GroupType:
		// Sometimes strace represents a pointer to int as [0] which gets parsed
		// as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]). We may also have an union int type that
		// is a represented as a struct in strace e.g.
		// sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		// For now we choose the first option
		if len(a.Elems) == 0 {
			log.Logf(2, "parsing const type, got array type with len 0")
			return syzType.DefaultArg(dir)
		}
		return ctx.genConst(syzType, dir, a.Elems[0])
	case *parser.BufferType:
		// strace decodes some arguments as hex strings because those values are network ordered
		// e.g. sin_port or sin_addr fields of sockaddr_in.
		// network order is big endian byte order so if the len of byte array is 1, 2, 4, or 8 then
		// it is a good chance that we are decoding one of those fields. If it isn't, then most likely
		// we have an error i.e. a sockaddr_un struct passed to a connect call with an inet file descriptor
		var val uint64
		toUint64 := binary.LittleEndian.Uint64
		toUint32 := binary.LittleEndian.Uint32
		toUint16 := binary.LittleEndian.Uint16
		if syzType.Format() == prog.FormatBigEndian {
			toUint64 = binary.BigEndian.Uint64
			toUint32 = binary.BigEndian.Uint32
			toUint16 = binary.BigEndian.Uint16
		}
		switch len(a.Val) {
		case 8:
			val = toUint64([]byte(a.Val))
		case 4:
			val = uint64(toUint32([]byte(a.Val)))
		case 2:
			val = uint64(toUint16([]byte(a.Val)))
		case 1:
			val = uint64(a.Val[0])
		default:
			return syzType.DefaultArg(dir)
		}
		return prog.MakeConstArg(syzType, dir, val)
	default:
		log.Fatalf("unsupported type for const: %#v", traceType)
	}
	return nil
}

func (ctx *context) genResource(syzType *prog.ResourceType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	if dir == prog.DirOut {
		log.Logf(2, "resource returned by call argument: %s", traceType.String())
		res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
		ctx.returnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if arg := ctx.returnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, dir, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		res := prog.MakeResultArg(syzType, dir, nil, val)
		return res
	case *parser.GroupType:
		if len(a.Elems) == 1 {
			// For example: 5028  ioctl(3, SIOCSPGRP, [0])          = 0
			// last argument is a pointer to a resource. Strace will output a pointer to
			// a number x as [x].
			res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
			ctx.returnCache.cache(syzType, a.Elems[0], res)
			return res
		}
		log.Fatalf("generating resource type from GroupType with %d elements", len(a.Elems))
	default:
		log.Fatalf("unsupported type for resource: %#v", traceType)
	}
	return nil
}

func (ctx *context) parseProc(syzType *prog.ProcType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, dir, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, dir, val)
	case *parser.BufferType:
		// Again probably an error case
		// Something like the following will trigger this
		// bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		return syzType.DefaultArg(dir)
	default:
		log.Fatalf("unsupported type for proc: %#v", traceType)
	}
	return nil
}

func (ctx *context) addr(syzType prog.Type, dir prog.Dir, size uint64, data prog.Arg) prog.Arg {
	return prog.MakePointerArg(syzType, dir, ctx.builder.Allocate(size, data.Type().Alignment()), data)
}

func shouldSkip(c *parser.Syscall) bool {
	switch c.CallName {
	// We skip all writes to stdout and stderr because they can corrupt our crash summary.
	case "write":
		switch a := c.Args[0].(type) {
		case parser.Constant:
			if a.Val() <= 2 {
				return true
			}
		}
	// Also there will be nothing on stdin, so any reads will hang.
	case "read":
		switch a := c.Args[0].(type) {
		case parser.Constant:
			if a.Val() <= 2 {
				return true
			}
		}
	}
	return unsupportedCalls[c.CallName]
}
