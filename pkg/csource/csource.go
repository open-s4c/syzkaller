// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package csource generates [almost] equivalent C programs from syzkaller programs.
//
// Outline of the process:
//   - inputs to the generation are the program and options
//   - options control multiple aspects of the resulting C program,
//     like if we want a multi-threaded program or a single-threaded,
//     what type of sandbox we want to use, if we want to setup net devices or not, etc
//   - we use actual executor sources as the base
//   - gen.go takes all executor/common*.h headers and bundles them into generated.go
//   - during generation we tear executor headers apart and take only the bits
//     we need for the current program/options, this is done by running C preprocessor
//     with particular set of defines so that the preprocessor removes unneeded
//     #ifdef SYZ_FOO sections
//   - then we generate actual syscall calls with the given arguments
//     based on the binary "encodingexec" representation of the program
//     (the same representation executor uses for interpretation)
//   - then we glue it all together
//   - as the last step we run some text post-processing on the resulting source code:
//     remove debug calls, replace exitf/fail with exit, hoist/sort/dedup includes,
//     remove duplicate empty lines, etc
package csource

import (
	"bytes"
	"fmt"
	"math/bits"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type NetOp int

const (
	NetRead NetOp = iota
	NetWrite
)

type NetOpSize struct {
	Op   NetOp
	Num  uint64
	Size uint64
}

var (
	missedFDResources = make(map[uint64](bool))
	connectFDs        = make(map[uint64](bool))
	acceptFDs         = make(map[uint64](bool))
	readFDSizes       = make(map[uint64](uint64))
	NetOpsFDs         = make(map[uint64]([]NetOpSize))
	NetOpsFDsConnect  = make(map[uint64]([]NetOpSize))
	NetOpsFDsAccept   = make(map[uint64]([]NetOpSize))
	listenFDs         = make(map[uint64](bool))
	initFDs           = make(map[uint64](bool))
)

func AddToNetOps(res uint64, op NetOp, size uint64) {
	netops, ok := NetOpsFDs[res]

	// no operation for this file descriptor recorded yet, initialize
	if !ok {
		NetOpsFDs[res] = make([]NetOpSize, 0)
		netops = NetOpsFDs[res]
	}

	// empty list of operations, or current operation is write -> append
	if len(netops) == 0 || op == NetWrite {
		nosNew := NetOpSize{op, 1, size}
		netops = append(netops, nosNew)
		NetOpsFDs[res] = netops
		return
	}

	// op is Read
	nosLast := netops[len(netops)-1]
	if nosLast.Op == NetWrite {
		nosNew := NetOpSize{op, 1, size}
		netops = append(netops, nosNew)
		NetOpsFDs[res] = netops
		return
	}

	// Last op was also Read, combine into total
	nosNew := NetOpSize{op, nosLast.Num + 1, nosLast.Size + size}
	netops[len(netops)-1] = nosNew
	NetOpsFDs[res] = netops
}

var netOpName = map[NetOp]string{
	NetRead:  "r",
	NetWrite: "w",
}

func (no NetOp) String() string {
	return netOpName[no]
}

func (nos NetOpSize) String() string {
	return strconv.FormatUint(nos.Num, 10) + netOpName[nos.Op] + strconv.FormatUint(nos.Size, 10)
}

func NetOpsString(res uint64, ops map[uint64][]NetOpSize) string {
	netops, ok := ops[res]
	var netopstring string
	// no operation for this file descriptor recorded yet, initialize
	if !ok {
		return ""
	}

	for idx, nos := range netops {
		if idx != 0 {
			netopstring += "-"
		}
		netopstring += nos.String()
	}
	return netopstring
}

// Write generates C source for program p based on the provided options opt.
func Write(p *prog.Prog, opts Options) (program []byte, metaData string, err error) {
	if err := opts.Check(p.Target.OS); err != nil {
		return nil, "", fmt.Errorf("csource: invalid opts: %w", err)
	}
	resetGenerationState()
	ctx := &context{
		p:         p,
		opts:      opts,
		target:    p.Target,
		sysTarget: targets.Get(p.Target.OS, p.Target.Arch),
		calls:     make(map[string]uint64),
	}
	return ctx.generateSource()
}

func resetGenerationState() {
	missedFDResources = make(map[uint64]bool)
	connectFDs = make(map[uint64]bool)
	acceptFDs = make(map[uint64]bool)
	readFDSizes = make(map[uint64]uint64)
	NetOpsFDs = make(map[uint64][]NetOpSize)
	NetOpsFDsConnect = make(map[uint64][]NetOpSize)
	NetOpsFDsAccept = make(map[uint64][]NetOpSize)
	listenFDs = make(map[uint64]bool)
	initFDs = make(map[uint64]bool)
}

type context struct {
	p         *prog.Prog
	opts      Options
	target    *prog.Target
	sysTarget *targets.Target
	calls     map[string]uint64 // CallName -> NR
}

func generateSandboxFunctionSignature(sandboxName string, sandboxArg int, ctx *context) string {
	if ctx.opts.CSB {
		if sandboxName == "" {
			return "LOOPUNIQUE" + "(ctx, op_id);"
		}
	} else {
		if sandboxName == "" {
			return "loop();"
		}

	}

	arguments := []string{}
	if sandboxName == "android" {
		arguments = append(arguments, strconv.Itoa(sandboxArg))
	}
	if ctx.opts.CSB {
		arguments = append(arguments, "ctx")
	}

	argumentsStr := "(" + strings.Join(arguments, ",") + ");"
	return "do_sandbox_" + sandboxName + argumentsStr
}

func (ctx *context) mapToArrayStringBool(inMap map[string]bool) string {
	keys := make([]string, 0, len(inMap))
	for key := range inMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, fmt.Sprintf("\"%s\"", key))
	}
	return strings.Join(values, ",")
}

func sortedUint64AnyKeys[V bool | uint64 | string | []NetOpSize](inMap map[uint64]V) []uint64 {
	keys := make([]uint64, 0, len(inMap))
	for key := range inMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}

func toStringArray[V uint64 | string | []NetOpSize](opMap map[uint64]V) (string, error) {
	opsSeq := make([]string, 0, len(opMap))
	for _, res := range sortedUint64AnyKeys(opMap) {

		v_string := ""
		switch val := any(opMap).(type) {
		case map[uint64]uint64:
			v_string = fmt.Sprint(val[res])

		case map[uint64]string:
			v_string = fmt.Sprintf("\"%s\"", val[res])

		case map[uint64][]NetOpSize:
			v_string = "\"" + NetOpsString(res, val) + "\""

		default:
			return "", fmt.Errorf("Unknown type for array to string conversion! %T\n", opMap)
		}

		opsSeq = append(opsSeq, v_string)
	}
	return strings.Join(opsSeq, ", "), nil
}

func (ctx *context) generateSource() ([]byte, string, error) {
	metaData := ""

	ctx.filterCalls()

	var excludeIdices []int

	netSrvListen := prog.CallAnnotationMarker{prog.LISTEN, "listen", prog.ENDINCLUDE}
	netSrvListenIdxs := ctx.p.GetAnnotationIndicesMarker(netSrvListen)
	if len(netSrvListenIdxs) > 0 {
		// got all indices of calls that use the listen socket in the program
		// fmt.Fprintf(os.Stderr, "Found LISTEN-listen indices:\n%#v\n", netSrvListenIdxs)
		excludeIdices = append(excludeIdices, netSrvListenIdxs...)
	}

	netSrvClose := prog.CallAnnotationMarker{prog.LISTEN, "close", prog.STARTINCLUDE}
	netSrvCloseIdxs := ctx.p.GetAnnotationIndicesMarker(netSrvClose)
	if len(netSrvCloseIdxs) > 0 {
		// got all indices of calls that use the listen socket in the program
		// fmt.Fprintf(os.Stderr, "Found LISTEN-close indices:\n%#v\n", netSrvCloseIdxs)
		excludeIdices = append(excludeIdices, netSrvCloseIdxs...)
	}

	calls, vars, err := ctx.generateProgCalls(ctx.p, ctx.opts.Trace, ctx.opts.CallComments, netSrvListenIdxs, false)
	if err != nil {
		return nil, metaData, err
	}

	mmapProg := ctx.p.Target.DataMmapProg()
	// Disable comments on the mmap calls as they are part of the initial setup
	// for a program and always very similar. Comments on these provide
	// little-to-no additional context that can't be inferred from looking at
	// the call arguments directly, and just make the source longer.
	mmapCalls, _, err := ctx.generateProgCalls(mmapProg, false, false, []int{}, true)
	if err != nil {
		return nil, metaData, err
	}

	for _, c := range append(mmapProg.Calls, ctx.p.Calls...) {
		ctx.calls[c.Meta.CallName] = c.Meta.NR
		for _, dep := range ctx.sysTarget.PseudoSyscallDeps[c.Meta.CallName] {
			depCall := ctx.target.SyscallMap[dep]
			if depCall == nil {
				panic(dep + " is specified in PseudoSyscallDeps, but not present")
			}
			ctx.calls[depCall.CallName] = depCall.NR
		}
	}

	varsBuf := new(bytes.Buffer)
	if !ctx.opts.CSB {
		if len(vars) != 0 {
			fmt.Fprintf(varsBuf, "uint64 UNIQUE_VAR(ctx->r)[%v] = {", len(vars))
			for i, v := range vars {
				if i != 0 {
					fmt.Fprintf(varsBuf, ", ")
				}
				fmt.Fprintf(varsBuf, "0x%x", v)
			}
			fmt.Fprintf(varsBuf, "};\n")
		}
	}

	// Leaking file descriptors
	closeBuf := new(bytes.Buffer)
	for _, fdRes := range sortedUint64AnyKeys(missedFDResources) {
		if !missedFDResources[fdRes] {
			continue
		}
		// only close file descriptors that are not part if the reg init function
		// TODO: check the potential usage of initFDs below, and in the whole file.
		if _, ok := listenFDs[fdRes]; !ok {
			if ctx.opts.CSB {
				fmt.Fprintf(closeBuf,
					"\t{ uint32 fd = (uint32)UNIQUE_VAR(ctx->r)[%[1]v]; if (fd > 2) close(fd); }\n", fdRes)
			} else {
				fmt.Fprintf(closeBuf, "\tclose(UNIQUE_VAR(ctx->r)[%v]);\n", fdRes)
			}
		}
	}

	// sub directories for mkdir
	subdirs := ctx.mapToArrayStringBool(ctx.opts.SubDirs)

	// file sizes for truncation
	filesizes, err := toStringArray(ctx.opts.FileSizes)
	if err != nil {
		return nil, "", err
	}

	// file names for truncation
	filenames, err := toStringArray(ctx.opts.FileNames)
	if err != nil {
		return nil, "", err
	}
	sandboxFunc := generateSandboxFunctionSignature(ctx.opts.Sandbox, ctx.opts.SandboxArg, ctx)

	results := varsBuf.String()

	// initialization of resource array in reg function
	var callsNetSrvReg []string
	if len(vars) > 0 {
		callsNetSrvReg = append(callsNetSrvReg, fmt.Sprintf("\tUNIQUE_VAR(ctx->r) = (uint64*)malloc(sizeof(uint64)*%d);\n", len(vars)))
		for i, v := range vars {
			callsNetSrvReg = append(callsNetSrvReg, fmt.Sprintf("\tUNIQUE_VAR(ctx->r)[%d] = 0x%x;\n", i, v))
		}
	}

	// put syscalls into reg function if their index is stored in netSrvListenIdxs
	for idx, call := range calls {
		if slices.Contains(netSrvListenIdxs, idx) {
			callsNetSrvReg = append(callsNetSrvReg, call)
		}
	}

	netSrvListenIdxsAll := ctx.p.GetAnnotationIndices(prog.LISTEN)
	netSrvAcceptIdxsAll := ctx.p.GetAnnotationIndices(prog.ACCEPT)
	// fmt.Fprintf(os.Stderr, "Accept idxs:\n%#v\n", netSrvAcceptIdxsAll)

	// generate c source for reg function
	syscallsNetSrvReg := ctx.generateSyscalls(callsNetSrvReg, len(vars) != 0)

	// use all but reg and dereg syscalls
	var callsNetSrvBody []string
	for idx, call := range calls {
		if slices.Contains(netSrvListenIdxs, idx) {
			continue
		}
		if slices.Contains(netSrvCloseIdxs, idx) {
			continue
		}
		if slices.Contains(netSrvListenIdxsAll, idx) && !slices.Contains(netSrvAcceptIdxsAll, idx) {
			continue
		}
		callsNetSrvBody = append(callsNetSrvBody, call)
	}
	syscallsBody := ctx.generateSyscalls(callsNetSrvBody, len(vars) != 0)

	// Get number of listen annotations
	var callsNetSrvDereg []string
	for _, rIdx := range sortedUint64AnyKeys(listenFDs) {
		callsNetSrvDereg = append(callsNetSrvDereg, fmt.Sprintf("\tclose(UNIQUE_VAR(ctx->r)[%d]);", rIdx))
	}
	callsNetSrvDereg = append(callsNetSrvDereg, "\tfree(UNIQUE_VAR(ctx->r));")
	syscallsNetSrvDereg := strings.Join(callsNetSrvDereg, "\n")

	syscalls := syscallsBody

	// Add close calls from leakage detector
	if ctx.opts.CSB {
		results = ""
		syscalls = varsBuf.String() + "\n" + syscalls + "\n" + closeBuf.String()
	}

	replacements := map[string]string{
		"PROCS":                  fmt.Sprint(ctx.opts.Procs),
		"REPEAT_TIMES":           fmt.Sprint(ctx.opts.RepeatTimes),
		"NUM_CALLS":              fmt.Sprint(len(ctx.p.Calls)),
		"MMAP_DATA":              strings.Join(mmapCalls, ""),
		"SYSCALL_DEFINES":        ctx.generateSyscallDefines(),
		"SANDBOX_FUNC":           sandboxFunc,
		"RESULTS":                results,
		"SYSCALLS":               syscalls,
		"SYSCALLS_NET_SRV_REG":   syscallsNetSrvReg,
		"SYSCALLS_NET_SRV_DEREG": syscallsNetSrvDereg,
		"NUM_NOP":                fmt.Sprint(ctx.opts.NumNop),
		"NUMSUBDIRS":             fmt.Sprint(len(ctx.opts.SubDirs)),
		"SUBDIRS":                subdirs,
		"NUMFILESIZES":           fmt.Sprint(len(ctx.opts.FileSizes)),
		"FILESIZES":              filesizes,
		"NUMFILENAMES":           fmt.Sprint(len(ctx.opts.FileNames)),
		"FILENAMES":              filenames,
	}

	if !ctx.opts.Threaded && !ctx.opts.Repeat && ctx.opts.Sandbox == "" {
		// This inlines syscalls right into main for the simplest case.
		replacements["SANDBOX_FUNC"] = replacements["SYSCALLS"]
		replacements["SYSCALLS"] = "unused"
	}

	timeouts := ctx.sysTarget.Timeouts(ctx.opts.Slowdown)
	replacements["PROGRAM_TIMEOUT_MS"] = fmt.Sprint(int(timeouts.Program / time.Millisecond))
	timeoutExpr := fmt.Sprint(int(timeouts.Syscall / time.Millisecond))
	replacements["BASE_CALL_TIMEOUT_MS"] = timeoutExpr
	for i, call := range ctx.p.Calls {
		if timeout := call.Meta.Attrs.Timeout; timeout != 0 {
			timeoutExpr += fmt.Sprintf(" + (call == %v ? %v : 0)", i, timeout*uint64(timeouts.Scale))
		}
	}
	replacements["CALL_TIMEOUT_MS"] = timeoutExpr
	if ctx.p.RequiredFeatures().Async {
		conditions := []string{}
		for idx, call := range ctx.p.Calls {
			if !call.Props.Async {
				continue
			}
			conditions = append(conditions, fmt.Sprintf("call == %v", idx))
		}
		replacements["ASYNC_CONDITIONS"] = strings.Join(conditions, " || ")
	}

	result, err := createCommonHeader(ctx.p, mmapProg, replacements, ctx.opts)
	if err != nil {
		return nil, metaData, err
	}
	header := "// autogenerated by syzkaller (https://github.com/google/syzkaller)\n"
	if ctx.opts.CSB {
		header += "// clang-format off\n"
		header += "#ifndef UNIQUE_ID\n"
		header += "#define UNIQUE_ID\n"
		header += "#endif\n"
		header += "#define RESOLVE(x) x\n"
		header += "#define BM_JOIN(a,b) a ## b\n"
		header += "#define BM_CAT(a,b) BM_JOIN(a,b)\n"
		header += "#define UNIQUE_ID_TOK_TOK(...) BM_CAT(__VA_OPT__(_),RESOLVE(UNIQUE_ID))\n"
		header += "#define UNIQUE_ID_TOK RESOLVE(UNIQUE_ID_TOK_TOK(RESOLVE(UNIQUE_ID)))\n"
		header += "#define UNIQUE_NAME(prefix, tok) BM_CAT(prefix,tok)\n"
		header += "#define UNIQUE_VAR(var) UNIQUE_NAME(var, RESOLVE(UNIQUE_ID_TOK))\n"
		header += "#define UNIQUE_FUNC(func) UNIQUE_NAME(func, RESOLVE(UNIQUE_ID_TOK))\n"
		header += "#define UNIQUE_GOTO(mark) UNIQUE_NAME(mark, RESOLVE(UNIQUE_ID_TOK))\n"
		header += "#define UNIQUE_STR_STR(str) #str\n"
		header += "#define UNIQUE_STR() UNIQUE_STR_STR(RESOLVE(UNIQUE_ID))\n"
		header += "#define MMAP_OFFSET " + fmt.Sprintf("0x%x", ctx.target.DataOffset) + "ul\n"
		header += "#define MMAP_LENGTH " + fmt.Sprintf("0x%x", ctx.target.NumPages*ctx.target.PageSize) + "ul\n"
		header += "const static uint64_t UNIQUE_VAR(maxWriteBufferSize) = " + fmt.Sprintf("%d", ctx.opts.MaxWriteSize) + "ul;\n"
		header += "const static uint64_t UNIQUE_VAR(maxWriteBufferSizeAlignment) = " + fmt.Sprintf("%d", ctx.opts.MaxWriteSizeAlignment) + "ul;\n"

		// Connect NetOps
		opsSeq, err := toStringArray(NetOpsFDsConnect)
		if err != nil {
			return nil, "", err
		}
		header += fmt.Sprintf("const char* UNIQUE_VAR(netops_connect)[%d] = {%s};\n", len(NetOpsFDsConnect), opsSeq)
		// Add to meta data if there is networking sequence
		if opsSeq != "" {
			metaData += fmt.Sprintf("CLIENT_SEQ=%s\n", opsSeq)
		}

		// Accept NetOps
		opsSeq, err = toStringArray(NetOpsFDsAccept)
		if err != nil {
			return nil, "", err
		}
		header += fmt.Sprintf("const char* UNIQUE_VAR(netops_accept)[%d] = {%s};\n", len(NetOpsFDsAccept), opsSeq)
		// Add to meta data if there is networking sequence
		if opsSeq != "" {
			metaData += fmt.Sprintf("SERVER_SEQ=%s\n", opsSeq)
		}
	}
	header += "\n"
	result = append([]byte(header), result...)
	result = ctx.postProcess(result)
	return result, metaData, nil
}

// This is a kludge, but we keep it here until a better approach is implemented.
// TODO: untie syz_emit_ethernet/syz_extract_tcp_res and NetInjection. And also
// untie VhciInjection and syz_emit_vhci. Then we could remove this method.
func (ctx *context) filterCalls() {
	p := ctx.p
	for i := 0; i < len(p.Calls); {
		call := p.Calls[i]
		callName := call.Meta.CallName
		emitCall := (ctx.opts.NetInjection ||
			callName != "syz_emit_ethernet" &&
				callName != "syz_extract_tcp_res") &&
			(ctx.opts.VhciInjection || callName != "syz_emit_vhci")
		if emitCall {
			i++
			continue
		}
		// Remove the call.
		if ctx.p == p {
			// We lazily clone the program to avoid unnecessary copying.
			p = ctx.p.Clone()
		}
		p.RemoveCall(i)
	}
	ctx.p = p
}

func (ctx *context) generateSyscalls(calls []string, hasVars bool) string {
	opts := ctx.opts
	buf := new(bytes.Buffer)
	if !opts.Threaded && !opts.Collide {
		// Keep generateCalls' one-to-one mapping between program calls and
		// generated fragments intact until annotation-based filtering is done.
		// Threaded generation also needs that mapping for its switch cases.
		if opts.RuntimeLoops {
			calls = loopIdenticalCalls(calls, opts.RuntimeLoopMin)
		}
		if len(calls) > 0 && (hasVars || opts.Trace) {
			fmt.Fprintf(buf, "\tintptr_t res = 0;\n")
			if opts.CSB {
				fmt.Fprintf(buf, "\tV_UNUSED(res);\n")
			}
		}
		if !ctx.opts.CSB {
			fmt.Fprintf(buf, "\tif (write(1, \"executing program\\n\", sizeof(\"executing program\\n\") - 1)) {}\n")
			if opts.Trace {
				fmt.Fprintf(buf, "\tfprintf(stderr, \"### start\\n\");\n")
			}
		}
		for _, c := range calls {
			fmt.Fprintf(buf, "%s", c)
		}
	} else if len(calls) > 0 {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tintptr_t res = 0;\n")
		}
		fmt.Fprintf(buf, "\tswitch (call) {\n")
		for i, c := range calls {
			fmt.Fprintf(buf, "\tcase %v:\n", i)
			fmt.Fprintf(buf, "%s", strings.ReplaceAll(c, "\t", "\t\t"))
			fmt.Fprintf(buf, "\t\tbreak;\n")
		}
		fmt.Fprintf(buf, "\t}\n")
	}
	return buf.String()
}

func (ctx *context) generateSyscallDefines() string {
	var calls []string
	for name, nr := range ctx.calls {
		if !ctx.sysTarget.HasCallNumber(name) || !ctx.sysTarget.NeedSyscallDefine(nr) {
			continue
		}
		calls = append(calls, name)
	}
	sort.Strings(calls)
	buf := new(bytes.Buffer)
	prefix := ctx.sysTarget.SyscallPrefix
	for _, name := range calls {
		fmt.Fprintf(buf, "#ifndef %v%v\n", prefix, name)
		fmt.Fprintf(buf, "#define %v%v %v\n", prefix, name, ctx.calls[name])
		fmt.Fprintf(buf, "#endif\n")
	}
	if ctx.target.OS == targets.Linux && ctx.target.PtrSize == 4 {
		// This is a dirty hack.
		// On 32-bit linux mmap translated to old_mmap syscall which has a different signature.
		// mmap2 has the right signature. syz-extract translates mmap to mmap2, do the same here.
		fmt.Fprintf(buf, "#undef __NR_mmap\n")
		fmt.Fprintf(buf, "#define __NR_mmap __NR_mmap2\n")
	}
	return buf.String()
}

const indent string = "  " // Two spaces.
// clang-format produces nicer comments with '//' prefixing versus '/* ... */' style comments.
const commentPrefix string = "//"

func linesToCStyleComment(lines []string) string {
	var commentBuilder strings.Builder
	for i, line := range lines {
		commentBuilder.WriteString(commentPrefix + indent + line)
		if i != len(lines)-1 {
			commentBuilder.WriteString("\n")
		}
	}
	return commentBuilder.String()
}

func generateComment(call *prog.Call) string {
	lines := []string{fmt.Sprintf("%s arguments: [", call.Meta.Name)}
	for i, arg := range call.Args {
		argLines := prog.FormatArg(arg, call.Meta.Args[i].Name)
		// Indent the formatted argument.
		for i := range argLines {
			argLines[i] = indent + argLines[i]
		}
		lines = append(lines, argLines...)
	}
	lines = append(lines, "]")
	if call.Ret != nil {
		lines = append(lines, "returns "+call.Ret.Type().Name())
	}
	return linesToCStyleComment(lines)
}

func (ctx *context) generateProgCalls(p *prog.Prog, trace, addComments bool, initIndices []int,
	dataMmap bool) ([]string, []uint64, error) {
	msgSizes := make([]uint64, len(p.Calls))
	var comments []string
	if addComments {
		comments = make([]string, len(p.Calls))
		for i, call := range p.Calls {
			comments[i] = generateComment(call)
		}
	}

	// generate sendmsg, recvmsg sizes
	for i, call := range p.Calls {
		if call.Meta.CallName == "recvmsg" || call.Meta.CallName == "sendmsg" {
			if len(call.Args) <= 1 {
				continue
			}
			arg1, ok := call.Args[1].(*prog.PointerArg)
			if !ok {
				continue
			}
			msghdr, ok := arg1.Res.(*prog.GroupArg)
			if !ok {
				continue
			}
			if len(msghdr.Inner) <= 3 {
				continue
			}

			// arg3 is array of iovec *msg_iov
			iovPtr, ok := msghdr.Inner[3].(*prog.PointerArg)
			if !ok {
				continue
			}
			iovGroup, ok := iovPtr.Res.(*prog.GroupArg)
			if !ok {
				continue
			}

			// arg4 is number of iovec *msg_iov
			// data4 := msghdr[4].(*prog.ConstArg).Val

			totalLength := uint64(0)
			for _, msg := range iovGroup.Inner {
				iov, ok := msg.(*prog.GroupArg)
				if !ok {
					continue
				}
				if len(iov.Inner) <= 1 {
					continue
				}
				msglen, ok := iov.Inner[1].(*prog.ConstArg)
				if !ok {
					continue
				}
				totalLength += msglen.Val
			}

			msgSizes[i] = totalLength
		}
	}

	exec, err := p.SerializeForExec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize program: %w", err)
	}
	decoded, err := ctx.target.DeserializeExec(exec, nil)
	if err != nil {
		return nil, nil, err
	}
	calls, vars := ctx.generateCalls(decoded, trace, addComments, comments, msgSizes, initIndices, dataMmap)
	return calls, vars, nil
}

func (ctx *context) generateCalls(p prog.ExecProg, trace, addComments bool,
	callComments []string, msgSizes []uint64, initIndices []int, dataMmap bool) ([]string, []uint64) {
	var calls []string
	csumSeq := 0
	localIO := localIOResources(p, ctx.target)
	for ci, call := range p.Calls {
		w := new(bytes.Buffer)
		if addComments {
			w.WriteString(callComments[ci] + "\n")
		}
		// Copyin.
		for _, copyin := range call.Copyin {
			ctx.copyin(w, &csumSeq, copyin)
		}
		csbFIONBIO := false
		if ctx.opts.CSB && call.Meta.CallName == "ioctl" && len(call.Args) > 2 &&
			localIOArg(call, localIO) {
			cmd, cmdOK := call.Args[1].(prog.ExecArgConst)
			value, valueOK := call.Args[2].(prog.ExecArgConst)
			if cmdOK && valueOK && cmd.Value == ctx.target.ConstMap["FIONBIO"] && valInMMapRange(ctx, value.Value) {
				csbFIONBIO = true
				fmt.Fprintf(w, "\tuint32 csb_fionbio_%d = 1;\n", ci)
			}
		}
		if ctx.opts.CSB && call.Meta.CallName == "openat2" {
			how, known := ctx.openat2How(ci)
			if known && how[0]&ctx.target.ConstMap["O_PATH"] == 0 {
				how[0] |= ctx.target.ConstMap["O_NONBLOCK"]
			}
			fmt.Fprintf(w, "\t{\n\tstruct { uint64 flags; uint64 mode; uint64 resolve; } "+
				"csb_open_how_%[1]d = {%[2]d, %[3]d, %[4]d};\n", ci, how[0], how[1], how[2])
		}
		if call.Props.FailNth > 0 {
			fmt.Fprintf(w, "\tinject_fault(%v);\n", call.Props.FailNth)
		}
		// Call itself.
		resCopyout := call.Index != prog.ExecNoCopyout
		argCopyout := len(call.Copyout) != 0

		initCall := false
		if slices.Contains(initIndices, ci) {
			initCall = true
		}
		forceNonblockArg := -1
		if ctx.opts.CSB && fcntlCommand(call, ctx.target.ConstMap["F_SETFL"]) && localIOArg(call, localIO) {
			args := append([]prog.ExecArg(nil), call.Args...)
			if flags, ok := args[2].(prog.ExecArgConst); ok {
				flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
				args[2] = flags
				call.Args = args
			} else if _, ok := args[2].(prog.ExecArgResult); ok {
				forceNonblockArg = 2
			}
		}
		csbMQAttr := false
		if ctx.opts.CSB && call.Meta.CallName == "mq_getsetattr" && localIOArg(call, localIO) {
			if attr, ok := call.Args[1].(prog.ExecArgConst); ok && valInMMapRange(ctx, attr.Value) {
				csbMQAttr = true
				fmt.Fprintf(w, "\tstruct { intptr_t flags; intptr_t maxmsg; intptr_t msgsize; intptr_t curmsgs; "+
					"intptr_t reserved[4]; } "+
					"csb_mq_attr_%[1]d = {%[2]d, 0, 0, 0};\n", ci, ctx.target.ConstMap["O_NONBLOCK"])
			}
		}
		if ctx.opts.CSB && ctx.target.OS == targets.Linux {
			// Opening a FIFO for one end only must not stall a generated workload.
			flagArg := -1
			switch call.Meta.CallName {
			case "open":
				flagArg = 1
			case "openat":
				flagArg = 2
			case "mq_open":
				flagArg = 1
			case "creat":
				var flags prog.ExecArgConst
				switch mode := call.Args[1].(type) {
				case prog.ExecArgConst:
					flags.Size, flags.Format = mode.Size, mode.Format
				case prog.ExecArgResult:
					flags.Size, flags.Format = mode.Size, mode.Format
				}
				flags.Value = ctx.target.ConstMap["O_WRONLY"] | ctx.target.ConstMap["O_CREAT"] |
					ctx.target.ConstMap["O_TRUNC"] | ctx.target.ConstMap["O_NONBLOCK"]
				call.Meta = ctx.target.SyscallMap["open"]
				call.Args = []prog.ExecArg{call.Args[0], flags, call.Args[1]}
			}
			if flagArg != -1 {
				args := append([]prog.ExecArg(nil), call.Args...)
				if flags, ok := args[flagArg].(prog.ExecArgConst); ok {
					flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
					args[flagArg] = flags
					call.Args = args
				} else if _, ok := args[flagArg].(prog.ExecArgResult); ok {
					forceNonblockArg = flagArg
				}
			}
		}

		dynamicFcntlCommand := ctx.opts.CSB && call.Meta.CallName == "fcntl" &&
			localIOArg(call, localIO) && len(call.Args) > 1
		if dynamicFcntlCommand {
			_, dynamicFcntlCommand = call.Args[1].(prog.ExecArgResult)
		}
		if dynamicFcntlCommand {
			cmd := ctx.resultArgToStr(call.Args[1].(prog.ExecArgResult))
			fmt.Fprintf(w, "\tintptr_t csb_fcntl_cmd_%d = %s;\n", ci, cmd)
		}
		ctx.emitCall(w, call, ci, resCopyout || argCopyout, trace, initCall,
			forceNonblockArg, dynamicFcntlCommand, csbFIONBIO, csbMQAttr, dataMmap)
		if call.Props.Rerun > 0 {
			fmt.Fprintf(w, "\tfor (int i = 0; i < %v; i++) {\n", call.Props.Rerun)
			// Rerun invocations should not affect the result value.
			ctx.emitCall(w, call, ci, false, false, initCall, forceNonblockArg,
				dynamicFcntlCommand, csbFIONBIO, csbMQAttr, dataMmap)
			fmt.Fprintf(w, "\t}\n")
		}
		if ctx.opts.CSB && call.Meta.CallName == "openat2" {
			fmt.Fprintf(w, "\t}\n")
		}
		// Copyout.
		if resCopyout || argCopyout {
			ctx.copyout(w, call, ci, resCopyout, localIO, dynamicFcntlCommand)
		}
		calls = append(calls, w.String())

		// get resource indices for filedescriptor related calls
		if resCopyout {
			fdRes := call.Index
			missedFDResources[fdRes] = true
		}

		callName, ok := ctx.sysTarget.SyscallTrampolines[call.Meta.CallName]
		if !ok {
			callName = call.Meta.CallName
		}
		if callName == "close" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				missedFDResources[fdRes] = false
			}
		}

		if callName == "read" || callName == "pread" || callName == "pread64" || callName == "recv" || callName == "recvfrom" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				arg2 := call.Args[2]
				size := arg2.(prog.ExecArgConst).Value
				AddToNetOps(fdRes, NetRead, size)
			}
		}

		if callName == "recvmsg" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				AddToNetOps(fdRes, NetRead, msgSizes[ci])
			}
		}

		if callName == "write" || callName == "pwrite" || callName == "pwrite64" || callName == "send" || callName == "sendto" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				arg2 := call.Args[2]
				size := arg2.(prog.ExecArgConst).Value
				AddToNetOps(fdRes, NetWrite, size)
			}
		}

		if callName == "sendmsg" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				AddToNetOps(fdRes, NetWrite, msgSizes[ci])
			}
		}

		if callName == "connect" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				connectFDs[fdRes] = true
			}
		}

		if callName == "listen" {
			if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
				listenFDs[fdRes] = true
			}
		}

		if callName == "accept" || callName == "accept4" {
			fdRes := call.Index

			acceptFDs[fdRes] = true
		}
	}

	// remove resources from network ops which are not created by a connect

	tmpOps := make(map[uint64]([]NetOpSize))
	for res := range connectFDs {
		nop, ok := NetOpsFDs[res]
		if ok {
			tmpOps[res] = nop
		}
	}

	NetOpsFDsConnect = tmpOps

	tmpOps = make(map[uint64]([]NetOpSize))
	for _, res := range sortedUint64AnyKeys(acceptFDs) {
		nop, ok := NetOpsFDs[res]
		if ok {
			tmpOps[res] = nop
		}
	}

	NetOpsFDsAccept = tmpOps

	return calls, p.Vars
}

func execArgResultIndex(arg prog.ExecArg) (uint64, bool) {
	result, ok := arg.(prog.ExecArgResult)
	return result.Index, ok
}

func localIOResources(p prog.ExecProg, target *prog.Target) map[uint64]bool {
	local := make(map[uint64]bool)
	for _, call := range p.Calls {
		switch call.Meta.CallName {
		case "open", "openat", "openat2", "creat", "mq_open", "eventfd", "eventfd2", "timerfd_create", "inotify_init", "inotify_init1", "fanotify_init", "userfaultfd", "signalfd", "signalfd4":
			if call.Index != prog.ExecNoCopyout {
				local[call.Index] = true
			}
		case "pipe", "pipe2", "socketpair":
			for _, copyout := range call.Copyout {
				local[copyout.Index] = true
			}
		case "dup", "dup2", "dup3":
			if call.Index != prog.ExecNoCopyout && localIOArg(call, local) {
				local[call.Index] = true
			}
		case "fcntl":
			duplicate := fcntlCommand(call, target.ConstMap["F_DUPFD"]) ||
				fcntlCommand(call, target.ConstMap["F_DUPFD_CLOEXEC"])
			if _, dynamic := call.Args[1].(prog.ExecArgResult); dynamic {
				// A dynamic command may duplicate a local descriptor at runtime.
				duplicate = true
			}
			if duplicate &&
				call.Index != prog.ExecNoCopyout && localIOArg(call, local) {
				local[call.Index] = true
			}
		}
	}
	return local
}

func fcntlCommand(call prog.ExecCall, command uint64) bool {
	if call.Meta.CallName != "fcntl" || len(call.Args) < 2 {
		return false
	}
	arg, ok := call.Args[1].(prog.ExecArgConst)
	return ok && arg.Value == command
}

func localIOArg(call prog.ExecCall, local map[uint64]bool) bool {
	if len(call.Args) == 0 {
		return false
	}
	arg, ok := call.Args[0].(prog.ExecArgResult)
	return ok && arg.DivOp == 0 && arg.AddOp == 0 && local[arg.Index]
}

func loopIdenticalCalls(calls []string, minRun int) []string {
	if minRun <= 1 {
		minRun = 2
	}
	var out []string
	for i := 0; i < len(calls); {
		j := i + 1
		for j < len(calls) && calls[j] == calls[i] {
			j++
		}
		if run := j - i; run >= minRun {
			out = append(out, fmt.Sprintf("\tfor (size_t csb_runtime_loop = 0; csb_runtime_loop < %d; csb_runtime_loop++) {\n%s\t}\n", run, calls[i]))
		} else {
			out = append(out, calls[i:j]...)
		}
		i = j
	}
	return out
}

func isNative(sysTarget *targets.Target, callName string) bool {
	_, trampoline := sysTarget.SyscallTrampolines[callName]
	return sysTarget.HasCallNumber(callName) && !trampoline
}

func (ctx *context) emitCall(w *bytes.Buffer, call prog.ExecCall, ci int, haveCopyout, trace, initCall bool,
	forceNonblockArg int, dynamicFcntlCommand, csbFIONBIO, csbMQAttr, dataMmap bool) {
	native := isNative(ctx.sysTarget, call.Meta.CallName)
	fmt.Fprintf(w, "\t")
	if !native {
		// This mimics the same as executor does for execute_syscall,
		// but only for non-native syscalls to reduce clutter (native syscalls are assumed to not crash).
		// Arrange for res = -1 in case of syscall abort, we care about errno only if we are tracing for pkg/runtest.
		if haveCopyout || trace {
			fmt.Fprintf(w, "res = -1;\n\t")
		}
		if trace {
			fmt.Fprintf(w, "errno = EFAULT;\n\t")
		}
		fmt.Fprintf(w, "NONFAILING(")
	}
	if haveCopyout || trace {
		fmt.Fprintf(w, "res = ")
	}
	w.WriteString(ctx.fmtCallBody(call, initCall, ci, forceNonblockArg, dynamicFcntlCommand,
		csbFIONBIO, csbMQAttr, dataMmap))
	if !native {
		fmt.Fprintf(w, ")") // close NONFAILING macro
	}
	fmt.Fprintf(w, ";")
	comment := ctx.target.AnnotateCall(call)
	if comment != "" {
		fmt.Fprintf(w, " /* %s */", comment)
	}
	fmt.Fprintf(w, "\n")
	if trace {
		cast := ""
		if !native && !strings.HasPrefix(call.Meta.CallName, "syz_") {
			// Potentially we casted a function returning int to a function returning intptr_t.
			// So instead of intptr_t -1 we can get 0x00000000ffffffff. Sign extend it to intptr_t.
			cast = "(intptr_t)(int)"
		}
		if ctx.opts.CSB {
			fmt.Fprintf(w, "\tif (res == -1 ) { assert(!abort_on_fail); UNIQUE_VAR(ctx->num_failed)++;} else {UNIQUE_VAR(ctx->num_succeeded)++;};\n")
		} else {
			fmt.Fprintf(w, "\tfprintf(stderr, \"### call=%v errno=%%u\\n\", %vres == -1 ? errno : 0);\n", ci, cast)
		}
	}
}

func valInMMapRange(ctx *context, val uint64) bool {
	min := ctx.sysTarget.DataOffset
	max := min + ctx.target.NumPages*ctx.target.PageSize

	// The CSB mapping is exactly [min, max); adjacent values are not pointers into it.
	return val >= min && val < max
}

func (ctx *context) openat2How(ci int) ([3]uint64, bool) {
	fallback := [3]uint64{ctx.target.ConstMap["O_PATH"] | ctx.target.ConstMap["O_CLOEXEC"]}
	if ci >= len(ctx.p.Calls) || len(ctx.p.Calls[ci].Args) < 3 {
		return fallback, false
	}
	ptr, ok := ctx.p.Calls[ci].Args[2].(*prog.PointerArg)
	if !ok || ptr.Res == nil {
		return fallback, false
	}
	how, ok := ptr.Res.(*prog.GroupArg)
	if !ok || len(how.Inner) < 3 {
		return fallback, false
	}
	values := [3]uint64{}
	for i := range values {
		field, ok := how.Inner[i].(*prog.ConstArg)
		if !ok {
			return fallback, false
		}
		values[i] = field.Val
	}
	return values, true
}

func (ctx *context) rewriteCSBOpenat2Arg(call prog.ExecCall, argIndex, callIndex int, value string) string {
	if !ctx.opts.CSB || call.Meta.CallName != "openat2" {
		return value
	}
	switch argIndex {
	case 2:
		return fmt.Sprintf("(intptr_t)&csb_open_how_%d", callIndex)
	case 3:
		return fmt.Sprintf("sizeof(csb_open_how_%d)", callIndex)
	default:
		return value
	}
}

func (ctx *context) fmtCallBody(call prog.ExecCall, initCall bool, ci int, forceNonblockArg int,
	dynamicFcntlCommand, csbFIONBIO, csbMQAttr, dataMmap bool) string {
	native := isNative(ctx.sysTarget, call.Meta.CallName)
	callName, ok := ctx.sysTarget.SyscallTrampolines[call.Meta.CallName]
	if !ok {
		callName = call.Meta.CallName
	}
	argsStrs := []string{}
	funcName := ""
	if native {
		funcName = "syscall"
		argsStrs = append(argsStrs, ctx.sysTarget.SyscallPrefix+callName)
	} else if strings.HasPrefix(callName, "syz_") {
		funcName = callName
		// Multiple generated CSB headers share a translation unit, so calls must
		// use the same header-local name as their UNIQUE_FUNC declarations.
		if ctx.opts.CSB && (strings.HasPrefix(callName, "syz_csb_") ||
			callName == "syz_reapply_affinity") {
			funcName = fmt.Sprintf("UNIQUE_FUNC(%v)", callName)
		}
	} else {
		args := strings.Repeat(",intptr_t", len(call.Args)+call.Meta.MissingArgs)
		if args != "" {
			args = args[1:]
		}
		funcName = fmt.Sprintf("((intptr_t(*)(%v))CAST(%v))", args, callName)
	}

	for i, arg := range call.Args {
		if ctx.opts.CSB {
			switch i {
			// argument index 0
			case 0:
				//TODO: check if argument is dirfd already and keep it in that case
				switch callName {
				case "readlinkat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "openat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "faccessat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "faccessat2":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "newfstatat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "unlinkat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "mknodat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "fchownat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				case "fchmodat":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->dirfd)")
					continue
				}
			// argument index 1
			case 1:
				switch call.Meta.Name {
				case "connect$inet":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->connect4_arg)")
					continue
				case "bind$inet":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->bind4_arg)")
					continue
				case "connect$inet6":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->connect6_arg)")
					continue
				case "bind$inet6":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->bind6_arg)")
					continue
				}
			case 2:
				switch call.Meta.Name {
				case "connect$inet":
					argsStrs = append(argsStrs, "sizeof(*(UNIQUE_VAR(ctx->connect4_arg)))")
					continue
				case "bind$inet":
					argsStrs = append(argsStrs, "sizeof(*(UNIQUE_VAR(ctx->bind4_arg)))")
					continue
				case "connect$inet6":
					argsStrs = append(argsStrs, "sizeof(*(UNIQUE_VAR(ctx->connect6_arg)))")
					continue
				case "bind$inet6":
					argsStrs = append(argsStrs, "sizeof(*(UNIQUE_VAR(ctx->bind6_arg)))")
					continue
				case "bind$unix":
					argsStrs = append(argsStrs, "sizeof(sa_family_t)")
					continue
				}
			}
			if i == 1 {
				switch callName {
				case "write", "pwrite64", "send", "sendto":
					argsStrs = append(argsStrs, "UNIQUE_VAR(ctx->writeBuffer)")
					continue
				}
			}
		}

		switch arg := arg.(type) {
		case prog.ExecArgConst:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("string format in syscall argument")
			}
			com := ctx.argComment(call.Meta.Args[i], arg)

			PTR_OFFSET_STR := ""

			// DataMmapProg includes adjacent guard pages that move with the mapping.
			if ctx.opts.CSB && ((dataMmap && i == 0) ||
				(call.Meta.Name == "ioctl$auto_FIONBIO" && i == 2 &&
					valInMMapRange(ctx, arg.Value)) ||
				(arg.IsPointer && valInMMapRange(ctx, arg.Value))) {
				PTR_OFFSET_STR = "+PTR_OFFSET"
			}

			value := handleBigEndian(arg, ctx.constArgToStr(arg, native)) + PTR_OFFSET_STR
			value = ctx.rewriteCSBOpenat2Arg(call, i, ci, value)
			if csbFIONBIO && i == 2 {
				value = fmt.Sprintf("(intptr_t)&csb_fionbio_%d", ci)
			}
			if csbMQAttr && i == 1 {
				value = fmt.Sprintf("(intptr_t)&csb_mq_attr_%d", ci)
			}
			if dynamicFcntlCommand && i == 2 {
				value = fmt.Sprintf("(csb_fcntl_cmd_%d == F_SETFL ? (%s | O_NONBLOCK) : %s)", ci, value, value)
			}
			argsStrs = append(argsStrs, ctx.protectCSBControlFD(callName, i, com+value))
		case prog.ExecArgResult:
			if initCall {
				initFDs[arg.Index] = true
			}
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("string format in syscall argument")
			}
			com := ctx.argComment(call.Meta.Args[i], arg)
			val := ctx.resultArgToStr(arg)
			if dynamicFcntlCommand && i == 1 {
				val = fmt.Sprintf("csb_fcntl_cmd_%d", ci)
			}
			if dynamicFcntlCommand && i == 2 {
				val = fmt.Sprintf("(csb_fcntl_cmd_%d == F_SETFL ? (%s | O_NONBLOCK) : %s)", ci, val, val)
			}
			if forceNonblockArg == i {
				val = fmt.Sprintf("(%s | O_NONBLOCK)", val)
			}
			val = ctx.rewriteCSBOpenat2Arg(call, i, ci, val)
			if native && ctx.target.PtrSize == 4 {
				// syscall accepts args as ellipsis, resources are uint64
				// and take 2 slots without the cast, which would be wrong.
				val = "(intptr_t)" + val
			}
			argsStrs = append(argsStrs, ctx.protectCSBControlFD(callName, i, com+val))
		default:
			panic(fmt.Sprintf("unknown arg type: %+v", arg))
		}
	}
	for i := 0; i < call.Meta.MissingArgs; i++ {
		argsStrs = append(argsStrs, "0")
	}
	if ctx.opts.CSB && (callName == "dup2" || callName == "dup3") {
		argOffset := 0
		if native {
			argOffset = 1
		}
		src, dst := argsStrs[argOffset], argsStrs[argOffset+1]
		argsStrs[argOffset] = "csb_dup_src"
		argsStrs[argOffset+1] = "((uint32)csb_dup_dst <= 2 && (uint32)csb_dup_src != (uint32)csb_dup_dst ? -1 : csb_dup_dst)"
		return fmt.Sprintf("({ intptr_t csb_dup_src = (%s); intptr_t csb_dup_dst = (%s); %v(%v); })",
			src, dst, funcName, strings.Join(argsStrs, ", "))
	}
	return fmt.Sprintf("%v(%v)", funcName, strings.Join(argsStrs, ", "))
}

func (ctx *context) protectCSBControlFD(callName string, arg int, val string) string {
	if !ctx.opts.CSB {
		return val
	}
	// CSB uses stdin/stdout/stderr to control and report benchmark operations.
	if callName == "close" && arg == 0 {
		return fmt.Sprintf("({ intptr_t csb_fd = (%s); (uint32)csb_fd <= 2 ? -1 : csb_fd; })", val)
	}
	if callName == "close_range" && arg == 0 {
		return fmt.Sprintf("({ intptr_t csb_fd = (%s); (uint32)csb_fd <= 2 ? 3 : csb_fd; })", val)
	}
	return val
}

func (ctx *context) generateCsumInet(w *bytes.Buffer, addr uint64, arg prog.ExecArgCsum, csumSeq int) {
	fmt.Fprintf(w, "\tstruct csum_inet csum_%d;\n", csumSeq)
	fmt.Fprintf(w, "\tcsum_inet_init(&csum_%d);\n", csumSeq)
	for i, chunk := range arg.Chunks {
		switch chunk.Kind {
		case prog.ExecArgCsumChunkData:
			fmt.Fprintf(w, "\tNONFAILING(csum_inet_update(&csum_%d, (const uint8*)(0x%xul%v), %d));\n",
				csumSeq, chunk.Value, ctx.ptrOffset(chunk.Value), chunk.Size)
		case prog.ExecArgCsumChunkConst:
			fmt.Fprintf(w, "\tuint%d csum_%d_chunk_%d = 0x%x;\n",
				chunk.Size*8, csumSeq, i, chunk.Value)
			fmt.Fprintf(w, "\tcsum_inet_update(&csum_%d, (const uint8*)&csum_%d_chunk_%d, %d);\n",
				csumSeq, csumSeq, i, chunk.Size)
		default:
			panic(fmt.Sprintf("unknown checksum chunk kind %v", chunk.Kind))
		}
	}
	fmt.Fprintf(w, "\tNONFAILING(*(uint16*)(0x%xul%v) = csum_inet_digest(&csum_%d));\n",
		addr, ctx.ptrOffset(addr), csumSeq)
}

func (ctx *context) ptrOffset(addr uint64) string {
	if ctx.opts.CSB && valInMMapRange(ctx, addr) {
		return "+PTR_OFFSET"
	}
	return ""
}

func (ctx *context) copyin(w *bytes.Buffer, csumSeq *int, copyin prog.ExecCopyin) {
	PTR_OFFSET_STR_ADDR := ""
	if ctx.opts.CSB && valInMMapRange(ctx, copyin.Addr) {
		PTR_OFFSET_STR_ADDR = "+PTR_OFFSET"
	}

	switch arg := copyin.Arg.(type) {
	case prog.ExecArgConst:
		if arg.BitfieldOffset == 0 && arg.BitfieldLength == 0 {
			ctx.copyinVal(w, copyin.Addr, arg.Size, handleBigEndian(arg, ctx.constArgToStr(arg, false)), arg.Format,
				arg.IsPointer && valInMMapRange(ctx, arg.Value))
		} else {
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("bitfield+string format")
			}
			htobe := ""
			if !ctx.target.BigEndian && arg.Format == prog.FormatBigEndian {
				htobe = fmt.Sprintf("htobe%v", arg.Size*8)
			}
			bitfieldOffset := arg.BitfieldOffset
			if ctx.target.BigEndian {
				bitfieldOffset = arg.Size*8 - arg.BitfieldOffset - arg.BitfieldLength
			}
			fmt.Fprintf(w, "\tNONFAILING(STORE_BY_BITMASK(uint%v, %v, 0x%xul%v, %v, %v, %v));\n",
				arg.Size*8, htobe, copyin.Addr, PTR_OFFSET_STR_ADDR, ctx.constArgToStr(arg, false),
				bitfieldOffset, arg.BitfieldLength)
		}
	case prog.ExecArgResult:
		ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.resultArgToStr(arg), arg.Format, false)
	case prog.ExecArgData:
		addr := fmt.Sprintf("0x%x", copyin.Addr)
		if PTR_OFFSET_STR_ADDR != "" {
			addr = fmt.Sprintf("(0x%xul%v)", copyin.Addr, PTR_OFFSET_STR_ADDR)
		}
		if bytes.Equal(arg.Data, bytes.Repeat(arg.Data[:1], len(arg.Data))) {
			fmt.Fprintf(w, "\tNONFAILING(memset((void*)%v, %v, %v));\n",
				addr, arg.Data[0], len(arg.Data))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(memcpy((void*)%v, \"%s\", %v));\n",
				addr, toCString(arg.Data, arg.Readable), len(arg.Data))
		}
	case prog.ExecArgCsum:
		switch arg.Kind {
		case prog.ExecArgCsumInet:
			*csumSeq++
			ctx.generateCsumInet(w, copyin.Addr, arg, *csumSeq)
		default:
			panic(fmt.Sprintf("unknown csum kind %v", arg.Kind))
		}
	default:
		panic(fmt.Sprintf("bad argument type: %+v", arg))
	}
}

func (ctx *context) copyinVal(w *bytes.Buffer, addr, size uint64, val string, bf prog.BinaryFormat,
	relocateValue bool) {
	PTR_OFFSET_STR_ADDR := ""
	PTR_OFFSET_STR_VAL := ""
	if ctx.opts.CSB && valInMMapRange(ctx, addr) {
		PTR_OFFSET_STR_ADDR = "+PTR_OFFSET"
	}

	if ctx.opts.CSB && relocateValue {
		PTR_OFFSET_STR_VAL = "+PTR_OFFSET"
	}

	switch bf {
	case prog.FormatNative, prog.FormatBigEndian:

		fmt.Fprintf(w, "\tNONFAILING(*(uint%v*)(0x%xul%v) = %v%v);\n", size*8, addr, PTR_OFFSET_STR_ADDR, val, PTR_OFFSET_STR_VAL)
	case prog.FormatStrDec:
		if size != 20 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)(0x%xul%v), \"%%020llu\", (long long)(%v%v)));\n", addr, PTR_OFFSET_STR_ADDR, val, PTR_OFFSET_STR_VAL)
	case prog.FormatStrHex:
		if size != 18 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)(0x%xul%v), \"0x%%016llx\", (long long)(%v%v)));\n", addr, PTR_OFFSET_STR_ADDR, val, PTR_OFFSET_STR_VAL)
	case prog.FormatStrOct:
		if size != 23 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)(0x%xul%v), \"%%023llo\", (long long)(%v%v)));\n", addr, PTR_OFFSET_STR_ADDR, val, PTR_OFFSET_STR_VAL)
	default:
		panic("unknown binary format")
	}
}

func (ctx *context) copyout(w *bytes.Buffer, call prog.ExecCall, ci int, resCopyout bool,
	localIO map[uint64]bool, dynamicFcntlCommand bool) {
	if ctx.sysTarget.OS == targets.Fuchsia {
		// On fuchsia we have real system calls that return ZX_OK on success,
		// and libc calls that are casted to function returning intptr_t,
		// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
		if strings.HasPrefix(call.Meta.CallName, "zx_") {
			fmt.Fprintf(w, "\tif (res == ZX_OK)")
		} else {
			fmt.Fprintf(w, "\tif ((int)res != -1)")
		}
	} else {
		fmt.Fprintf(w, "\tif (res != -1)")
	}
	copyoutMultiple := len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0 ||
		resCopyout && ctx.opts.CSB && ctx.target.OS == targets.Linux && localIO[call.Index]
	if copyoutMultiple {
		fmt.Fprintf(w, " {")
	}
	fmt.Fprintf(w, "\n")
	if resCopyout {
		initFDs[call.Index] = true
		if ctx.opts.CSB && ctx.target.OS == targets.Linux && localIO[call.Index] {
			// Set nonblocking mode before publishing the descriptor to concurrent calls.
			if dynamicFcntlCommand {
				fmt.Fprintf(w, "\t\tif (csb_fcntl_cmd_%[1]d == F_DUPFD || "+
					"csb_fcntl_cmd_%[1]d == F_DUPFD_CLOEXEC) "+
					"{ int flags = fcntl(res, F_GETFL); if (flags != -1) "+
					"fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n", ci)
			} else {
				fmt.Fprintf(w, "\t\t{ int flags = fcntl(res, F_GETFL); "+
					"if (flags != -1) fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n")
			}
		}
		if dynamicFcntlCommand && localIO[call.Index] {
			fmt.Fprintf(w, "\t\t%[1]v[%[2]v] = "+
				"(csb_fcntl_cmd_%[3]d == F_DUPFD || csb_fcntl_cmd_%[3]d == F_DUPFD_CLOEXEC) ? res : -1;\n",
				ctx.resultArrayName(), call.Index, ci)
		} else {
			fmt.Fprintf(w, "\t\t%v[%v] = res;\n", ctx.resultArrayName(), call.Index)
		}
	}
	for _, copyout := range call.Copyout {
		PTR_OFFSET_STR_ADDR := ""
		if ctx.opts.CSB && valInMMapRange(ctx, copyout.Addr) {
			PTR_OFFSET_STR_ADDR = "+PTR_OFFSET"
		}
		value := fmt.Sprintf("*(uint%v*)(0x%xul%v)", copyout.Size*8, copyout.Addr, PTR_OFFSET_STR_ADDR)
		if ctx.opts.CSB && ctx.target.OS == targets.Linux && localIO[copyout.Index] {
			fmt.Fprintf(w, "\t\tNONFAILING({ int fd = %[1]s; int flags = fcntl(fd, F_GETFL); "+
				"if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK); %[2]v[%[3]v] = fd; });\n",
				value, ctx.resultArrayName(), copyout.Index)
			continue
		}
		fmt.Fprintf(w, "\t\tNONFAILING(%v[%v] = %v);\n", ctx.resultArrayName(), copyout.Index, value)
	}
	if copyoutMultiple {
		fmt.Fprintf(w, "\t}\n")
	}
}

func (ctx *context) factorizeAsFlags(value uint64, flags []string, attemptsLeft *int) ([]string, uint64) {
	if len(flags) == 0 || value == 0 || *attemptsLeft == 0 {
		return nil, value
	}

	*attemptsLeft -= 1
	currentFlag := flags[0]
	subset, remainder := ctx.factorizeAsFlags(value, flags[1:], attemptsLeft)

	if flagMask, ok := ctx.p.Target.ConstMap[currentFlag]; ok && (value&flagMask == flagMask) {
		subsetIfTaken, remainderIfTaken := ctx.factorizeAsFlags(value & ^flagMask, flags[1:], attemptsLeft)
		subsetIfTaken = append(subsetIfTaken, currentFlag)

		bits, bitsIfTaken := bits.OnesCount64(remainder), bits.OnesCount64(remainderIfTaken)
		if (bitsIfTaken < bits) || (bits == bitsIfTaken && len(subsetIfTaken) < len(subset)) {
			return subsetIfTaken, remainderIfTaken
		}
	}

	return subset, remainder
}

func (ctx *context) prettyPrintValue(field prog.Field, arg prog.ExecArgConst) string {
	mask := (uint64(1) << (arg.Size * 8)) - 1
	v := arg.Value & mask

	f := ctx.p.Target.FlagsMap[field.Type.Name()]
	if len(f) == 0 {
		return ""
	}

	maxFactorizationAttempts := 256
	flags, remainder := ctx.factorizeAsFlags(v, f, &maxFactorizationAttempts)
	if len(flags) == 0 {
		return ""
	}
	if remainder != 0 {
		flags = append(flags, fmt.Sprintf("0x%x", remainder))
	}

	return strings.Join(flags, "|")
}

func (ctx *context) argComment(field prog.Field, arg prog.ExecArg) string {
	val := ""
	constArg, isConstArg := arg.(prog.ExecArgConst)
	if isConstArg {
		val = ctx.prettyPrintValue(field, constArg)
	}

	return "/*" + field.Name + "=" + val + "*/"
}

// enforceBitSize is necessary e.g. in the variadic arguments context of the syscall() function.
func (ctx *context) constArgToStr(arg prog.ExecArgConst, enforceBitSize bool) string {
	suffix := ""
	if enforceBitSize {
		suffix = ctx.literalSuffix(arg)
	}
	mask := (uint64(1) << (arg.Size * 8)) - 1
	v := arg.Value & mask
	val := ""
	if v == ^uint64(0)&mask {
		if enforceBitSize {
			val = "(intptr_t)-1"
		} else {
			val = "-1"
		}
	} else if v >= 10 {
		val = fmt.Sprintf("0x%x%s", v, suffix)
	} else {
		val = fmt.Sprintf("%d%s", v, suffix)
	}
	if ctx.opts.Procs > 1 && arg.PidStride != 0 {
		val += fmt.Sprintf(" + procid*%v", arg.PidStride)
	}
	return val
}

func (ctx *context) literalSuffix(arg prog.ExecArgConst) string {
	if arg.Size == 8 {
		// syscall() is variadic, so constant arguments must be explicitly
		// promoted. Otherwise the compiler is free to leave garbage in the
		// upper 32 bits of the argument value. In practice this can happen
		// on amd64 with arguments that are passed on the stack, i.e.,
		// arguments beyond the first six. For example, on freebsd/amd64,
		// syscall(SYS_mmap, ..., 0) causes clang to emit a 32-bit store of
		// 0 to the stack, but the kernel expects a 64-bit value.
		//
		// syzkaller's argument type representations do not always match
		// the OS ABI. For instance, "flags" is always 64 bits wide on 64-bit
		// platforms, but is a 32-bit value ("unsigned int" or so) in many
		// cases. Thus, we assume here that passing a 64-bit argument where
		// a 32-bit argument is expected won't break anything. On amd64
		// this should be fine: arguments are passed in 64-bit registers or
		// at 64 bit-aligned addresses on the stack.
		if ctx.target.PtrSize == 4 {
			return "ull"
		} else {
			return "ul"
		}
	}
	return ""
}

func handleBigEndian(arg prog.ExecArgConst, val string) string {
	if arg.Format == prog.FormatBigEndian {
		return fmt.Sprintf("htobe%v(%v)", arg.Size*8, val)
	}
	return val
}

func (ctx *context) resultArgToStr(arg prog.ExecArgResult) string {
	res := fmt.Sprintf("%v[%v]", ctx.resultArrayName(), arg.Index)
	if arg.DivOp != 0 {
		res = fmt.Sprintf("%v/%v", res, arg.DivOp)
	}
	if arg.AddOp != 0 {
		res = fmt.Sprintf("%v+%v", res, arg.AddOp)
	}
	if arg.Format == prog.FormatBigEndian {
		res = fmt.Sprintf("htobe%v(%v)", arg.Size*8, res)
	}
	return res
}

func (ctx *context) resultArrayName() string {
	if ctx.opts.CSB {
		return "UNIQUE_VAR(ctx->r)"
	}
	return "r"
}

func (ctx *context) postProcess(result []byte) []byte {
	// Remove NONFAILING, debug, fail, etc calls.
	if !ctx.opts.HandleSegv {
		result = regexp.MustCompile(`\t*NONFAILING\((.*)\);\n`).ReplaceAll(result, []byte("$1;\n"))
	}
	result = bytes.ReplaceAll(result, []byte("NORETURN"), nil)
	if ctx.opts.CSB {
		result = bytes.ReplaceAll(result, []byte("UNIQUE_FUNC(doexit)("), []byte("exit("))
	} else {
		result = bytes.ReplaceAll(result, []byte("doexit("), []byte("exit("))
	}
	// TODO: Figure out what would be the right replacement for doexit_thread().
	result = bytes.ReplaceAll(result, []byte("doexit_thread("), []byte("exit("))
	result = regexp.MustCompile(`PRINTF\(.*?\)`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug_dump_data\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*exitf\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\tassert(0);\n"))
	result = regexp.MustCompile(`\t*fail(msg)?\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\tassert(0);\n"))

	// Remove executor include guards.
	result = regexp.MustCompile(`#define\s+[A-Z0-9_]*_H\s*\n`).ReplaceAll(result, nil)

	// Add guarded definition for REPEAT_NUM to be used by CSB bench framework
	// rep_def := fmt.Sprintf("#ifndef REPEAT_NUM\\n#define REPEAT_NUM %d\\n#endif", ctx.opts.RepeatTimes)
	result = bytes.ReplaceAll(result, []byte("/*#ifndef*/"), []byte("#ifndef"))
	result = bytes.ReplaceAll(result, []byte("/*#endif*/"), []byte("#endif"))

	result = ctx.hoistIncludes(result)
	result = ctx.removeEmptyLines(result)
	return result
}

// hoistIncludes moves all includes to the top, removes dups and sorts.
func (ctx *context) hoistIncludes(result []byte) []byte {
	includesStart := bytes.Index(result, []byte("#include"))
	if includesStart == -1 {
		return result
	}
	includes := make(map[string]bool)
	includeRe := regexp.MustCompile("#include <.*>\n")
	for _, match := range includeRe.FindAll(result, -1) {
		includes[string(match)] = true
	}
	result = includeRe.ReplaceAll(result, nil)
	// Certain linux and bsd headers are broken and go to the bottom.
	var sorted, sortedBottom, sortedTop []string
	for include := range includes {
		if strings.Contains(include, "<linux/") {
			sortedBottom = append(sortedBottom, include)
		} else if strings.Contains(include, "<netinet/if_ether.h>") {
			sortedBottom = append(sortedBottom, include)
		} else if ctx.target.OS == targets.FreeBSD && strings.Contains(include, "<sys/types.h>") {
			sortedTop = append(sortedTop, include)
		} else {
			sorted = append(sorted, include)
		}
	}
	sort.Strings(sortedTop)
	sort.Strings(sorted)
	sort.Strings(sortedBottom)
	newResult := append([]byte{}, result[:includesStart]...)
	newResult = append(newResult, strings.Join(sortedTop, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sorted, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sortedBottom, "")...)
	newResult = append(newResult, result[includesStart:]...)
	return newResult
}

// removeEmptyLines removes duplicate new lines.
func (ctx *context) removeEmptyLines(result []byte) []byte {
	for {
		newResult := bytes.ReplaceAll(result, []byte{'\n', '\n', '\n'}, []byte{'\n', '\n'})
		newResult = bytes.ReplaceAll(newResult, []byte{'\n', '\n', '\t'}, []byte{'\n', '\t'})
		newResult = bytes.ReplaceAll(newResult, []byte{'\n', '\n', ' '}, []byte{'\n', ' '})
		if len(newResult) == len(result) {
			return result
		}
		result = newResult
	}
}

func toCString(data []byte, readable bool) []byte {
	if len(data) == 0 {
		panic("empty data arg")
	}
	buf := new(bytes.Buffer)
	prog.EncodeData(buf, data, readable)
	return buf.Bytes()
}
