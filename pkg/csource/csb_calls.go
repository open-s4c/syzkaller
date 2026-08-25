// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type emitCallOpts struct {
	initCall      bool
	dataMmap      bool
	localIO       map[uint64]bool
	captureResult bool
	hooks         emitCallHooks
}

type formatArgHook func(index int, value string) string

// emitCallHooks keeps syscall-specific CSB source generation next to the code
// that recognizes the syscall. Argument hooks decorate the generically rendered
// value. Call-body and result-copyout hooks replace their respective defaults.
// afterEmit runs after the primary call; finishEmit runs after any rerun loop.
type emitCallHooks struct {
	beforeEmit      func(*bytes.Buffer)
	afterEmit       func(*bytes.Buffer)
	finishEmit      func(*bytes.Buffer)
	formatConstArg  formatArgHook
	formatResultArg formatArgHook
	formatCallBody  func(callName, funcName string, args []string, native bool) (string, bool)
	copyoutResult   func(*bytes.Buffer)
}

func replaceArgAt(target int, replacement string) formatArgHook {
	return func(index int, value string) string {
		if index == target {
			return replacement
		}
		return value
	}
}

func sprintfValueArgAt(target int, format string) formatArgHook {
	return func(index int, value string) string {
		if index == target {
			return fmt.Sprintf(format, value)
		}
		return value
	}
}

func assertHookUnset(installer, hook string, installed bool) {
	if installed {
		panic(fmt.Sprintf("%s: %s hook is already installed", installer, hook))
	}
}

func csbMessageSizes(p *prog.Prog) []uint64 {
	sizes := make([]uint64, len(p.Calls))
	for i, call := range p.Calls {
		if call.Meta.CallName != "recvmsg" && call.Meta.CallName != "sendmsg" || len(call.Args) <= 1 {
			continue
		}
		msgPtr, ok := call.Args[1].(*prog.PointerArg)
		if !ok {
			continue
		}
		msgHeader, ok := msgPtr.Res.(*prog.GroupArg)
		if !ok || len(msgHeader.Inner) <= 3 {
			continue
		}
		iovPtr, ok := msgHeader.Inner[3].(*prog.PointerArg)
		if !ok {
			continue
		}
		iovGroup, ok := iovPtr.Res.(*prog.GroupArg)
		if !ok {
			continue
		}
		for _, msg := range iovGroup.Inner {
			iov, ok := msg.(*prog.GroupArg)
			if !ok || len(iov.Inner) <= 1 {
				continue
			}
			if length, ok := iov.Inner[1].(*prog.ConstArg); ok {
				sizes[i] += length.Val
			}
		}
	}
	return sizes
}

func (ctx *context) prepareEmitCall(call *prog.ExecCall, ci int, opts emitCallOpts,
	initCall, dataMmap, resCopyout bool) emitCallOpts {
	opts.initCall = initCall
	opts.dataMmap = dataMmap
	if !ctx.opts.CSB {
		return opts
	}
	ctx.prepareUnusedFD(call.Meta, resCopyout, &opts)
	ctx.prepareFIONBIO(*call, ci, &opts)
	ctx.prepareFcntl(call, ci, &opts)
	ctx.prepareMQAttr(*call, ci, &opts)
	ctx.prepareNonblockingOpen(call, &opts)
	ctx.prepareOpenat2(*call, ci, &opts)
	ctx.prepareDup(*call, &opts)
	return opts
}

func returnsFD(call *prog.Syscall) bool {
	ret, ok := call.Ret.(*prog.ResourceType)
	// Resource kinds are ordered from the base kind to the most specific kind.
	return ok && len(ret.Desc.Kind) != 0 && ret.Desc.Kind[0] == "fd"
}

func (ctx *context) emitPreparedCall(w *bytes.Buffer, call prog.ExecCall, ci int,
	haveCopyout, trace bool, opts emitCallOpts) {
	if opts.hooks.beforeEmit != nil {
		opts.hooks.beforeEmit(w)
	}
	ctx.emitCall(w, call, ci, haveCopyout || opts.captureResult, trace, opts)
	if opts.hooks.afterEmit != nil {
		opts.hooks.afterEmit(w)
	}
}

func (ctx *context) copyoutMultiple(call prog.ExecCall, resCopyout bool, opts emitCallOpts) bool {
	return len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0 ||
		resCopyout && ctx.opts.CSB && ctx.target.OS == targets.Linux && opts.localIO[call.Index]
}

func (*context) prepareUnusedFD(call *prog.Syscall, resCopyout bool, opts *emitCallOpts) {
	if resCopyout || !returnsFD(call) {
		return
	}
	assertHookUnset("prepareUnusedFD", "afterEmit", opts.hooks.afterEmit != nil)
	opts.captureResult = true
	opts.hooks.afterEmit = func(w *bytes.Buffer) {
		fmt.Fprintf(w, "\tif (res > 2) close((int)res);\n")
	}
}

func (ctx *context) prepareFIONBIO(call prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "ioctl" || len(call.Args) <= 2 {
		return
	}
	cmd, cmdOK := call.Args[1].(prog.ExecArgConst)
	value, valueOK := call.Args[2].(prog.ExecArgConst)
	relocatePointer := valueOK && call.Meta.Name == "ioctl$auto_FIONBIO" &&
		valInMMapRange(ctx, value.Value)
	replacePointer := localIOArg(call, opts.localIO) && cmdOK && valueOK &&
		cmd.Value == ctx.target.ConstMap["FIONBIO"] && valInMMapRange(ctx, value.Value)
	if !relocatePointer && !replacePointer {
		return
	}
	assertHookUnset("prepareFIONBIO", "formatConstArg", opts.hooks.formatConstArg != nil)
	if replacePointer {
		assertHookUnset("prepareFIONBIO", "beforeEmit", opts.hooks.beforeEmit != nil)
		opts.hooks.beforeEmit = func(w *bytes.Buffer) {
			fmt.Fprintf(w, "\tuint32 csb_fionbio_%d = 1;\n", ci)
		}
		opts.hooks.formatConstArg = replaceArgAt(2,
			fmt.Sprintf("(intptr_t)&csb_fionbio_%d", ci))
		return
	}
	if relocatePointer {
		opts.hooks.formatConstArg = sprintfValueArgAt(2, "%s+PTR_OFFSET")
	}
}

func (ctx *context) prepareFcntl(call *prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "fcntl" || len(call.Args) <= 1 || !localIOArg(*call, opts.localIO) {
		return
	}
	setFlags := ctx.fcntlCommand(*call, "F_SETFL")
	command, dynamic := call.Args[1].(prog.ExecArgResult)
	if !setFlags && !dynamic {
		return
	}
	assertHookUnset("prepareFcntl", "beforeEmit", opts.hooks.beforeEmit != nil)
	assertHookUnset("prepareFcntl", "formatConstArg", opts.hooks.formatConstArg != nil)
	assertHookUnset("prepareFcntl", "formatResultArg", opts.hooks.formatResultArg != nil)
	assertHookUnset("prepareFcntl", "copyoutResult", opts.hooks.copyoutResult != nil)
	if setFlags {
		args := append([]prog.ExecArg(nil), call.Args...)
		if flags, ok := args[2].(prog.ExecArgConst); ok {
			flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
			args[2] = flags
			call.Args = args
		} else if _, ok := args[2].(prog.ExecArgResult); ok {
			opts.hooks.formatResultArg = sprintfValueArgAt(2, "(%s | O_NONBLOCK)")
		}
	}
	if !dynamic {
		return
	}
	commandName := fmt.Sprintf("csb_fcntl_cmd_%d", ci)
	opts.hooks.beforeEmit = func(w *bytes.Buffer) {
		fmt.Fprintf(w, "\tintptr_t %s = %s;\n", commandName, ctx.resultArgToStr(command))
	}
	formatArg := func(index int, value string) string {
		switch index {
		case 1:
			return commandName
		case 2:
			return fmt.Sprintf("(%s == F_SETFL ? (%s | O_NONBLOCK) : %s)",
				commandName, value, value)
		default:
			return value
		}
	}
	opts.hooks.formatConstArg = formatArg
	opts.hooks.formatResultArg = formatArg
	if opts.localIO[call.Index] {
		resultIndex := call.Index
		opts.hooks.copyoutResult = func(w *bytes.Buffer) {
			fmt.Fprintf(w, "\t\tif (%[1]s == F_DUPFD || "+
				"%[1]s == F_DUPFD_CLOEXEC) "+
				"{ int flags = fcntl(res, F_GETFL); if (flags != -1) "+
				"fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n", commandName)
			fmt.Fprintf(w, "\t\t%[1]v[%[2]v] = "+
				"(%[3]s == F_DUPFD || %[3]s == F_DUPFD_CLOEXEC) ? res : -1;\n",
				ctx.resultArrayName(), resultIndex, commandName)
		}
	}
}

func (ctx *context) prepareMQAttr(call prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "mq_getsetattr" || !localIOArg(call, opts.localIO) {
		return
	}
	attr, ok := call.Args[1].(prog.ExecArgConst)
	if !ok || !valInMMapRange(ctx, attr.Value) {
		return
	}
	assertHookUnset("prepareMQAttr", "beforeEmit", opts.hooks.beforeEmit != nil)
	assertHookUnset("prepareMQAttr", "formatConstArg", opts.hooks.formatConstArg != nil)
	opts.hooks.beforeEmit = func(w *bytes.Buffer) {
		fmt.Fprintf(w, "\tstruct { intptr_t flags; intptr_t maxmsg; intptr_t msgsize; intptr_t curmsgs; "+
			"intptr_t reserved[4]; } csb_mq_attr_%[1]d = {%[2]d, 0, 0, 0};\n",
			ci, ctx.target.ConstMap["O_NONBLOCK"])
	}
	opts.hooks.formatConstArg = replaceArgAt(1,
		fmt.Sprintf("(intptr_t)&csb_mq_attr_%d", ci))
}

func (ctx *context) prepareNonblockingOpen(call *prog.ExecCall, opts *emitCallOpts) {
	if ctx.target.OS != targets.Linux {
		return
	}
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
	if flagArg == -1 {
		return
	}
	args := append([]prog.ExecArg(nil), call.Args...)
	if flags, ok := args[flagArg].(prog.ExecArgConst); ok {
		flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
		args[flagArg] = flags
		call.Args = args
	} else if _, ok := args[flagArg].(prog.ExecArgResult); ok {
		assertHookUnset("prepareNonblockingOpen", "formatResultArg", opts.hooks.formatResultArg != nil)
		opts.hooks.formatResultArg = sprintfValueArgAt(flagArg, "(%s | O_NONBLOCK)")
	}
}

func (ctx *context) prepareOpenat2(call prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "openat2" {
		return
	}
	assertHookUnset("prepareOpenat2", "beforeEmit", opts.hooks.beforeEmit != nil)
	assertHookUnset("prepareOpenat2", "finishEmit", opts.hooks.finishEmit != nil)
	assertHookUnset("prepareOpenat2", "formatConstArg", opts.hooks.formatConstArg != nil)
	assertHookUnset("prepareOpenat2", "formatResultArg", opts.hooks.formatResultArg != nil)
	how, known := ctx.openat2How(ci)
	if known && how[0]&ctx.target.ConstMap["O_PATH"] == 0 {
		how[0] |= ctx.target.ConstMap["O_NONBLOCK"]
	}
	opts.hooks.beforeEmit = func(w *bytes.Buffer) {
		fmt.Fprintf(w, "\t{\n\tstruct { uint64 flags; uint64 mode; uint64 resolve; } "+
			"csb_open_how_%[1]d = {%[2]d, %[3]d, %[4]d};\n", ci, how[0], how[1], how[2])
	}
	formatArg := func(index int, value string) string {
		switch index {
		case 2:
			return fmt.Sprintf("(intptr_t)&csb_open_how_%d", ci)
		case 3:
			return fmt.Sprintf("sizeof(csb_open_how_%d)", ci)
		default:
			return value
		}
	}
	opts.hooks.formatConstArg = formatArg
	opts.hooks.formatResultArg = formatArg
	opts.hooks.finishEmit = func(w *bytes.Buffer) {
		fmt.Fprintf(w, "\t}\n")
	}
}

func (*context) prepareDup(call prog.ExecCall, opts *emitCallOpts) {
	if call.Meta.CallName != "dup2" && call.Meta.CallName != "dup3" {
		return
	}
	assertHookUnset("prepareDup", "formatCallBody", opts.hooks.formatCallBody != nil)
	opts.hooks.formatCallBody = func(_ string, funcName string, args []string, native bool) (string, bool) {
		argOffset := 0
		if native {
			argOffset = 1
		}
		src, dst := args[argOffset], args[argOffset+1]
		args[argOffset] = "csb_dup_src"
		args[argOffset+1] =
			"((uint32)csb_dup_dst <= 2 && (uint32)csb_dup_src != (uint32)csb_dup_dst ? -1 : csb_dup_dst)"
		return fmt.Sprintf("({ intptr_t csb_dup_src = (%s); intptr_t csb_dup_dst = (%s); %v(%v); })",
			src, dst, funcName, strings.Join(args, ", ")), true
	}
}

func (*context) finishEmitCall(w *bytes.Buffer, opts emitCallOpts) {
	if opts.hooks.finishEmit != nil {
		opts.hooks.finishEmit(w)
	}
}

func finishCSBCalls() {
	// Remove resources from network operations which are not created by a connect.
	connectOps := make(map[uint64][]NetOpSize)
	for res := range connectFDs {
		connectOps[res] = netOpsOrHandshake(res)
	}
	NetOpsFDsConnect = connectOps

	acceptOps := make(map[uint64][]NetOpSize)
	for _, res := range sortedUint64AnyKeys(acceptFDs) {
		acceptOps[res] = netOpsOrHandshake(res)
	}
	NetOpsFDsAccept = acceptOps
}

func (ctx *context) localIOResources(p prog.ExecProg) map[uint64]bool {
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
			duplicate := ctx.fcntlCommand(call, "F_DUPFD") ||
				ctx.fcntlCommand(call, "F_DUPFD_CLOEXEC")
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

func (ctx *context) fcntlCommand(call prog.ExecCall, commandName string) bool {
	if call.Meta.CallName != "fcntl" || len(call.Args) < 2 {
		return false
	}
	commandValue, ok := ctx.target.ConstMap[commandName]
	if !ok {
		return false
	}
	arg, ok := call.Args[1].(prog.ExecArgConst)
	return ok && arg.Value == commandValue
}

func localIOArg(call prog.ExecCall, local map[uint64]bool) bool {
	if len(call.Args) == 0 {
		return false
	}
	arg, ok := call.Args[0].(prog.ExecArgResult)
	return ok && arg.DivOp == 0 && arg.AddOp == 0 && local[arg.Index]
}

func valInMMapRange(ctx *context, val uint64) bool {
	min := ctx.sysTarget.DataOffset
	max := min + ctx.target.NumPages*ctx.target.PageSize

	// The CSB mapping is exactly [min, max); adjacent values are not pointers into it.
	return val >= min && val < max
}

func (ctx *context) formatCSBConstArg(arg prog.ExecArgConst, i int,
	opts emitCallOpts, value string) string {
	// DataMmapProg includes adjacent guard pages that move with the mapping.
	if ctx.opts.CSB && ((opts.dataMmap && i == 0) ||
		(arg.IsPointer && valInMMapRange(ctx, arg.Value))) {
		value += "+PTR_OFFSET"
	}
	if opts.hooks.formatConstArg != nil {
		value = opts.hooks.formatConstArg(i, value)
	}
	return value
}

func (*context) formatCSBResultArg(i int, opts emitCallOpts, value string) string {
	if opts.hooks.formatResultArg != nil {
		value = opts.hooks.formatResultArg(i, value)
	}
	return value
}

func (*context) formatCSBCallBody(callName, funcName string, args []string, native bool,
	opts emitCallOpts) (string, bool) {
	if opts.hooks.formatCallBody != nil {
		return opts.hooks.formatCallBody(callName, funcName, args, native)
	}
	return "", false
}

func (ctx *context) copyoutCSBResult(w *bytes.Buffer, call prog.ExecCall, opts emitCallOpts) {
	initFDs[call.Index] = true
	if opts.hooks.copyoutResult != nil {
		opts.hooks.copyoutResult(w)
		return
	}
	if ctx.opts.CSB && ctx.target.OS == targets.Linux && opts.localIO[call.Index] {
		// Set nonblocking mode before publishing the descriptor to concurrent calls.
		fmt.Fprintf(w, "\t\t{ int flags = fcntl(res, F_GETFL); "+
			"if (flags != -1) fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n")
	}
	fmt.Fprintf(w, "\t\t%v[%v] = res;\n", ctx.resultArrayName(), call.Index)
}

func (ctx *context) copyoutCSBArg(w *bytes.Buffer, copyout prog.ExecCopyout, value string,
	opts emitCallOpts) bool {
	if !ctx.opts.CSB || ctx.target.OS != targets.Linux || !opts.localIO[copyout.Index] {
		return false
	}
	fmt.Fprintf(w, "\t\tNONFAILING({ int fd = %[1]s; int flags = fcntl(fd, F_GETFL); "+
		"if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK); %[2]v[%[3]v] = fd; });\n",
		value, ctx.resultArrayName(), copyout.Index)
	return true
}

func (ctx *context) recordCSBCall(call prog.ExecCall, resCopyout bool, msgSize uint64) {
	if resCopyout {
		missedFDResources[call.Index] = true
	}
	callName := call.Meta.CallName
	if trampoline, ok := ctx.sysTarget.SyscallTrampolines[callName]; ok {
		callName = trampoline
	}
	if callName == "close" {
		if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
			missedFDResources[fdRes] = false
		}
	}
	if callName == "pipe" || callName == "pipe2" {
		for _, copyout := range call.Copyout {
			missedFDResources[copyout.Index] = true
		}
	}
	if fdRes, ok := firstResultIndex(call); ok {
		switch callName {
		case "read", "pread", "pread64", "recv", "recvfrom":
			AddToNetOps(fdRes, NetRead, call.Args[2].(prog.ExecArgConst).Value)
		case "recvmsg":
			AddToNetOps(fdRes, NetRead, msgSize)
		case "write", "pwrite", "pwrite64", "send", "sendto":
			AddToNetOps(fdRes, NetWrite, call.Args[2].(prog.ExecArgConst).Value)
		case "sendmsg":
			AddToNetOps(fdRes, NetWrite, msgSize)
		case "connect":
			if call.Meta.Name == "connect$inet" || call.Meta.Name == "connect$inet6" {
				connectFDs[fdRes] = true
			}
		case "listen":
			listenFDs[fdRes] = true
		}
	}
	if (callName == "accept" || callName == "accept4") &&
		(call.Meta.Name == "accept$inet" || call.Meta.Name == "accept4$inet" ||
			call.Meta.Name == "accept$inet6" || call.Meta.Name == "accept4$inet6") {
		acceptCalls++
		acceptFDs[call.Index] = true
	}
}

func firstResultIndex(call prog.ExecCall) (uint64, bool) {
	if len(call.Args) == 0 {
		return 0, false
	}
	return execArgResultIndex(call.Args[0])
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
