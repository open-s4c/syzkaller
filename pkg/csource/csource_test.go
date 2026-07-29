// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/syzkaller/executor"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

var flagRunGenerateTest = flag.Bool("runGenerate", false, "run TestGenerate")

func init() {
	// csource tests consume too much memory under race detector (>1GB),
	// and periodically timeout on Travis. So we skip them.
	if testutil.RaceEnabled {
		for _, arg := range os.Args[1:] {
			if strings.Contains(arg, "-test.short") {
				fmt.Printf("skipping race testing in short mode\n")
				os.Exit(0)
			}
		}
	}
}

func TestGenerate(t *testing.T) {
	if !*flagRunGenerateTest {
		t.Skip("skipping without -runGenerate")
	}
	t.Parallel()
	checked := make(map[string]bool)
	for _, target := range prog.AllTargets() {
		// Auto-generated descriptions currently do not properly mark arch-specific syscalls, see
		// https://github.com/google/syzkaller/issues/5410#issuecomment-3570190241.
		// Until it's fixed, let's remove these syscalls from csource tests.
		ct := target.NoAutoChoiceTable()
		sysTarget := targets.Get(target.OS, target.Arch)
		if runtime.GOOS != sysTarget.BuildOS {
			continue
		}
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			if err := sysTarget.BrokenCompiler; err != "" {
				t.Skipf("target compiler is broken: %v", err)
			}
			full := !checked[target.OS]
			if full || !testing.Short() {
				checked[target.OS] = true
				t.Parallel()
				testTarget(t, target, full, ct)
			}
			testPseudoSyscalls(t, target, ct)
		})
	}
}

func TestCSBExecLifecycle(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"syz_csb_execve()", "syz_csb_execveat()", "syz_csb_fexecve()"} {
		p, err := target.Deserialize([]byte(call+"\n"), prog.NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		testOne(t, p, Options{Slowdown: 1})
		src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"csb_exec_lifecycle", "/proc/self/exe", "syz_csb_exec_child"} {
			assert.Contains(t, string(src), want)
		}
		assertCSBExecIdentifiersNamespaced(t, src)
		assert.NotContains(t, string(src), "return -errno")
	}
}

func TestCSBReappliesCurrentAffinity(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("syz_reapply_affinity()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "UNIQUE_FUNC(syz_reapply_affinity)()")
	assert.Contains(t, string(src), "static __thread cpu_set_t* mask = NULL")
	assert.Contains(t, string(src), "mask = CPU_ALLOC(cpus)")
	assert.Contains(t, string(src), "sched_getaffinity(0, mask_size, mask)")
}

func TestCSBBoundsLocalIO(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	tests := []string{
		"openat(0xffffffffffffff9c, &(0x7f0000000000)='./fifo\\x00', 0x0, 0x0)\n",
		"creat(&(0x7f0000000000)='./fifo\\x00', 0x0)\n",
		"socketpair$unix(0x1, 0x1, 0x0, &(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"fcntl$setstatus(r0, 0x4, 0x0)\n" +
			"read(r0, &(0x7f0000000040), 0x1)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"r2 = dup(r1)\nwrite(r2, &(0x7f0000000040)=\"00\", 0x1)\n",
		"r0 = eventfd(0x0)\nread$eventfd(r0, &(0x7f0000000000), 0x8)\n",
		"r0 = timerfd_create(0x0, 0x0)\nread(r0, &(0x7f0000000000), 0x8)\n",
		"r0 = inotify_init()\nread(r0, &(0x7f0000000000), 0x10)\n",
		"r0 = fanotify_init(0x0, 0x0)\nread(r0, &(0x7f0000000000), 0x10)\n",
		"r0 = userfaultfd(0x0)\nread(r0, &(0x7f0000000000), 0x20)\n",
		"r0 = mq_open(&(0x7f0000000000)='/queue\\x00', 0x42, 0x180, 0x0)\n" +
			"mq_getsetattr(r0, &(0x7f0000000040)={0x0, 0x0, 0x0, 0x0}, 0x0)\n" +
			"mq_timedreceive(r0, &(0x7f0000000080), 0x1, 0x0, 0x0)\n",
		"r0 = signalfd(0xffffffffffffffff, &(0x7f0000000000)=0x0, 0x8)\n" +
			"read(r0, &(0x7f0000000040), 0x80)\n",
		"r0 = signalfd(0xffffffffffffffff, &(0x7f0000000000)=0x0, 0x8)\n" +
			"r1 = signalfd(r0, &(0x7f0000000040)=0x0, 0x8)\nread(r1, &(0x7f0000000080), 0x80)\n",
		"r0 = socket$inet(0x2, 0x1, 0x0)\n" +
			"r1 = signalfd(r0, &(0x7f0000000040)=0x0, 0x8)\nread(r1, &(0x7f0000000080), 0x80)\n",
		"openat2(0xffffffffffffff9c, &(0x7f0000000000)='./fifo\\x00', " +
			"&(0x7f0000000040)={0x0, 0x0, 0x0}, 0x18)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"ioctl$int_in(r0, 0x5421, &(0x7f0000000040)=0x0)\nread(r0, &(0x7f0000000080), 0x1)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"ioctl(r0, 0x5421, &(0x7f0000000040)=0x0)\nread(r0, &(0x7f0000000080), 0x1)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"ioctl$auto_FIONBIO(r0, 0x5421, 0x200000000040)\nread(r0, &(0x7f0000000080), 0x1)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"fcntl$auto_F_SETFL(r0, 0x4, 0x0)\nread(r0, &(0x7f0000000040), 0x1)\n",
		"pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n" +
			"r2 = fcntl$auto_F_DUPFD_CLOEXEC(r0, 0x406, 0x3)\n" +
			"fcntl$auto_F_SETFL(r2, 0x4, 0x0)\nread(r0, &(0x7f0000000040), 0x1)\n",
	}
	for _, input := range tests {
		p, err := target.Deserialize([]byte(input), prog.NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		src, _, err := Write(p, Options{CSB: true, HandleSegv: true, Slowdown: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"F_GETFL", "O_NONBLOCK", "F_SETFL"} {
			if !strings.HasPrefix(input, "openat") && !strings.HasPrefix(input, "creat") {
				assert.Contains(t, string(src), want)
			}
		}
		if !strings.HasPrefix(input, "openat2") && !strings.HasPrefix(input, "creat") {
			assert.Contains(t, string(src), "O_NONBLOCK")
		}
		if strings.HasPrefix(input, "creat") {
			assert.Contains(t, string(src), "syscall(__NR_open")
			assert.Contains(t, string(src), "0xa41")
		}
		if strings.HasPrefix(input, "r0 = mq_open") {
			assert.Contains(t, string(src), "0x842")
		}
		assert.NotContains(t, string(src), "csb_io_errno_")
		if strings.Contains(input, "F_SETFL") || strings.Contains(input, "fcntl$setstatus") {
			assert.Contains(t, string(src), "0x800")
		}
		if strings.Contains(input, "FIONBIO") {
			assert.Contains(t, string(src), "uint32_t csb_fionbio_1 = 1")
			assert.Contains(t, string(src), "/*arg=*/(intptr_t)&csb_fionbio_1")
			assert.NotContains(t, string(src), "/*arg=*/0x200000000040ul+PTR_OFFSET")
		}
		if strings.Contains(input, "mq_getsetattr") {
			assert.Contains(t, string(src), "csb_mq_attr_1 = {2048, 0, 0, 0}")
			assert.Contains(t, string(src), "/*attr=*/(intptr_t)&csb_mq_attr_1")
		}
		if strings.HasPrefix(input, "openat2") {
			assert.Contains(t, string(src), "csb_open_how_0 = {2048, 0, 0}")
			assert.Contains(t, string(src), "(intptr_t)&csb_open_how_0")
			assert.Contains(t, string(src), "sizeof(csb_open_how_0)")
			declaration := strings.Index(string(src), "csb_open_how_0 = {2048, 0, 0}")
			invocation := strings.Index(string(src), "syscall(__NR_openat2")
			assert.Less(t, declaration, invocation)
			assert.NotContains(t, string(src), "process_vm_readv")
		}
		src, _, err = Write(p, Options{Slowdown: 1})
		if err != nil {
			t.Fatal(err)
		}
		assert.NotContains(t, string(src), "F_SETFL")
	}
}

func TestCSBPreservesOpenat2OPath(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("openat2(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', "+
		"&(0x7f0000000040)={0x200000, 0x0, 0x0}, 0x18)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, HandleSegv: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "csb_open_how_0 = {2097152, 0, 0}")
}

func TestCSBPreservesExtendedOpenat2How(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("openat2(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', "+
		"&(0x7f0000000040)={0x0, 0x0, 0x0}, 0x20)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "csb_open_how_0 = {2048, 0, 0}")
	assert.Contains(t, string(src), "sizeof(csb_open_how_0)")
}

func TestCSBOpenat2Fallback(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("openat2(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', 0x0, 0x18)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "csb_open_how_0 = {2621440, 0, 0}")
	assert.NotContains(t, string(src), "process_vm_readv")
}

func TestCSBOpenat2DynamicSizeUsesSnapshotSize(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = getpid()\n"+
		"openat2(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', "+
		"&(0x7f0000000040)={0x0, 0x0, 0x0}, 0x18)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Calls[1].Args[3] = prog.ExecArgResult{Size: 8, Index: 0}
	ctx := &context{
		p: p, opts: Options{CSB: true, Slowdown: 1}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch), calls: make(map[string]uint64),
	}
	calls, _ := ctx.generateCalls(decoded, false, false, nil, nil, nil, false)
	assert.Contains(t, calls[1], "(intptr_t)&csb_open_how_1")
	assert.Contains(t, calls[1], "sizeof(csb_open_how_1)")
	assert.NotContains(t, calls[1], "/*size=*/UNIQUE_VAR(ctx->r)[0]")
}

func TestCSBPreservesNonblockAfterOpen(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./fifo\\x00', 0x2, 0x0)\n"+
		"fcntl$setstatus(r0, 0x4, 0x0)\nread(r0, &(0x7f0000000040), 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "/*flags=O_NONBLOCK*/0x800")
}

func TestCSBConstantFDDoesNotPanic(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		"close(0xffffffffffffffff)\n",
		"read(0xffffffffffffffff, &(0x7f0000000000), 0x1)\n",
		"write(0xffffffffffffffff, &(0x7f0000000000)=\"61\", 0x1)\n",
	} {
		p, err := target.Deserialize([]byte(data), prog.NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Write(p, Options{CSB: true, Slowdown: 1}); err != nil {
			t.Fatalf("Write(%q) failed: %v", data, err)
		}
	}
}

func TestLocalIOArgRejectsTransforms(t *testing.T) {
	local := map[uint64]bool{1: true}
	for _, arg := range []prog.ExecArgResult{{Index: 1, DivOp: 2}, {Index: 1, AddOp: 1}} {
		if localIOArg(prog.ExecCall{Args: []prog.ExecArg{arg}}, local) {
			t.Fatalf("transformed result treated as local: %+v", arg)
		}
	}
}

func TestCSBFIONBIOInvalidPointer(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\nioctl$int_in(r0, 0x5421, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, HandleSegv: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.NotContains(t, string(src), "uint32_t*)(0x0")
}

func TestCSBFSetFLResultArgument(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n"+
		"r2 = getpid()\nfcntl$auto(r0, 0x4, r2)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Write(p, Options{CSB: true, Slowdown: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestCSBDynamicOpenFlagsAndFcntlCommand(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = getpid()\n"+
		"r1 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./fifo\\x00', 0x0, 0x0)\n"+
		"creat(&(0x7f0000000040)='./fifo2\\x00', 0x0)\n"+
		"r2 = fcntl$auto(r1, 0x0, 0x0)\n"+
		"read(r2, &(0x7f0000000080), 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := prog.ExecArgResult{Size: 8, Index: 0}
	decoded.Calls[1].Args[2] = dynamic
	decoded.Calls[2].Args[1] = dynamic
	decoded.Calls[3].Args[1] = dynamic
	local := localIOResources(decoded, target)
	assert.True(t, local[decoded.Calls[3].Index])
	ctx := &context{
		p: p, opts: Options{CSB: true, Slowdown: 1}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch), calls: make(map[string]uint64),
	}
	calls, _ := ctx.generateCalls(decoded, false, false, nil, nil, nil, false)
	assert.Contains(t, calls[1], "(UNIQUE_VAR(ctx->r)[0] | O_NONBLOCK)")
	assert.Contains(t, calls[2], "syscall(__NR_open")
	assert.Contains(t, calls[3], "intptr_t csb_fcntl_cmd_3 = UNIQUE_VAR(ctx->r)[0]")
	assert.Contains(t, calls[3], "csb_fcntl_cmd_3 == F_SETFL ? (0 | O_NONBLOCK) : 0")
	assert.Contains(t, calls[3], "csb_fcntl_cmd_3 == F_DUPFD")
	assert.Contains(t, calls[3], "? res : -1")
}

func TestCSBTwoArgumentIoctl(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = eventfd(0x0)\nioctl$FIOCLEX(r0, 0x5451)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Write(p, Options{CSB: true, Slowdown: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestCSBMQAttrUsesTargetPointerWidth(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.I386)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = mq_open(&(0x7f0000000000)='/queue\\x00', 0x42, 0x180, 0x0)\n"+
		"mq_getsetattr(r0, &(0x7f0000000040)={0x0, 0x0, 0x0, 0x0}, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src),
		"intptr_t flags; intptr_t maxmsg; intptr_t msgsize; intptr_t curmsgs; intptr_t reserved[4];")
	assert.Contains(t, string(src), "csb_mq_attr_1 = {2048, 0, 0, 0}")
	assert.Contains(t, string(src), "/*attr=*/(intptr_t)&csb_mq_attr_1")
	assert.NotContains(t, string(src), "/*attr=*/0x80000040ul+PTR_OFFSET")
}

func TestLocalIONonblockingLifetime(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := syscall.Read(fds[0], make([]byte, 1))
			done <- err
		}()
	}
	for range 8 {
		select {
		case err := <-done:
			if err != syscall.EAGAIN {
				t.Fatalf("read returned %v, want EAGAIN", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent read blocked")
		}
	}
}

func TestCSBSetsNonblockingBeforePublishingDescriptor(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("pipe(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0})\n"+
		"read(r0, &(0x7f0000000040), 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Threaded: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	setNonblock := strings.Index(string(src), "int fd = *(uint32_t*)(0x200000000000ul+PTR_OFFSET)")
	publish := strings.Index(string(src), "UNIQUE_VAR(ctx->r)[0] = fd")
	if setNonblock == -1 || publish == -1 || setNonblock > publish {
		t.Fatalf("descriptor publication precedes nonblocking setup:\n%s", src)
	}
}

func assertCSBExecIdentifiersNamespaced(t *testing.T, src []byte) {
	t.Helper()
	// Strip text that cannot declare or reference a C identifier. In particular,
	// syz_csb_exec_child is intentionally shared as an environment variable name.
	code := regexp.MustCompile(`(?s)/\*.*?\*/|"(?:\\.|[^"\\])*"`).ReplaceAll(src, nil)
	code = regexp.MustCompile(`(?m)//.*$`).ReplaceAll(code, nil)
	execIdentifier := regexp.MustCompile(
		`\b(?:csb_exec_[A-Za-z0-9_]*|CSB_[A-Z0-9_]*EXEC[A-Z0-9_]*|syz_csb_[a-z0-9_]*exec[a-z0-9_]*)\b`)
	all := execIdentifier.FindAll(code, -1)
	if len(all) == 0 {
		t.Fatal("generated source contains no exec lifecycle identifiers")
	}
	namespaced := regexp.MustCompile(`UNIQUE_FUNC\(`+execIdentifier.String()+`\)`).ReplaceAll(code, nil)
	if bare := execIdentifier.FindAll(namespaced, -1); len(bare) != 0 {
		t.Fatalf("exec lifecycle identifiers are not namespaced: %q", bare)
	}
}

func testPseudoSyscalls(t *testing.T, target *prog.Target, ct *prog.ChoiceTable) {
	// Use options that are as minimal as possible.
	// We want to ensure that the code can always be compiled.
	opts := Options{
		Slowdown: 1,
	}
	rs := testutil.RandSource(t)
	for _, meta := range target.PseudoSyscalls() {
		p := target.GenSampleProg(meta, rs, ct)
		t.Run(fmt.Sprintf("single_%s", meta.CallName), func(t *testing.T) {
			t.Parallel()
			testOne(t, p, opts)
		})
	}
}

func testTarget(t *testing.T, target *prog.Target, full bool, ct *prog.ChoiceTable) {
	rs := testutil.RandSource(t)
	p := target.Generate(rs, 10, ct)
	// Turns out that fully minimized program can trigger new interesting warnings,
	// e.g. about NULL arguments for functions that require non-NULL arguments in syz_ functions.
	// We could append both AllSyzProg as-is and a minimized version of it,
	// but this makes the NULL argument warnings go away (they showed up in ".constprop" versions).
	// Testing 2 programs takes too long since we have lots of options permutations and OS/arch.
	// So we use the as-is in short tests and minimized version in full tests.
	syzProg := target.GenerateAllSyzProg(rs)
	var opts []Options
	if !full || testing.Short() {
		p.Calls = append(p.Calls, syzProg.Calls...)
		opts = allOptionsSingle(target.OS)
		opts = append(opts, ExecutorOpts)
	} else {
		minimized, _ := prog.Minimize(syzProg, -1, prog.MinimizeCorpus, func(p *prog.Prog, call int) bool {
			return len(p.Calls) == len(syzProg.Calls)
		})
		p.Calls = append(p.Calls, minimized.Calls...)
		opts = allOptionsPermutations(target.OS)
	}
	// Test various call properties.
	if len(p.Calls) > 0 {
		p.Calls[0].Props.FailNth = 1
	}
	if len(p.Calls) > 1 {
		p.Calls[1].Props.Async = true
	}
	if len(p.Calls) > 2 {
		p.Calls[2].Props.Rerun = 4
	}
	for opti, opts := range opts {
		if testing.Short() && opts.HandleSegv {
			// HandleSegv can radically increase compilation time/memory consumption on large programs.
			// For example, for one program captured from this test enabling HandleSegv increases
			// compilation time from 1.94s to 104.73s and memory consumption from 136MB to 8116MB.
			continue
		}
		t.Run(fmt.Sprintf("%v", opti), func(t *testing.T) {
			t.Parallel()
			testOne(t, p, opts)
		})
	}
}

var failedTests uint32

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	// Each failure produces lots of output (including full C source).
	// Frequently lots of tests fail at the same, which produces/tmp/log
	// tens of thounds of lines of output. Limit amount of output.
	maxFailures := uint32(10)
	if os.Getenv("CI") != "" {
		maxFailures = 1
	}
	if atomic.LoadUint32(&failedTests) > maxFailures {
		return
	}
	src, _, err := Write(p, opts)
	if err != nil {
		if atomic.AddUint32(&failedTests, 1) > maxFailures {
			t.Fatal()
		}
		t.Logf("opts: %+v\nprogram:\n%s", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	// Executor headers are embedded into the C source. Make sure there are no leftover include guards.
	if matches := regexp.MustCompile(`(?m)^#define\s+\S+_H\s*\n`).FindAllString(string(src), -1); len(matches) > 0 {
		t.Fatalf("source contains leftover include guards: %v\nopts: %+v\nprogram:\n%s",
			matches, opts, p.Serialize())
	}
	bin, err := Build(p.Target, src)
	if err != nil {
		if atomic.AddUint32(&failedTests, 1) > maxFailures {
			t.Fatal()
		}
		t.Logf("opts: %+v\nprogram:\n%s", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}

func TestExecutorMacros(t *testing.T) {
	// Ensure that executor does not mis-spell any of the SYZ_* macros.
	target, _ := prog.GetTarget(targets.TestOS, targets.TestArch64)
	p := target.Generate(rand.NewSource(0), 1, target.DefaultChoiceTable())
	expected := commonDefines(p, Options{})
	expected["SYZ_EXECUTOR"] = true
	expected["SYZ_HAVE_SETUP_LOOP"] = true
	expected["SYZ_HAVE_RESET_LOOP"] = true
	expected["SYZ_HAVE_SETUP_TEST"] = true
	expected["SYZ_TEST_COMMON_EXT_EXAMPLE"] = true
	macros := regexp.MustCompile("SYZ_[A-Za-z0-9_]+").FindAllString(string(executor.CommonHeader), -1)
	for _, macro := range macros {
		if strings.HasPrefix(macro, "SYZ_HAVE_") {
			continue
		}
		if _, ok := expected[macro]; !ok {
			t.Errorf("unexpected macro: %v", macro)
		}
	}
}

func TestSortedUint64AnyKeys(t *testing.T) {
	t.Parallel()

	expected := []uint64{1, 2, 3}
	t.Run("bool", func(t *testing.T) {
		t.Parallel()
		got := sortedUint64AnyKeys(map[uint64]bool{
			3: true,
			1: false,
			2: true,
		})
		assert.Equal(t, expected, got)
	})
	t.Run("uint64", func(t *testing.T) {
		t.Parallel()
		got := sortedUint64AnyKeys(map[uint64]uint64{
			3: 30,
			1: 10,
			2: 20,
		})
		assert.Equal(t, expected, got)
	})
	t.Run("string", func(t *testing.T) {
		t.Parallel()
		got := sortedUint64AnyKeys(map[uint64]string{
			3: "three",
			1: "one",
			2: "two",
		})
		assert.Equal(t, expected, got)
	})
	t.Run("net op size", func(t *testing.T) {
		t.Parallel()
		got := sortedUint64AnyKeys(map[uint64][]NetOpSize{
			3: {{Op: NetRead, Num: 3, Size: 30}},
			1: {{Op: NetWrite, Num: 1, Size: 10}},
			2: {{Op: NetRead, Num: 2, Size: 20}},
		})
		assert.Equal(t, expected, got)
	})
}

func TestToStringArray(t *testing.T) {
	t.Parallel()

	t.Run("uint64", func(t *testing.T) {
		t.Parallel()
		got, err := toStringArray(map[uint64]uint64{
			3: 30,
			1: 10,
			2: 20,
		})
		assert.NoError(t, err)
		assert.Equal(t, "10, 20, 30", got)
	})
	t.Run("string", func(t *testing.T) {
		t.Parallel()
		got, err := toStringArray(map[uint64]string{
			3: "three",
			1: "one",
			2: "two",
		})
		assert.NoError(t, err)
		assert.Equal(t, `"one", "two", "three"`, got)
	})
	t.Run("net op size", func(t *testing.T) {
		t.Parallel()
		got, err := toStringArray(map[uint64][]NetOpSize{
			3: {
				{Op: NetRead, Num: 3, Size: 30},
			},
			1: {
				{Op: NetWrite, Num: 1, Size: 10},
				{Op: NetRead, Num: 2, Size: 20},
			},
			2: {
				{Op: NetRead, Num: 2, Size: 40},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, `"1w10-2r20", "2r40", "3r30"`, got)
	})
}

func TestSource(t *testing.T) {
	t.Parallel()

	target32, err := prog.GetTarget(targets.TestOS, targets.TestArch32)
	if err != nil {
		t.Fatal(err)
	}

	target64, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}

	type Test struct {
		input  string
		output string
		target *prog.Target // target64 by default.
	}
	tests := []Test{
		{
			input: `
r0 = csource0(0x1)
csource1(r0)
`,
			output: `
res = syscall(SYS_csource0, /*num=*/1);
if (res != -1)
	r[0] = res;
syscall(SYS_csource1, /*fd=*/r[0]);
`,
		},
		{
			input: `
csource2(&AUTO="12345678")
csource3(&AUTO)
csource4(&AUTO)
csource5(&AUTO)
csource6(&AUTO)
`,
			output: fmt.Sprintf(`
NONFAILING(memcpy((void*)0x%x, "\x12\x34\x56\x78", 4));
syscall(SYS_csource2, /*buf=*/0x%xul);
NONFAILING(memset((void*)0x%x, 0, 10));
syscall(SYS_csource3, /*buf=*/0x%xul);
NONFAILING(memset((void*)0x%x, 48, 10));
syscall(SYS_csource4, /*buf=*/0x%xul);
NONFAILING(memcpy((void*)0x%x, "0101010101", 10));
syscall(SYS_csource5, /*buf=*/0x%xul);
NONFAILING(memcpy((void*)0x%x, "101010101010", 12));
syscall(SYS_csource6, /*buf=*/0x%xul);
`,
				target64.DataOffset+0x40, target64.DataOffset+0x40,
				target64.DataOffset+0x80, target64.DataOffset+0x80,
				target64.DataOffset+0xc0, target64.DataOffset+0xc0,
				target64.DataOffset+0x100, target64.DataOffset+0x100,
				target64.DataOffset+0x140, target64.DataOffset+0x140),
		},
		{
			input: `
csource7(0x0)
csource7(0x1)
csource7(0x2)
csource7(0x3)
csource7(0x4)
csource7(0x5)
`,
			output: `
syscall(SYS_csource7, /*flag=*/0ul);
syscall(SYS_csource7, /*flag=BIT_0*/1ul);
syscall(SYS_csource7, /*flag=BIT_1*/2ul);
syscall(SYS_csource7, /*flag=BIT_0_AND_1*/3ul);
syscall(SYS_csource7, /*flag=*/4ul);
syscall(SYS_csource7, /*flag=BIT_0|0x4*/5ul);
`,
		},

		{
			input: `
csource0(0xffffffff)
csource8(0xffffffffffffffff)
`,
			output: `
syscall(SYS_csource0, /*num=*/(intptr_t)-1);
syscall(SYS_csource8, /*num=*/(intptr_t)-1);
`,
		},
		{
			input: `
csource0(0xffffffff)
csource8(0xffffffffffffffff)
`,
			output: `
syscall(SYS_csource0, /*num=*/(intptr_t)-1);
syscall(SYS_csource8, /*num=*/(intptr_t)-1);
`,
			target: target32,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if test.target == nil {
				test.target = target64
			}
			p, err := test.target.Deserialize([]byte(test.input), prog.Strict)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &context{
				p:         p,
				target:    test.target,
				sysTarget: targets.Get(test.target.OS, test.target.Arch),
			}
			// Disable comment generation, as it's not the focus of these tests.
			// This simplifies the expected output. For tests covering comments, see
			// /pkg/csource/syscall_generation_test.go.
			calls, _, err := ctx.generateProgCalls(p, false, false, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			got := regexp.MustCompile(`(\n|^)\t`).ReplaceAllString(strings.Join(calls, ""), "\n")
			if test.output != got {
				t.Fatalf("input:\n%v\nwant:\n%v\ngot:\n%v", test.input, test.output, got)
			}
		})
	}
}

func generateSandboxFunctionSignatureTestCase(t *testing.T, sandbox string, sandboxArg int, expected, message string) {
	actual := generateSandboxFunctionSignature(sandbox, sandboxArg, &context{})
	assert.Equal(t, actual, expected, message)
}

func TestGenerateSandboxFunctionSignature(t *testing.T) {
	// This test-case intentionally omits the following edge cases:
	// - sandbox name as whitespaces, tabs
	// - control chars \r, \n and unprintables
	// - unsuitable chars - punctuation, emojis, '#', '*', etc
	// - character case mismatching function prototype defined in common_linux.h.
	//   For example 'do_sandbox_android' and 'AnDroid'.
	// - non english letters, unicode compound characters
	// and focuses on correct handling of sandboxes supporting and not 'sandbox_arg'
	// config setting.
	generateSandboxFunctionSignatureTestCase(t,
		"",        // sandbox name
		0,         // sandbox arg
		"loop();", // expected
		"Empty sandbox name should produce 'loop();'")

	generateSandboxFunctionSignatureTestCase(t,
		"abrakadabra",               // sandbox name
		0,                           // sandbox arg
		"do_sandbox_abrakadabra();", // expected
		"Empty sandbox name should produce 'loop();'")

	generateSandboxFunctionSignatureTestCase(t,
		"android",                    // sandbox name
		-1234,                        // sandbox arg
		"do_sandbox_android(-1234);", // expected
		"Android sandbox function requires an argument")
}

func TestLoopIdenticalCalls(t *testing.T) {
	calls := []string{
		"\tcall_a();\n",
		"\tcall_a();\n",
		"\tcall_a();\n",
		"\tcall_b();\n",
		"\tcall_b();\n",
	}
	got := strings.Join(loopIdenticalCalls(calls, 3), "")
	if !strings.Contains(got, "csb_runtime_loop < 3") {
		t.Fatalf("missing loop for run of 3:\n%s", got)
	}
	if strings.Contains(got, "csb_runtime_loop < 2") {
		t.Fatalf("unexpected loop for run below threshold:\n%s", got)
	}

	ctx := &context{opts: Options{RuntimeLoops: true, RuntimeLoopMin: 3, Threaded: true}}
	got = ctx.generateSyscalls(calls, false)
	if strings.Contains(got, "csb_runtime_loop") {
		t.Fatalf("threaded generation must retain one fragment per switch case:\n%s", got)
	}
	for i := range calls {
		if !strings.Contains(got, fmt.Sprintf("case %d:", i)) {
			t.Fatalf("missing case %d after runtime-loop generation:\n%s", i, got)
		}
	}
}

func TestCSBHelpersNamespaced(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("syz_csb_io_setup()\nsyz_csb_thread_create_join()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syz_csb_io_setup", "syz_csb_thread_create_join"} {
		assert.GreaterOrEqual(t, strings.Count(string(src), "UNIQUE_FUNC("+name+")"), 2)
	}
}
