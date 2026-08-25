// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

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
		assertCSBExecIdentifiersArePlain(t, src)
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
	assert.Contains(t, string(src), "syz_reapply_affinity()")
	assert.Contains(t, string(src), "pthread_key_create")
	assert.Contains(t, string(src), "pthread_getspecific")
	assert.Contains(t, string(src), "pthread_setspecific")
	assert.Contains(t, string(src), "pthread_key_delete")
	assert.Contains(t, string(src), "sched_getaffinity(0, mask_size, affinity->mask)")
	assert.Contains(t, string(src), "AffinityMaskState* am = &am_state;")
	assert.Contains(t, string(src), "pthread_key_create(&am->affinity_mask_key, free)")
	assert.Contains(t, string(src), "cleanup_affinity_mask();")
}

func TestCSBEmptyNetworkMetadata(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		prog string
		meta string
	}{
		{
			name: "connect_only",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)\n",
			meta: "CLIENT_SEQ=\"1r1\"\n",
		},
		{
			name: "accept_only",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"listen(r0, 0x1)\n" +
				"accept$inet(r0, 0x0, 0x0)\n",
			meta: "SERVER_SEQ=\"1r1\"\n",
		},
		{
			name: "identical_clients",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)\n" +
				"r1 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r1, &(0x7f0000000040)={0x2, 0x1f90}, 0x10)\n",
			meta: "CLIENT_SEQ=\"1r1\", \"1r1\"\n",
		},
		{
			name: "unix_connect_only",
			prog: "r0 = socket$unix(0x1, 0x1, 0x0)\n" +
				"connect$unix(r0, &(0x7f0000000000)=@file={0x1, 'temp\\x00'}, 0x6e)\n",
		},
		{
			name: "unix_accept_only",
			prog: "r0 = socket$unix(0x1, 0x1, 0x0)\n" +
				"listen(r0, 0x1)\n" +
				"accept$unix(r0, 0x0, 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), prog.NonStrict)
			if err != nil {
				t.Fatal(err)
			}
			_, meta, err := Write(p, Options{CSB: true, Slowdown: 1})
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.meta, meta)
		})
	}
}

func TestCSBRestartsSetupOnlyServer(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		prog    string
		restart bool
	}{
		{
			name: "setup_only",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"listen(r0, 0x1)\n",
			restart: true,
		},
		{
			name: "server_with_dispatch_work",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"listen(r0, 0x1)\n" +
				"accept$inet(r0, 0x0, 0x0)\n",
		},
	}
	const restart = "(void)bm_target_dereg(ctx);\n\t(void)bm_target_reg(ctx);"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), prog.NonStrict)
			if err != nil {
				t.Fatal(err)
			}
			for idx := range p.Calls {
				p.AnnotateResources(idx)
			}
			src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
			if err != nil {
				t.Fatal(err)
			}
			if test.restart {
				assert.Contains(t, string(src), restart)
			} else {
				assert.NotContains(t, string(src), restart)
			}
		})
	}
}

func TestCSBRejectsUnsupportedNetworkTopology(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "client_and_server",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)\n" +
				"r1 = socket$inet(0x2, 0x1, 0x0)\n" +
				"listen(r1, 0x1)\n" +
				"accept$inet(r1, 0x0, 0x0)\n",
		},
		{
			name: "different_clients",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)\n" +
				"read(r0, &(0x7f0000000040), 0x1)\n" +
				"r1 = socket$inet(0x2, 0x1, 0x0)\n" +
				"connect$inet(r1, &(0x7f0000000080)={0x2, 0x1f90}, 0x10)\n" +
				"read(r1, &(0x7f00000000c0), 0x2)\n",
		},
		{
			name: "multiple_servers",
			prog: "r0 = socket$inet(0x2, 0x1, 0x0)\n" +
				"listen(r0, 0x1)\n" +
				"accept$inet(r0, 0x0, 0x0)\n" +
				"accept$inet(r0, 0x0, 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), prog.NonStrict)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Write(p, Options{CSB: true, Slowdown: 1})
			assert.ErrorIs(t, err, ErrUnsupportedCSBNetwork)
		})
	}
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
	assert.NotContains(t, calls[1], "/*size=*/ctx->r[0]")
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
	ctx := &context{
		p: p, opts: Options{CSB: true, Slowdown: 1}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch), calls: make(map[string]uint64),
	}
	local := ctx.localIOResources(decoded)
	assert.True(t, local[decoded.Calls[3].Index])
	calls, _ := ctx.generateCalls(decoded, false, false, nil, nil, nil, false)
	assert.Contains(t, calls[1], "(ctx->r[0] | O_NONBLOCK)")
	assert.Contains(t, calls[2], "syscall(__NR_open")
	assert.Contains(t, calls[3], "intptr_t csb_fcntl_cmd_3 = ctx->r[0]")
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
	publish := strings.Index(string(src), "ctx->r[0] = fd")
	if setNonblock == -1 || publish == -1 || setNonblock > publish {
		t.Fatalf("descriptor publication precedes nonblocking setup:\n%s", src)
	}
}

func TestCSBClosesUnusedFDResults(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	for call, want := range map[string]bool{
		"openat": true,
		"socket": true,
		"getpid": false,
	} {
		assert.Equal(t, want, returnsFD(target.SyscallMap[call]), call)
	}
	p, err := target.Deserialize([]byte(
		"openat(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', 0x0, 0x0)\n"+
			"socket(0x2, 0x1, 0x0)\n"+
			"dup(0x3)\n"+
			"dup3(0x3, 0x5, 0x0)\n"+
			"getpid()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{
		{CSB: true, Trace: true, Slowdown: 1},
		{CSB: true, Threaded: true, Trace: true, Slowdown: 1},
	} {
		src, _, err := Write(p, opts)
		if err != nil {
			t.Fatal(err)
		}
		assert.Contains(t, string(src), "intptr_t res = 0;\n\tV_UNUSED(res);")
		assert.Equal(t, 4, strings.Count(string(src), "if (res > 2) close((int)res);"))
	}
}

func TestCSBPrepareRejectsHookOverwrite(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	opts := emitCallOpts{hooks: emitCallHooks{
		formatCallBody: func(string, string, []string, bool) (string, bool) {
			return "", false
		},
	}}
	call := prog.ExecCall{Meta: target.SyscallMap["dup2"]}
	assert.PanicsWithValue(t, "prepareDup: formatCallBody hook is already installed", func() {
		new(context).prepareDup(call, &opts)
	})
}

func TestCSBDoesNotCloseUsedFDResultImmediately(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./file\\x00', 0x0, 0x0)\n"+
			"read(r0, &(0x7f0000000040), 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Trace: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.NotContains(t, string(src), "if (res > 2) close((int)res);")
	assert.Contains(t, string(src),
		"{ uint32_t fd = (uint32_t)ctx->r[0]; if (fd > 2) close(fd); }")
}

func assertCSBExecIdentifiersArePlain(t *testing.T, src []byte) {
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
	if bytes.Contains(code, []byte("UNIQUE_")) {
		t.Fatal("generated source still contains UNIQUE_* naming macros")
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
