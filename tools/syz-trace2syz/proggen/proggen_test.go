// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package proggen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func TestParse(t *testing.T) {
	type Test struct {
		input  string
		output string
	}
	tests := []Test{
		{`
open("file", 66) = 3
write(3, "somedata", 8) = 8
`, `
r0 = open(&(0x7f0000000000)='file\x00', 0x42, 0x0)[3]
write(r0, &(0x7f0000000040)='somedata', 0x8)[8]
`,
		}, {`
pipe([5,6]) = 0
write(6, "\xff\xff\xfe\xff", 4) = 4
`, `
pipe(&(0x7f0000000000)={0xffffffffffffffff, <r0=>0xffffffffffffffff})[0]
write(r0, &(0x7f0000000040)="fffffeff", 0x4)[4]
`,
		}, {`
pipe({0x0, 0x1}) = 0
shmget(0x0, 0x1, 0x2, 0x3) = 0
`, `
pipe(&(0x7f0000000000))[0]
shmget(0x0, 0x1, 0x2, &(0x7f0000001000/0x1)=nil)[0]
`,
		}, {`
socket(29, 3, 1) = 3
getsockopt(-1, 132, 119, 0x200005c0, [14]) = -1 EBADF (Bad file descriptor)
`, `
socket$can_raw(0x1d, 0x3, 0x1)[3]
getsockopt$inet_sctp6_SCTP_RESET_STREAMS(0xffffffffffffffff, 0x84, 0x77, &(0x7f0000000000), &(0x7f0000000040)=0xe)[-1]
`,
		}, {`
inotify_init() = 2
open("tmp", 66) = 3
inotify_add_watch(3, "\x2e", 0xfff) = 3
write(3, "temp", 4) = 4
inotify_rm_watch(2, 3) = 0
`, `
r0 = inotify_init()[2]
r1 = open(&(0x7f0000000000)='tmp\x00', 0x42, 0x0)[3]
r2 = inotify_add_watch(r1, &(0x7f0000000040)='.\x00', 0xfff)[3]
write(r1, &(0x7f0000000080)='temp', 0x4)[4]
inotify_rm_watch(r0, r2)[0]
`,
		}, {`
socket(1, 1, 0) = 3
socket(1, 1 | 2048, 0) = 3
socket(1, 1 | 524288, 0) = 3
socket(1, 1 | 524288, 0) = 3
`, `
socket$unix(0x1, 0x1, 0x0)[3]
socket$unix(0x1, 0x801, 0x0)[3]
socket$unix(0x1, 0x80001, 0x0)[3]
socket$unix(0x1, 0x80001, 0x0)[3]
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=2, sin_port=37957, sin_addr=0x0}, 16) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)[3]
connect(r0, &(0x7f0000000040)=@in={0x2, 0x9445}, 0x10)[-1]
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=1, sun_path="temp"}, 110) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)[3]
connect(r0, &(0x7f0000000040)=@un=@file={0x1, 'temp\x00'}, 0x6e)[-1]
`,
		}, {`
open("temp", 1) = 3
bind(5, {sa_family=16, nl_pid=0x2, nl_groups=00000003}, 12)  = -1
`, `
open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)[3]
bind(0x5, &(0x7f0000000040)=@nl=@proc={0x10, 0x2, 0x3}, 0xc)[-1]
`,
		}, {`
socket(17, 3, 768)  = 3
ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0
`, `
r0 = socket$packet(0x11, 0x3, 0x300)[3]
ioctl$sock_ifreq(r0, 0x8927, &(0x7f0000000000)={'lo\x00'})[0]
`,
		}, {`
socket(1, 1, 0) = 3
connect(3, {sa_family=1, sun_path="temp"}, 110) = -1 ENOENT (Bad file descriptor)
`, `
r0 = socket$unix(0x1, 0x1, 0x0)[3]
connect$unix(r0, &(0x7f0000000000)=@file={0x1, 'temp\x00'}, 0x6e)[-1]
`,
		}, {`
socket(1, 1, 0) = 3
`, `
socket$unix(0x1, 0x1, 0x0)[3]
`,
		}, {`
socket(2, 1, 0) = 5
ioctl(5, 21537, [1]) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[5]
ioctl$int_in(r0, 0x5421, &(0x7f0000000000)=0x1)[0]
`,
		}, {`
socket(2, 1, 0) = 3
setsockopt(3, 1, 2, [1], 4) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
setsockopt$sock_int(r0, 0x1, 0x2, &(0x7f0000000000)=0x1, 0x4)[0]
`,
		}, {`
9795  socket(17, 3, 768)  = 3
9795  ioctl(3, 35123, {ifr_name="\x6c\x6f", }) = 0
`, `
<9795>r0 = socket$packet(0x11, 0x3, 0x300)[3]
<9795>ioctl$ifreq_SIOCGIFINDEX_batadv_hard(r0, 0x8933, &(0x7f0000000000)={'lo\x00'})[0]
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)[3]
connect(r0, &(0x7f0000000040)=@in={0x2, 0x4594}, 0x10)[-1]
`,
		}, {`
ioprio_get(1, 0) = 4
`, `
ioprio_get$pid(0x1, 0x0)[4]
`,
		}, {`
socket(17, 2, 768) = 3
`, `
socket$packet(0x11, 0x2, 0x300)[3]
`,
		}, {`
socket(2, 1, 0) = 3
connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
connect$inet(r0, &(0x7f0000000000)={0x2, 0x4594}, 0x10)[0]
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x73\x6e\x64\x2f\x73\x65\x71", 0) = 3
fsetxattr(3, "\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x73\x65\x6c\x69\x6e\x75\x78","\x73\x79\x73", 4, 0) = 0
`, `
r0 = openat$sndseq(0xffffffffffffff9c, &(0x7f0000000000), 0x0)[3]
fsetxattr(r0, &(0x7f0000000040)=@known='security.selinux\x00', &(0x7f0000000080)='sys\x00', 0x4, 0x0)[0]
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x7f\x00\x00\x01"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90, @rand_addr=0x7f000001}, 0x10)[-1]
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00\x00\x00\x00\x7f\x00\x00\x01"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90, @rand_addr=0x7f000001}, 0x10)[-1]
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)[-1]
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)[3]
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)[-1]
`,
		}, {`
connect(-1, {sa_family=0xa, sin6_port="\x30\x39",` +
			`sin6_flowinfo="\x07\x5b\xcd\x7a",` +
			`sin6_addr="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",` +
			`sin6_scope_id=4207869677}, 28) = -1
`, `
connect(0xffffffffffffffff, &(0x7f0000000000)=@in6={0xa, 0x3039, 0x75bcd7a, @rand_addr='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', 0xfacefeed}, 0x1c)[-1]
`,
		}, {`
connect(-1, {sa_family=0xa, sin6_port="\x30\x39",` +
			` sin6_flowinfo="\x07\x5b\xcd\x7a",` +
			` sin6_addr="\x00\x12\x00\x34\x00\x56\x00\x78\x00\x90\x00\xab\x00\xcd\x00\xef",` +
			` sin6_scope_id=4207869677}, 28) = -1
`, `
connect(0xffffffffffffffff, &(0x7f0000000000)=@in6={0xa, 0x3039, 0x75bcd7a, @rand_addr='\x00\x12\x004\x00V\x00x\x00\x90\x00\xab\x00\xcd\x00\xef', 0xfacefeed}, 0x1c)[-1]
`,
		}, {`
socket(0xa, 0x2, 0) = 3
sendto(3, "", 0, 0, {sa_family=0xa, sin6_port="\x4e\x24", sin6_flowinfo="\x00\x00\x00\x00",` +
			` sin6_addr="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",` +
			` sin6_scope_id=0}, 28) = -1
`, `
r0 = socket$inet6_udp(0xa, 0x2, 0x0)[3]
sendto$inet6(r0, &(0x7f0000000000), 0x0, 0x0, &(0x7f0000000040)={0xa, 0x4e24}, 0x1c)[-1]
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x7a\x65\x72\x6f", "1") = 3
`, `
openat$zero(0xffffffffffffff9c, &(0x7f0000000000), 0x31, 0x0)[3]
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x6c\x6f\x6f\x70\x30", 0) = 3
`, `
syz_open_dev$loop(&(0x7f0000000000)='/dev/loop0\x00', 0x0, 0x0)[3]
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x6c\x6f\x6f\x70\x31", 0) = 3
`, `
syz_open_dev$loop(&(0x7f0000000000)='/dev/loop1\x00', 0x1, 0x0)[3]
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x62\x75\x73\x2f\x75\x73\x62\x2f\x30\x30\x31\x2f\x30\x30\x31", 0) = 3
`, `
syz_open_dev$usbfs(&(0x7f0000000000)='/dev/bus/usb/001/001\x00', 0xb, 0x0)[3]
`,
		}, {`
openat(0xffffffffffffff9c, "\x2f\x64\x65\x76\x2f\x7a\x65\x72\x6f", 0x31, 0) = 3
`, `
openat$zero(0xffffffffffffff9c, &(0x7f0000000000), 0x31, 0x0)[3]
`}, {`
socket(0xa, 0x1, 0) = 3
setsockopt(3, 0x29, 0x2a, {gr_interface=0, gr_group={sa_family=0xa, sin6_port="\x00\x00", sin6_flowinfo=` +
			`"\x00\x00\x00\x00", sin6_addr="\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",` +
			` sin6_scope_id=0}}, 136) = 0
`, `
r0 = socket$inet6_tcp(0xa, 0x1, 0x0)[3]
setsockopt$inet6_MCAST_JOIN_GROUP(r0, 0x29, 0x2a, &(0x7f0000000000)={0x0, {{0xa, 0x0, 0x0, @rand_addr='\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'}}}, 0x88)[0]
`,
		}, {
			`
openat(-100, "\x2f\x64\x65\x76\x2f\x72\x74\x63\x30", 0) = 3
ioctl(3, 0x4028700f, {enabled=0, pending=0, time={tm_sec=0, tm_min=0, tm_hour=0, tm_mday=0, tm_mon=65536,` +
				`tm_year=20865, tm_wday=0, tm_yday=0, tm_isdst=0}}) = -1 EINVAL (Invalid argument)`, `
r0 = openat$rtc(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)[3]
ioctl$RTC_WKALM_SET(r0, 0x4028700f, &(0x7f0000000040)={0x0, 0x0, {0x0, 0x0, 0x0, 0x0, 0x10000, 0x5181}})[-1]
`,
		},
	}
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	for _, test := range tests {
		input := strings.TrimSpace(test.input)
		tree, _, err := parser.ParseData([]byte(input), true, -1)
		if err != nil {
			t.Fatal(err)
		}
		p := genProg(tree.TraceMap[tree.RootPid], target, false, true, false)
		if p == nil {
			t.Fatalf("failed to parse trace")
		}
		got := string(bytes.TrimSpace(p.Serialize()))
		want := strings.TrimSpace(test.output)
		if want != got {
			t.Errorf("input:\n%v\n\nwant:\n%v\n\ngot:\n%v", input, want, got)
		}
	}
}

func TestGenBufferDeterministicOutSize(t *testing.T) {
	tests := []struct {
		name  string
		kind  prog.BufferKind
		begin uint64
		end   uint64
		want  uint64
	}{
		{
			name: "rand",
			kind: prog.BufferBlobRand,
			want: 64,
		},
		{
			name:  "range",
			kind:  prog.BufferBlobRange,
			begin: 16,
			end:   80,
			want:  48,
		},
		{
			name:  "odd range",
			kind:  prog.BufferBlobRange,
			begin: 1,
			end:   4,
			want:  2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			syzType := &prog.BufferType{
				TypeCommon: prog.TypeCommon{
					TypeName:  "buffer",
					TypeAlign: 1,
					IsVarlen:  true,
				},
				Kind:       test.kind,
				RangeBegin: test.begin,
				RangeEnd:   test.end,
			}
			prog.RestoreLinks(nil, nil, []prog.Type{syzType})

			ctx := &context{}
			arg := ctx.genBuffer(syzType, prog.DirOut, parser.Constant(0x1000))
			if got := arg.Size(); got != test.want {
				t.Fatalf("got size %d, want %d", got, test.want)
			}
		})
	}
}

func TestMadviseFromTrace(t *testing.T) {
	p := parseSingleProg(t, `
madvise(0xffff7fb57000, 8192, 0x4) = 0
madvise(0xffff7fb57000, 2097152, 0x64) = 0
`)
	got := string(bytes.TrimSpace(p.Serialize()))
	want := strings.TrimSpace(`
madvise(&(0x7f0000000000/0x2000)=nil, 0x2000, 0x4)[0]
madvise(&(0x7f0000002000/0x100000)=nil, 0x100000, 0x0)[0]
`)
	if got != want {
		t.Fatalf("want:\n%v\n\ngot:\n%v", want, got)
	}
}

func TestMadviseTraceToCSBHeader(t *testing.T) {
	p := parseSingleProg(t, `
madvise(0xffff7fb57000, 4096, 0x8) = 0
`)
	src, _, err := csource.Write(p, csource.Options{
		Slowdown: 1,
		CSB:      true,
		Trace:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "syscall(__NR_madvise") {
		t.Fatalf("generated CSB header does not contain madvise syscall:\n%s", src)
	}
}

func TestSafeReplayDroppedSyscallsFromTrace(t *testing.T) {
	p := parseSingleProg(t, `
futex(0x1234, 0x81, 2147483647) = 0
mmap(NULL, 8192, 0x3, 0x22, -1, 0) = 0x70000000
mprotect(0x70000000, 8192, 0x1) = 0
msync(0x70000000, 8192, 0x4) = 0
munmap(0x70000000, 8192) = 0
mremap(0x70000000, 4096, 8192, 1) = 0x70002000
rt_sigprocmask(0, [], NULL, 8) = 0
rt_sigtimedwait([], NULL, {tv_sec=0, tv_nsec=0}, 8) = -1 EAGAIN (Resource temporarily unavailable)
set_robust_list(0x1234, 24) = 0
set_tid_address(0x1234) = 1234
wait4(-1, NULL, 1, NULL) = -1 ECHILD (No child processes)
wait(NULL) = -1 ECHILD (No child processes)
`)
	serialized := string(p.Serialize())
	for _, want := range []string{
		"futex(",
		"mprotect(",
		"msync(",
		"munmap(",
		"mremap(",
		"rt_sigprocmask(",
		"rt_sigtimedwait(",
		"set_robust_list(",
		"set_tid_address(",
		"wait4(",
	} {
		if !strings.Contains(serialized, want) {
			t.Fatalf("generated program missing %q:\n%s", want, serialized)
		}
	}
	if got := strings.Count(serialized, "mmap("); got != 3 {
		t.Fatalf("got %d mmap calls, want 3 in:\n%s", got, serialized)
	}
	if got := strings.Count(serialized, "wait4("); got != 2 {
		t.Fatalf("got %d wait4 calls, want 2 in:\n%s", got, serialized)
	}
	for _, call := range p.Calls {
		switch call.Meta.CallName {
		case "rt_sigtimedwait":
			these := call.Args[0].(*prog.PointerArg).Address
			timeout := call.Args[2].(*prog.PointerArg).Address
			if these == timeout {
				t.Fatalf("rt_sigtimedwait default pointers alias at %#x", these)
			}
		case "mmap", "mprotect", "msync", "munmap":
			if got, want := call.Args[0].(*prog.PointerArg).VmaSize, call.Args[1].(*prog.ConstArg).Val; got != want {
				t.Fatalf("%s VMA size = %#x, want byte length %#x", call.Meta.CallName, got, want)
			}
		case "mremap":
			for _, pair := range [][2]int{{0, 1}, {4, 2}} {
				if got, want := call.Args[pair[0]].(*prog.PointerArg).VmaSize,
					call.Args[pair[1]].(*prog.ConstArg).Val; got != want {
					t.Fatalf("mremap VMA size = %#x, want byte length %#x", got, want)
				}
			}
		}
	}

	src, _, err := csource.Write(p, csource.Options{
		Slowdown: 1,
		CSB:      true,
		Trace:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	header := string(src)
	for _, want := range []string{
		"__NR_futex",
		"__NR_mmap",
		"__NR_mprotect",
		"__NR_msync",
		"__NR_munmap",
		"__NR_mremap",
		"__NR_rt_sigprocmask",
		"__NR_rt_sigtimedwait",
		"__NR_set_robust_list",
		"__NR_set_tid_address",
		"__NR_wait4",
	} {
		if !strings.Contains(header, want) {
			t.Fatalf("generated CSB header missing %q:\n%s", want, header)
		}
	}
}

func TestTaskCreationLifecycleFromTrace(t *testing.T) {
	tests := []struct {
		name  string
		trace string
		want  string
	}{
		{"pthread clone", `clone(child_stack=0x1234, flags=0x10f00, child_tidptr=0) = 2`, "syz_csb_thread_create_join()"},
		{"pthread clone3", `clone3({flags=0x10000, exit_signal=0}, 88) = 2`, "syz_csb_thread_create_join()"},
		{"process clone", `clone(child_stack=0x1234, flags=0x11) = 2`, "syz_csb_fork_wait()"},
		{"vfork clone", `clone(child_stack=0x1234, flags=0x4111) = 2`, "syz_csb_vfork_wait()"},
		{"fork", `fork() = 2`, "syz_csb_fork_wait()"},
		{"vfork", `vfork() = 2`, "syz_csb_vfork_wait()"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := parseSingleProg(t, test.trace)
			if got := strings.TrimSpace(string(p.Serialize())); got != test.want+"[2]" {
				t.Fatalf("got %q, want %q", got, test.want+"[2]")
			}
			src, _, err := csource.Write(p, csource.Options{Slowdown: 1, CSB: true, Trace: true})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(src), test.want) {
				t.Fatalf("generated CSB header missing %q:\n%s", test.want, src)
			}
		})
	}
}

func TestExecLifecycleCall(t *testing.T) {
	tests := []struct {
		call *parser.Syscall
		want string
	}{
		{parser.NewSyscall(1, "execve", nil, 0, false, false), "syz_csb_execve"},
		{parser.NewSyscall(1, "execveat", nil, 0, false, false), "syz_csb_execveat"},
		{parser.NewSyscall(1, "execveat", []parser.IrType{nil, &parser.BufferType{Val: ""}, nil, nil, parser.Constant(0x1000)},
			0, false, false), "syz_csb_fexecve"},
		{parser.NewSyscall(1, "execveat", []parser.IrType{nil, &parser.BufferType{Val: "/bin/true"}, nil, nil,
			parser.Constant(0x1000)}, 0, false, false), "syz_csb_execveat"},
	}
	for _, test := range tests {
		if got := execLifecycleCall(test.call); got != test.want {
			t.Errorf("%s mapped to %q, want %q", test.call.CallName, got, test.want)
		}
	}
}

func TestSkipOnlyRootBootstrapExec(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	trace := &parser.Trace{Calls: []*parser.Syscall{
		parser.NewSyscall(1, "execve", nil, -1, false, false),
		parser.NewSyscall(1, "getpid", nil, 1, false, false),
		parser.NewSyscall(1, "execveat", nil, 0, false, false),
		parser.NewSyscall(1, "getppid", nil, 1, false, false),
		parser.NewSyscall(1, "execve", nil, 0, false, false),
	}}

	root := string(genProg(trace, target, false, false, true).Serialize())
	if got := strings.Count(root, "syz_csb_execve"); got != 2 {
		t.Fatalf("root contains %d exec lifecycles, want 2:\n%s", got, root)
	}
	if !strings.Contains(root, "getppid") {
		t.Fatalf("root lost calls after its skipped bootstrap exec:\n%s", root)
	}
	child := string(genProg(trace, target, false, false, false).Serialize())
	if got := strings.Count(child, "syz_csb_execve"); got != 2 {
		t.Fatalf("child contains %d exec lifecycles, want 2:\n%s", got, child)
	}
	if strings.Contains(child, "getppid") {
		t.Fatalf("child retained calls after its successful workload exec:\n%s", child)
	}
}

func TestSuccessfulExecTerminatesOnlyItsTID(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	trace := &parser.Trace{Calls: []*parser.Syscall{
		parser.NewSyscall(1, "execve", nil, 0, false, false),
		parser.NewSyscall(2, "getpid", nil, 2, false, false),
		parser.NewSyscall(2, "execveat", nil, 0, false, false),
		parser.NewSyscall(1, "getppid", nil, 1, false, false),
		parser.NewSyscall(2, "getuid", nil, 0, false, false),
	}}

	got := string(genProg(trace, target, false, false, false).Serialize())
	if lifecycles := strings.Count(got, "syz_csb_execve"); lifecycles != 2 {
		t.Fatalf("got %d exec lifecycles, want 2:\n%s", lifecycles, got)
	}
	if !strings.Contains(got, "getpid") {
		t.Fatalf("calls from a live interleaved TID were lost:\n%s", got)
	}
	if strings.Contains(got, "getppid") || strings.Contains(got, "getuid") {
		t.Fatalf("calls after successful exec remained in their TID:\n%s", got)
	}
}

func TestExitCallsAreSkipped(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	trace := &parser.Trace{Calls: []*parser.Syscall{
		parser.NewSyscall(1, "execve", nil, 0, false, false),
		parser.NewSyscall(2, "exit", []parser.IrType{parser.Constant(0)}, 0, false, false),
		parser.NewSyscall(3, "exit_group", []parser.IrType{parser.Constant(0)}, 0, false, false),
	}}

	got := string(genProg(trace, target, false, false, false).Serialize())
	if !strings.Contains(got, "syz_csb_execve()") {
		t.Fatalf("exec lifecycle was lost:\n%s", got)
	}
	if strings.Contains(got, "exit(") || strings.Contains(got, "exit_group(") {
		t.Fatalf("process termination call remained:\n%s", got)
	}
}

func parseSingleProg(t *testing.T, input string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	tree, _, err := parser.ParseData([]byte(strings.TrimSpace(input)), true, -1)
	if err != nil {
		t.Fatal(err)
	}
	p := genProg(tree.TraceMap[tree.RootPid], target, false, true, false)
	if p == nil {
		t.Fatal("failed to parse trace")
	}
	return p
}
