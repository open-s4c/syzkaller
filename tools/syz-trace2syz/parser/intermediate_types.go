// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"bytes"
	"fmt"
)

// TraceTree struct contains intermediate representation of trace.
// If a trace is multiprocess it constructs a trace for each type.
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
}

// NewTraceTree initializes a TraceTree.
func NewTraceTree() *TraceTree {
	return &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
	}
}

func (tree *TraceTree) add(call *Syscall) {
	if tree.RootPid == 0 {
		tree.RootPid = call.Pid
	}
	if tree.TraceMap[call.Pid] == nil {
		tree.TraceMap[call.Pid] = new(Trace)
	}
	c := tree.TraceMap[call.Pid].add(call)
	if !c.Paused && c.Ret > 0 {
		switch c.CallName {
		case "clone", "clone3", "fork", "vfork":
			tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
		}
	}
}

// Trace is just a list of system calls
type Trace struct {
	Calls   []*Syscall
	RootPid int64
}

func (trace *Trace) add(call *Syscall) *Syscall {
	if trace.RootPid == 0 {
		trace.RootPid = call.Pid
	}
	if !call.Resumed {
		trace.Calls = append(trace.Calls, call)
		return call
	}
	lastCall := trace.Calls[len(trace.Calls)-1]
	lastCall.Args = append(lastCall.Args, call.Args...)
	lastCall.Paused = false
	lastCall.Ret = call.Ret
	return lastCall
}

// IrType is the intermediate representation of the strace output
// Every argument of a system call should be represented in an intermediate type
type IrType interface {
	String() string
}

// Syscall struct is the IR type for any system call
type Syscall struct {
	CallName string
	Args     []IrType
	Pid      int64
	Ret      int64
	Paused   bool
	Resumed  bool
}

// NewSyscall - constructor
func NewSyscall(pid int64, name string, args []IrType, ret int64, paused, resumed bool) (sys *Syscall) {
	return &Syscall{
		CallName: name,
		Args:     args,
		Pid:      pid,
		Ret:      ret,
		Paused:   paused,
		Resumed:  resumed,
	}
}

func (s *Syscall) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Pid: -%v-Name: -%v-", s.Pid, s.CallName)
	for _, typ := range s.Args {
		fmt.Fprintf(buf, "-%v-", typ)
	}
	fmt.Fprintf(buf, "-Ret: %d\n", s.Ret)
	return buf.String()
}

// GroupType contains arrays and structs
type GroupType struct {
	Elems []IrType
}

func newGroupType(elems []IrType) (typ *GroupType) {
	return &GroupType{Elems: elems}
}

func newBPFGroupType(macro string, elems []IrType) *GroupType {
	if macro == "BPF_STMT" && len(elems) == 2 {
		elems = []IrType{elems[0], Constant(0), Constant(0), elems[1]}
	} else if macro == "BPF_JUMP" && len(elems) == 4 {
		elems = []IrType{elems[0], elems[2], elems[3], elems[1]}
	}
	return newGroupType(elems)
}

func bpfFlagConstant(flag string) (Constant, bool) {
	value, ok := map[string]uint64{
		"BPF_LD": 0x00, "BPF_LDX": 0x01, "BPF_ST": 0x02, "BPF_STX": 0x03,
		"BPF_ALU": 0x04, "BPF_JMP": 0x05, "BPF_RET": 0x06, "BPF_MISC": 0x07,
		"BPF_W": 0x00, "BPF_H": 0x08, "BPF_B": 0x10, "BPF_DW": 0x18,
		"BPF_IMM": 0x00, "BPF_ABS": 0x20, "BPF_IND": 0x40, "BPF_MEM": 0x60,
		"BPF_LEN": 0x80, "BPF_MSH": 0xa0,
		"BPF_ADD": 0x00, "BPF_SUB": 0x10, "BPF_MUL": 0x20, "BPF_DIV": 0x30,
		"BPF_OR": 0x40, "BPF_AND": 0x50, "BPF_LSH": 0x60, "BPF_RSH": 0x70,
		"BPF_NEG": 0x80, "BPF_MOD": 0x90, "BPF_XOR": 0xa0, "BPF_MOV": 0xb0,
		"BPF_ARSH": 0xc0, "BPF_END": 0xd0,
		"BPF_JA": 0x00, "BPF_JEQ": 0x10, "BPF_JGT": 0x20, "BPF_JGE": 0x30,
		"BPF_JSET": 0x40, "BPF_K": 0x00, "BPF_X": 0x08, "BPF_A": 0x10,
		"BPF_TAX": 0x00, "BPF_TXA": 0x80,
		"SECCOMP_RET_KILL_THREAD": 0x00000000, "SECCOMP_RET_KILL": 0x00000000,
		"SECCOMP_RET_TRAP": 0x00030000, "SECCOMP_RET_ERRNO": 0x00050000,
		"SECCOMP_RET_USER_NOTIF": 0x7fc00000, "SECCOMP_RET_TRACE": 0x7ff00000,
		"SECCOMP_RET_LOG": 0x7ffc0000, "SECCOMP_RET_ALLOW": 0x7fff0000,
		"SECCOMP_RET_KILL_PROCESS": 0x80000000,
		"SECCOMP_RET_ACTION_FULL":  0xffff0000, "SECCOMP_RET_DATA": 0x0000ffff,
	}[flag]
	return Constant(value), ok
}

// String implements IrType String()
func (a *GroupType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

// Constant represents all evaluated expressions produced by strace
// Constant types are evaluated at parse time
type Constant uint64

func (c Constant) String() string {
	return fmt.Sprintf("%#v", c)
}

func (c Constant) Val() uint64 {
	return uint64(c)
}

// BufferType contains strings
type BufferType struct {
	Val string
}

func newBufferType(val string) *BufferType {
	return &BufferType{Val: val}
}

// String implements IrType String()
func (b *BufferType) String() string {
	return fmt.Sprintf("Buffer: %v with length: %v\n", b.Val, len(b.Val))
}
