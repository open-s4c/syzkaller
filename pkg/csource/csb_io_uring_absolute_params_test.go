// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestCSBRequiresAbsoluteIoUringParamsSanitizing(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("io_uring_setup(0x1, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "{(void*)(0x0), sizeof(csb_io_uring_params_0)}")
	assert.Contains(t, string(src), "SYS_process_vm_readv")
	assert.Contains(t, string(src), "SYS_process_vm_writev")
	assert.Contains(t, string(src),
		"csb_io_uring_params_read_0 < 0 && csb_io_uring_params_errno_0 == EFAULT")
	assert.Contains(t, string(src),
		"csb_io_uring_params_ok_0 ? (intptr_t)csb_io_uring_params_0 : (intptr_t)(0x0)")
	p, err = target.Deserialize([]byte("syz_io_uring_setup(0x1, &(0x7f0000000000)={0x0, 0x0, 0x2}, "+
		"&(0x7f0000001000/0x1000)=nil, &(0x7f0000002000/0x1000)=nil)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err = Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "{(void*)(0x200000000000+PTR_OFFSET), sizeof(csb_io_uring_params_0)}")
	assert.Contains(t, string(src), "*(uint32_t*)(csb_io_uring_params_0 + 1) &= ~6")
	assert.Contains(t, string(src), "(intptr_t)(0x200000000000+PTR_OFFSET)")
}
