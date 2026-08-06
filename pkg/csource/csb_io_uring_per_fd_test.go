// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"strings"
	"testing"
)

func TestCSBScopesRawIoUringPerDescriptor(t *testing.T) {
	src := csbSource(t, "r0 = io_uring_setup(0x1, &(0x7f0000000000))\n"+
		"mmap(&(0x7f0000001000/0x1000)=nil, 0x1000, 0x3, 0x1, r0, 0x10000000)\n"+
		"r1 = syz_io_uring_setup(0x1, &(0x7f0000002000), &(0x7f0000003000/0x1000)=nil, &(0x7f0000004000/0x1000)=nil)\n"+
		"io_uring_enter(r0, 0x1, 0x0, 0x0, 0x0, 0x0)\n"+
		"io_uring_enter(r1, 0x1, 0x0, 0x0, 0x0, 0x0)\n", false)
	if got := strings.Count(src, "/*to_submit=*/0"); got != 2 {
		t.Fatalf("guarded submissions: got %d, want 2", got)
	}
}
