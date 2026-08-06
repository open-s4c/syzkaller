// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"
)

func TestCSBTracksAsyncRawIoUringAlias(t *testing.T) {
	src := csbSource(t, "r0 = io_uring_setup(0x1, &(0x7f0000000000))\n"+
		"r1 = openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)\n"+
		"io_uring_enter(r0, 0x1, 0x0, 0x0, 0x0, 0x0) (async)\n"+
		"dup2(r0, r1)\n"+
		"mmap(&(0x7f0000001000/0x1000)=nil, 0x1000, 0x3, 0x1, r1, 0x10000000)\n", true)
	requireCSource(t, src, "/*to_submit=*/0")
}
