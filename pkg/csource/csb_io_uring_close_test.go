// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"
)

func TestCSBSanitizesIoUringClose(t *testing.T) {
	src := csbSource(t, "syz_io_uring_submit(0x0, 0x0, &(0x7f0000000000)={0x13, 0x0, 0x2})\n", false)
	requireCSource(t, src, "memcpy(csb_sqe_0")
	requireCSource(t, src, "== 19 &&")
}
