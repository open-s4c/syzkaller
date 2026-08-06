// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"
)

func TestCSBTracksRawIoUringWithoutMmap(t *testing.T) {
	src := csbSource(t, "r0 = io_uring_setup$auto(0x1, &(0x7f0000000000)={0x0, 0x0, 0x4000})\n"+
		"io_uring_enter(r0, 0x1, 0x0, 0x0, 0x0, 0x0)\n", false)
	requireCSource(t, src, "/*to_submit=*/0")
}
