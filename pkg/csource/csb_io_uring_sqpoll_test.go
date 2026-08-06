// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"
)

func TestCSBClearsIoUringSQPoll(t *testing.T) {
	src := csbSource(t, "io_uring_setup(0x1, &(0x7f0000000000)={0x0, 0x0, 0x6})\n", false)
	requireCSource(t, src, "&= ~6")
}
