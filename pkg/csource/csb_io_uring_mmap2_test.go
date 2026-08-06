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

func TestCSBRequiresMmap2RingTracking(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.I386)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = io_uring_setup(0x1, &(0x7f0000000000))\n"+
		"mmap2$auto(0x20000000, 0x1000, 0x3, 0x1, r0, 0x10000)\n"+
		"io_uring_enter(r0, 0x1, 0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "/*to_submit=*/0")
}
