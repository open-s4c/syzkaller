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

func TestCSBRequiresNoCopyoutRingTracking(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("io_uring_setup$auto(0x1, &(0x7f0000000000)={0x0, 0x0, 0x4000})\n"+
		"io_uring_enter(0x3, 0x1, 0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(src), "/*to_submit=*/0")
}
