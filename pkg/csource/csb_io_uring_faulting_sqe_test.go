// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func TestCSBRequiresFaultSafeSQESanitizing(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("syz_io_uring_submit(0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, HandleSegv: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NONFAILING(memcpy(csb_sqe_0, (void*)(0x0), 64))", "if (csb_sqe_ok_0)"} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("generated C source does not contain %q", want)
		}
	}
}
