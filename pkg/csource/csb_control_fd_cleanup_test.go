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

func TestCSBRequiresControlFDCleanupGuard(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = dup2(0x0, 0x0)\nread(r0, &(0x7f0000000000), 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := "{ uint32_t fd = (uint32_t)UNIQUE_VAR(ctx->r)[0]; if (fd > 2) close(fd); }"
	if !strings.Contains(string(src), want) {
		t.Fatal("generated cleanup can close a CSB control descriptor")
	}
}
