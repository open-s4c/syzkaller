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

func TestCSBRequiresStableControlFDGuardArguments(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)\n"+
		"dup2(r0+1, 0x0)\nclose_range(r0+1, 0xffffffff, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Threaded: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{"intptr_t csb_dup_src =", "intptr_t csb_fd ="} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated C source does not contain %q", want)
		}
	}
	if got := strings.Count(text, "/*oldfd=*/UNIQUE_VAR(ctx->r)[0]+1"); got != 1 {
		t.Fatalf("dup source evaluated %d times, want 1", got)
	}
	if got := strings.Count(text, "/*fd=*/UNIQUE_VAR(ctx->r)[0]+1"); got != 1 {
		t.Fatalf("close_range lower bound evaluated %d times, want 1", got)
	}
}
