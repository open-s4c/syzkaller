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

func csbSource(t *testing.T, text string, threaded bool) string {
	t.Helper()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Threaded: threaded, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

func requireCSource(t *testing.T, src, want string) {
	t.Helper()
	if !strings.Contains(src, want) {
		t.Fatalf("generated C source does not contain %q", want)
	}
}

func TestCSBTracksRawIoUringWithoutMmap(t *testing.T) {
	src := csbSource(t, "r0 = io_uring_setup$auto(0x1, &(0x7f0000000000)={0x0, 0x0, 0x4000})\n"+
		"io_uring_enter(r0, 0x1, 0x0, 0x0, 0x0, 0x0)\n", false)
	requireCSource(t, src, "/*to_submit=*/0")
}
