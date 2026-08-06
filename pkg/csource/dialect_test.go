// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"strings"
	"testing"
)

func TestUpstreamDialectUsesPlainResultArray(t *testing.T) {
	got := (&upstreamDialect{}).declareResults([]uint64{1, 2})
	if want := "uint64 r[2] = {0x1, 0x2};\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUpstreamDialectRewritesNamespacedExit(t *testing.T) {
	got := string((&upstreamDialect{}).rewriteExit([]byte("UNIQUE_FUNC(doexit)(1); doexit(2);")))
	if strings.Contains(got, "doexit") || got != "exit(1); exit(2);" {
		t.Fatalf("unexpected exit rewrite: %q", got)
	}
}

func TestDialectPreservesCSBFailureRendering(t *testing.T) {
	input := []byte("#include <fcntl.h>\n#include <stdint.h>\n\n#ifndef CSB_MAX_WAIT_MS\n" +
		"\t\tif (unlink(filename))\n\t\t\texitf(\"unlink(%s) failed\", filename);\n" +
		"\twhile (rmdir(dir))\n\t\texitf(\"rmdir(%s) failed\", dir);\n")
	dialect := &csbDialect{}
	got := string(dialect.finalize(dialect.rewriteExit(input)))
	for _, want := range []string{
		"#include <fcntl.h> /* Definition of AT_* constants */",
		"#include <stdint.h>\n\n#include <fcntl.h> /* Definition of AT_* constants */\n#ifndef CSB_MAX_WAIT_MS",
		"if (unlink(filename)) {\n\tassert(0);\n\t\t}",
		"while (rmdir(dir)) {\n\tassert(0);\n\t}",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CSB rewrite missing %q:\n%s", want, got)
		}
	}
	if upstream := string((&upstreamDialect{}).rewriteExit([]byte("\texitf(\"x\");\n"))); upstream != "\texit(1);\n" {
		t.Fatalf("upstream failure rewrite = %q", upstream)
	}
}
