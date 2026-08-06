// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package proggen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileFinalLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, test := range []struct {
		name    string
		content string
		lines   int
	}{
		{"with final newline", "getpid() = 1\n", 1},
		{"without final newline", "getpid() = 1", 1},
		{"multiple lines without final newline", "getpid() = 1\ngetuid() = 2", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			data, lines, err := ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if lines != test.lines {
				t.Fatalf("got %d lines, want %d", lines, test.lines)
			}
			if got, want := string(data), strings.TrimSuffix(test.content, "\n")+"\n"; got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestReadFileEmpty(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.strace")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile accepted an empty trace")
	}
}
