// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestTrace2SyzDeterministicOutput(t *testing.T) {
	tracePath := os.Getenv("SYZ_TRACE2SYZ_TEST_TRACE")
	if tracePath == "" {
		t.Logf("No trace file specified in environment SYZ_TRACE2SYZ_TEST_TRACE, using builtin example.\n")
		inputDir := t.TempDir()
		tracePath = filepath.Join(inputDir, "trace_case.log")
		trace := []byte(`open("file", 66) = 3
write(3, "somedata", 8) = 8
socket(29, 3, 1) = 3
getsockopt(-1, 132, 119, 0x200005c0, [14]) = -1 EBADF (Bad file descriptor)
`)
		if err := os.WriteFile(tracePath, trace, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Logf("Found trace file %s in SYZ_TRACE2SYZ_TEST_TRACE.\n", tracePath)
	}

	first := runTrace2Syz(t, tracePath)
	second := runTrace2Syz(t, tracePath)
	if diff := diffOutputs(first, second); diff != "" {
		t.Fatalf("non-deterministic output:\n%s", diff)
	}
}

func runTrace2Syz(t *testing.T, tracePath string) map[string][]byte {
	t.Helper()
	return runTrace2SyzForArch(t, tracePath, "arm64")
}

func TestTrace2SyzEmbedsTargetArchMetadata(t *testing.T) {
	inputDir := t.TempDir()
	tracePath := filepath.Join(inputDir, "trace_case.log")
	trace := []byte(`openat(-100, "/tmp/x", 0) = 3
close(3) = 0
`)
	if err := os.WriteFile(tracePath, trace, 0600); err != nil {
		t.Fatal(err)
	}

	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			out := runTrace2SyzForArch(t, tracePath, arch)
			for name, data := range out {
				if !bytes.Contains(data, []byte("# csb.trace.os=linux\n")) {
					t.Fatalf("%s missing os metadata:\n%s", name, data)
				}
				want := []byte("# csb.trace.arch=" + arch + "\n")
				if !bytes.Contains(data, want) {
					t.Fatalf("%s missing arch metadata %q:\n%s", name, want, data)
				}
			}
		})
	}
}

func runTrace2SyzForArch(t *testing.T, tracePath, arch string) map[string][]byte {
	t.Logf("Testing logfile %s\n", tracePath)
	t.Helper()
	outDir := t.TempDir()

	oldFile := *flagFile
	oldDir := *flagDir
	oldDeserialize := *flagDeserialize
	oldSkipCorpus := *flagSkipCorpus
	oldSplitThreads := *flagSplitThreads
	oldArgLength := *flagArgLength
	oldOS := *flagOS
	oldArch := *flagArch
	*flagFile = tracePath
	*flagDir = ""
	*flagDeserialize = outDir
	*flagSkipCorpus = true
	*flagSplitThreads = false
	*flagArgLength = false
	*flagOS = "linux"
	*flagArch = arch
	t.Cleanup(func() {
		*flagFile = oldFile
		*flagDir = oldDir
		*flagDeserialize = oldDeserialize
		*flagSkipCorpus = oldSkipCorpus
		*flagSplitThreads = oldSplitThreads
		*flagArgLength = oldArgLength
		*flagOS = oldOS
		*flagArch = oldArch
	})

	parseTraces(initializeTarget(*flagOS, *flagArch))
	return readOutputFiles(t, outDir)
}

func readOutputFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	ret := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ret[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ret) == 0 {
		t.Fatalf("no program files were generated in %s", dir)
	}
	return ret
}

func diffOutputs(first, second map[string][]byte) string {
	var names []string
	seen := make(map[string]bool)
	for name := range first {
		names = append(names, name)
		seen[name] = true
	}
	for name := range second {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		left, leftOK := first[name]
		right, rightOK := second[name]
		switch {
		case !leftOK:
			return fmt.Sprintf("only second run generated %s", name)
		case !rightOK:
			return fmt.Sprintf("only first run generated %s", name)
		case !bytes.Equal(left, right):
			return fmt.Sprintf("content differs for %s", name)
		}
	}
	return ""
}
