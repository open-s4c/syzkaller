// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var repoRoot string

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	repoRoot = filepath.Clean(filepath.Join(wd, "../.."))
	os.Exit(m.Run())
}

// TestRealTracePipeline keeps the complete benchmark-generation path covered by
// one small real trace. Each stage consumes the preceding stage's actual output.
func TestRealTracePipeline(t *testing.T) {
	requireTools(t)
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			testPipeline(t, arch)
		})
	}
}

func testPipeline(t *testing.T, arch string) {
	work := t.TempDir()
	trace := filepath.Join(repoRoot, "traces/bash_ls_grep_strace.log")

	// Repeated conversion detects unstable ordering, while arg-length and thread
	// splitting cover the two transformations that materially reshape a trace.
	base := trace2syz(t, arch, trace, filepath.Join(work, "trace-base"))
	again := trace2syz(t, arch, trace, filepath.Join(work, "trace-again"))
	compareTrees(t, base, again)
	trimmed := trace2syz(t, arch, trace, filepath.Join(work, "trace-trimmed"), "-argLength")
	split := trace2syz(t, arch, trace, filepath.Join(work, "trace-split"), "-splitThreads")
	for _, tree := range []string{base, trimmed, split} {
		assertPrograms(t, tree, arch)
	}

	input := onlyProgram(t, base)
	serial := extract(t, arch, input, filepath.Join(work, "extract-1"), "1")
	parallel := extract(t, arch, input, filepath.Join(work, "extract-4"), "4")
	compareTrees(t, serial, parallel)
	assertPrograms(t, serial, arch)

	reducedInput := firstProgram(t, serial)
	reduced := filepath.Join(work, "reduced.prog")
	runOK(t, tool("syz-prog-reduce"), "-os=linux", "-arch="+arch,
		"-prog="+reducedInput, "-out="+reduced, "-max-calls=32",
		"-max-motif-instances=3", "-max-live-resources=16", "-keep-first=1", "-keep-last=1")
	assertProgram(t, reduced, arch)
	// A second pass must be a fixed point, otherwise repeated generator runs drift.
	reducedAgain := filepath.Join(work, "reduced-again.prog")
	runOK(t, tool("syz-prog-reduce"), "-os=linux", "-arch="+arch,
		"-prog="+reduced, "-out="+reducedAgain, "-max-calls=32",
		"-max-motif-instances=3", "-max-live-resources=16", "-keep-first=1", "-keep-last=1")
	compareFiles(t, reduced, reducedAgain)

	testProg2C(t, arch, reduced, work)
}

func trace2syz(t *testing.T, arch, trace, out string, extra ...string) string {
	t.Helper()
	mustMkdir(t, out)
	args := []string{"-os=linux", "-arch=" + arch, "-file=" + trace, "-deserialize=" + out, "-nocorpus"}
	runOK(t, tool("syz-trace2syz"), append(args, extra...)...)
	return out
}

func extract(t *testing.T, arch, input, out, jobs string) string {
	t.Helper()
	mustMkdir(t, out)
	runOK(t, tool("syz-extraction"), "-os=linux", "-arch="+arch, "-prog="+input,
		"-deserialize="+out, "-minCalls=1", "-jobs="+jobs, "-strict")
	return out
}

func testProg2C(t *testing.T, arch, input, work string) {
	t.Helper()
	variants := []struct {
		name string
		args []string
		csb  bool
	}{
		{name: "plain"},
		{name: "threaded", args: []string{"-threaded"}},
		{name: "runtime-loops", args: []string{"-runtime_loops", "-runtime_loop_min=2"}},
		{name: "threaded-runtime-loops", args: []string{"-threaded", "-runtime_loops"}},
		{name: "trace", args: []string{"-trace"}},
		{name: "csb-header", args: []string{"-csb"}, csb: true},
	}
	for _, variant := range variants {
		t.Run("prog2c-"+variant.name, func(t *testing.T) {
			prefix := filepath.Join(work, arch+"-"+variant.name)
			args := []string{"-os=linux", "-arch=" + arch, "-prog=" + input,
				"-cfile=" + prefix, "-format=false", "-strict"}
			runOK(t, tool("syz-prog2c"), append(args, variant.args...)...)
			outputs, err := filepath.Glob(prefix + "*")
			if err != nil || len(outputs) != 1 {
				t.Fatalf("prog2c produced %d files for %q: %v", len(outputs), prefix, err)
			}
			data := readFile(t, outputs[0])
			marker := []byte("int main")
			if variant.csb {
				marker = []byte("#ifndef UNIQUE_ID")
			}
			if len(data) < 100 || !bytes.Contains(data, marker) {
				t.Fatalf("implausible generated output %s (%d bytes)", outputs[0], len(data))
			}
			if !variant.csb {
				runOK(t, compiler(t), cSyntaxArgs(outputs[0])...)
			}
		})
	}
}

func TestPipelineRejectsInvalidInputs(t *testing.T) {
	requireTools(t)
	bad := filepath.Join(t.TempDir(), "bad.prog")
	if err := os.WriteFile(bad, []byte("this is not syzlang\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"extraction", []string{"-prog=" + bad, "-deserialize=" + t.TempDir(), "-strict"}},
		{"prog-reduce", []string{"-prog=" + bad, "-out=" + filepath.Join(t.TempDir(), "out.prog")}},
		{"prog2c", []string{"-prog=" + bad, "-cfile=" + filepath.Join(t.TempDir(), "out.c"), "-strict"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runFail(t, tool("syz-"+tc.name), tc.args...)
		})
	}
	runFail(t, tool("syz-trace2syz"), "-file="+filepath.Join(t.TempDir(), "missing.strace"),
		"-deserialize="+t.TempDir(), "-nocorpus")
	badC := filepath.Join(t.TempDir(), "bad-c-without-extension")
	if err := os.WriteFile(badC, []byte("not valid C\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFail(t, compiler(t), cSyntaxArgs(badC)...)
}

func cSyntaxArgs(file string) []string {
	// prog2c output may be extensionless, so do not rely on compiler guessing.
	return []string{"-x", "c", "-fsyntax-only", file}
}

func assertPrograms(t *testing.T, dir, arch string) {
	t.Helper()
	files := programs(t, dir)
	if len(files) == 0 {
		t.Fatalf("no programs in %s", dir)
	}
	for _, file := range files {
		assertMetadata(t, file, arch)
	}
	// The converter already emits every program through the same serializer;
	// validate boundary samples strictly without compiling hundreds of fragments.
	assertProgram(t, files[0], arch)
	if len(files) > 1 {
		assertProgram(t, files[len(files)-1], arch)
	}
}

func assertProgram(t *testing.T, file, arch string) {
	t.Helper()
	assertMetadata(t, file, arch)
	// Strict prog2c parsing is a cheap end-to-end validation of resources and types.
	prefix := filepath.Join(t.TempDir(), "validate")
	runOK(t, tool("syz-prog2c"), "-os=linux", "-arch="+arch, "-prog="+file,
		"-cfile="+prefix, "-format=false", "-strict")
}

func assertMetadata(t *testing.T, file, arch string) {
	t.Helper()
	data := readFile(t, file)
	for key, want := range map[string]string{"# csb.trace.os=": "linux", "# csb.trace.arch=": arch} {
		if got := strings.Count(string(data), key); got != 1 {
			t.Fatalf("%s contains %d %q metadata lines, want 1", file, got, key)
		}
		if !bytes.Contains(data, []byte(key+want)) {
			t.Fatalf("%s does not declare %s%s", file, key, want)
		}
	}
}

func compareTrees(t *testing.T, left, right string) {
	t.Helper()
	l, r := snapshot(t, left), snapshot(t, right)
	if len(l) != len(r) {
		t.Fatalf("output count differs: %s=%d %s=%d", left, len(l), right, len(r))
	}
	for name, data := range l {
		other, ok := r[name]
		if !ok || !bytes.Equal(data, other) {
			t.Fatalf("outputs differ for %s", name)
		}
	}
}

func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		result[rel] = readFile(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func onlyProgram(t *testing.T, dir string) string {
	t.Helper()
	files := programs(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d programs in %s, want 1", len(files), dir)
	}
	return files[0]
}

func firstProgram(t *testing.T, dir string) string {
	t.Helper()
	files := programs(t, dir)
	if len(files) == 0 {
		t.Fatalf("no programs in %s", dir)
	}
	return files[0]
}

func programs(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.prog"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func compareFiles(t *testing.T, left, right string) {
	t.Helper()
	if !bytes.Equal(readFile(t, left), readFile(t, right)) {
		t.Fatalf("files differ: %s and %s", left, right)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func runOK(t *testing.T, command string, args ...string) {
	t.Helper()
	if output, err := run(command, args...); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", command, strings.Join(args, " "), err, output)
	}
}

func runFail(t *testing.T, command string, args ...string) {
	t.Helper()
	output, err := run(command, args...)
	if err == nil {
		t.Fatalf("%s %s unexpectedly succeeded:\n%s", command, strings.Join(args, " "), output)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("%s %s did not reject input: %v\n%s", command, strings.Join(args, " "), err, output)
	}
}

func run(command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("timed out: %w", ctx.Err())
	}
	return output, err
}

func tool(name string) string {
	return filepath.Join(repoRoot, "bin", name)
}

func requireTools(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test")
	}
	for _, name := range []string{"syz-trace2syz", "syz-extraction", "syz-prog-reduce", "syz-prog2c"} {
		if _, err := os.Stat(tool(name)); err != nil {
			t.Fatalf("%s is required; run make trace2syz extraction progreduce prog2c: %v", tool(name), err)
		}
	}
}

func compiler(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"cc", "gcc", "clang"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Fatal("a C compiler is required")
	return ""
}
