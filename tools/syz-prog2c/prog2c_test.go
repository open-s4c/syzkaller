// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func deserializeTestProg(t *testing.T, data string) *prog.Prog {
	t.Helper()
	return deserializeTestProgForArch(t, targets.AMD64, data)
}

func deserializeTestProgForArch(t *testing.T, arch, data string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget(targets.Linux, arch)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(data), prog.NonStrictUnsafe)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRemoveTrailingNullChars(t *testing.T) {
	got := removeTrailingNullChars([]byte("file\x00\x00"))
	want := []byte("file")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}

	got = removeTrailingNullChars([]byte("fi\x00le\x00"))
	want = []byte("fi\x00le")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name    string
		path    []byte
		want    []byte
		wantDir string
	}{
		{
			name:    "empty path maps to current directory",
			path:    []byte("\x00"),
			want:    []byte("\x00"),
			wantDir: ".",
		},
		{
			name:    "absolute path becomes relative",
			path:    []byte("/tmp/file\x00"),
			want:    []byte("./tmp/file"),
			wantDir: "tmp",
		},
		{
			name:    "up directory segments get prefixed",
			path:    []byte("../dir/file\x00"),
			want:    []byte("a/../dir/file"),
			wantDir: "dir",
		},
		{
			name:    "directory path preserves trailing slash",
			path:    []byte("dir/sub/\x00"),
			want:    []byte("dir/sub/\x00"),
			wantDir: "dir/sub/",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotDir := sanitizePath(test.path)
			if !reflect.DeepEqual(got, test.want) || gotDir != test.wantDir {
				t.Fatalf("got (%q, %q), want (%q, %q)", got, gotDir, test.want, test.wantDir)
			}
		})
	}
}

func TestGenerateUniqueFileName(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "repro")
	if err := os.WriteFile(base+"_0.c", []byte("exists"), 0600); err != nil {
		t.Fatal(err)
	}

	got := generateUniqueFileName(base, ".c")
	want := base + "_1.c"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeProgramOpenAndPwrite(t *testing.T) {
	for _, arch := range []string{targets.AMD64, targets.ARM64} {
		t.Run(arch, func(t *testing.T) {
			p, subdirs, filesizes, filemap, maxWriteSize, alignment := sanitizeRecordedOpenWithGenerationArch(t, arch, arch)
			openFlags := targetOpenFlagConsts(p.Target)

			if got := string(p.Calls[0].Args[1].(*prog.PointerArg).Res.(*prog.DataArg).Data()); got != "./tmp/file" {
				t.Fatalf("sanitized path = %q, want %q", got, "./tmp/file")
			}
			flags := p.Calls[0].Args[2].(*prog.ConstArg).Val
			if flags&openFlags.Creat == 0 {
				t.Fatalf("openat flags %#x do not include O_CREAT %#x", flags, openFlags.Creat)
			}
			if flags&openFlags.Excl != 0 {
				t.Fatalf("openat flags %#x still include O_EXCL %#x", flags, openFlags.Excl)
			}
			if flags&openFlags.Direct != 0 {
				t.Fatalf("openat flags %#x still include O_DIRECT %#x", flags, openFlags.Direct)
			}
			if got := p.Calls[0].Args[3].(*prog.ConstArg).Val; got != 0777 {
				t.Fatalf("openat mode %#o, want 0777", got)
			}

			if !subdirs["tmp"] {
				t.Fatalf("subdirs %v do not contain tmp", subdirs)
			}
			if got := filemap[0]; got != "./tmp/file" {
				t.Fatalf("filemap[0] = %q, want ./tmp/file", got)
			}
			if got := filesizes[0]; got != 0x1003 {
				t.Fatalf("filesizes[0] = %#x, want 0x1003", got)
			}
			if maxWriteSize != 4096 || alignment != 4096 {
				t.Fatalf("max write/alignment = %d/%d, want 4096/4096", maxWriteSize, alignment)
			}
			if got := string(p.Calls[1].Args[1].(*prog.PointerArg).Res.(*prog.DataArg).Data()); got != "" {
				t.Fatalf("pwrite64 buffer = %q, want empty", got)
			}
		})
	}
}

func TestSanitizeProgramSizesSequentialReadFixture(t *testing.T) {
	p := deserializeTestProg(t, `
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/etc/localtime\x00', 0x0, 0x0)
read(r0, &(0x7f0000000040)=""/4096, 0x1000)
lseek(r0, 0xfffffffffffffeaa, 0x1)
`)
	_, _, filesizes, _, _, _ := sanitizeProgram(p, "test.prog")
	if got := filesizes[0]; got < 0x1000 {
		t.Fatalf("fixture size = %#x, want at least %#x", got, 0x1000)
	}
}

func TestSanitizeMaxWriteSizeNullBuffer(t *testing.T) {
	p := deserializeTestProg(t, `
write(0xffffffffffffffff, 0x0, 0x20)
`)

	got := sanitizeMaxWriteSize(p.Calls[0], 1, 2, 0)
	if got != 0x20 {
		t.Fatalf("max write size = %#x, want 0x20", got)
	}
}

func TestSanitizeProgramOpenFlagsRecordedArchMatrix(t *testing.T) {
	for _, recordedArch := range []string{targets.AMD64, targets.ARM64} {
		for _, generationArch := range []string{targets.AMD64, targets.ARM64} {
			name := recordedArch + "_recorded_" + generationArch + "_generation"
			t.Run(name, func(t *testing.T) {
				p, _, _, _, _, _ := sanitizeRecordedOpenWithGenerationArch(t, recordedArch, generationArch)
				flags := p.Calls[0].Args[2].(*prog.ConstArg).Val
				recordedTarget, err := prog.GetTarget(targets.Linux, recordedArch)
				if err != nil {
					t.Fatal(err)
				}
				expectedForRecordedArch := recordedTarget.ConstMap["O_CREAT"]

				if recordedArch == generationArch {
					if flags != expectedForRecordedArch {
						t.Fatalf("flags after %s generation = %#x, want recorded-arch sanitized value %#x",
							generationArch, flags, expectedForRecordedArch)
					}
					return
				}

				if flags == expectedForRecordedArch {
					t.Fatalf("wrong generation arch %s accidentally produced recorded-arch sanitized flags %#x",
						generationArch, flags)
				}
			})
		}
	}
}

func TestSanitizeOpenWithoutDirectoryFlag(t *testing.T) {
	p := deserializeTestProg(t, `
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/tmp/file\x00', 0x0, 0x0)
`)
	flags := targetOpenFlagConsts(p.Target)
	flags.Directory = 0
	flags.HasDirectory = false
	subdirs, _ := sanitizeOpenAt(p.Calls[0], flags, make(map[string]bool), make(map[uint64]string))

	gotFlags := p.Calls[0].Args[2].(*prog.ConstArg).Val
	if gotFlags&flags.Creat == 0 {
		t.Fatalf("openat flags %#x do not include O_CREAT %#x", gotFlags, flags.Creat)
	}
	if subdirs["./tmp/file"] {
		t.Fatalf("file path was registered as a directory: %v", subdirs)
	}
}

func TestSanitizeProgramUsesFirstPathType(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	directory := target.ConstMap["O_DIRECTORY"]
	for _, test := range []struct {
		name      string
		firstFlag uint64
		wantDir   bool
	}{
		{"directory first", directory, true},
		{"file first", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := deserializeTestProg(t, fmt.Sprintf(`
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/tmp/same\x00', 0x%x, 0x0)
r1 = openat(0xffffffffffffff9c, &(0x7f0000000040)='/tmp/same\x00', 0x%x, 0x0)
`, test.firstFlag, directory-test.firstFlag))
			_, subdirs, _, filemap, _, _ := sanitizeProgram(p, "test.prog")
			gotFile := false
			for _, path := range filemap {
				gotFile = gotFile || path == "./tmp/same"
			}
			if subdirs["./tmp/same"] != test.wantDir || gotFile == test.wantDir {
				t.Fatalf("subdirs=%v filemap=%v, want directory=%v", subdirs, filemap, test.wantDir)
			}
		})
	}
}

func sanitizeRecordedOpenWithGenerationArch(t *testing.T, recordedArch, generationArch string) (
	*prog.Prog, map[string]bool, map[uint64]uint64, map[uint64]string, uint64, uint64,
) {
	t.Helper()
	recordedTarget, err := prog.GetTarget(targets.Linux, recordedArch)
	if err != nil {
		t.Fatal(err)
	}
	initialFlags := recordedTarget.ConstMap["O_EXCL"] | recordedTarget.ConstMap["O_DIRECT"]
	p := deserializeTestProgForArch(t, generationArch, fmt.Sprintf(`
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/tmp/file\x00', 0x%x, 0x0)
pwrite64(r0, &(0x7f0000000040)='abc', 0x3, 0x1000)
`, initialFlags))
	_, subdirs, filesizes, filemap, maxWriteSize, alignment := sanitizeProgram(p, "test.prog")
	return p, subdirs, filesizes, filemap, maxWriteSize, alignment
}

func TestSanitizeReadlinkatSetsDefaultBufferSize(t *testing.T) {
	p := deserializeTestProg(t, `
readlinkat(0xffffffffffffff9c, &(0x7f0000000000)='/tmp/link\x00', &(0x7f0000000040)=""/0, 0x0)
`)

	subdirs := sanitizeReadlinkat(p.Calls[0], make(map[string]bool))

	if !subdirs["tmp"] || !subdirs["./tmp/link"] {
		t.Fatalf("subdirs = %v, want tmp and ./tmp/link", subdirs)
	}
	if got := p.Calls[0].Args[3].(*prog.ConstArg).Val; got != 0x80 {
		t.Fatalf("buffer size = %#x, want 0x80", got)
	}
}
