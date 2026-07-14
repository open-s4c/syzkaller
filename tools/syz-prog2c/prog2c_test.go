// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
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
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
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
	p := deserializeTestProg(t, `
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/tmp/file\x00', 0x4080, 0x0)
pwrite64(r0, &(0x7f0000000040)='abc', 0x3, 0x1000)
`)

	_, subdirs, filesizes, filemap, maxWriteSize, alignment := sanitizeProgram(p, "test.prog")

	if got := string(p.Calls[0].Args[1].(*prog.PointerArg).Res.(*prog.DataArg).Data()); got != "./tmp/file" {
		t.Fatalf("sanitized path = %q, want %q", got, "./tmp/file")
	}
	flags := p.Calls[0].Args[2].(*prog.ConstArg).Val
	if flags&linuxAmd64OCreat == 0 {
		t.Fatalf("openat flags %#x do not include O_CREAT", flags)
	}
	if flags&linuxAmd64OExcl != 0 {
		t.Fatalf("openat flags %#x still include O_EXCL", flags)
	}
	if flags&linuxAmd64ODirect != 0 {
		t.Fatalf("openat flags %#x still include O_DIRECT", flags)
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
