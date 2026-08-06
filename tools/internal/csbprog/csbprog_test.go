// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csbprog

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"absolute", []byte("/etc/ld.so.cache\x00"), []byte("./etc/ld.so.cache\x00")},
		{"parent", []byte("../file\x00"), []byte("a/../file\x00")},
		{"double-parent", []byte("../../file\x00"), []byte("a/a/../../file\x00")},
		{"parent-in-between-escape", []byte("foo/../../bar/../../file\x00"), []byte("a/a/foo/../../bar/../../file\x00")},
		{"parent-in-between-no-escape", []byte("foo/../bar/../file\x00"), []byte("foo/../bar/../file\x00")},
		{"bare-parent", []byte("..\x00"), []byte("a/..\x00")},
		{"dot-prefixed-file", []byte("..file\x00"), []byte("a/..file\x00")},
		{"all-zeros", []byte("\x00\x00"), []byte("\x00\x00")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sanitizeFilename(test.in); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestTraceComments(t *testing.T) {
	data := []byte("# ordinary\n# csb.trace.os=linux\n#csb.trace.arch=arm64\n# csb.trace.os=linux\n")
	want := []string{"csb.trace.os=linux", "csb.trace.arch=arm64"}
	if got := CommentsFromData(data); !reflect.DeepEqual(got, want) {
		t.Fatalf("comments = %q, want %q", got, want)
	}

	p := &prog.Prog{
		Comments: []string{"ordinary", want[0]},
		Calls:    []*prog.Call{{Comment: want[1]}, {Comment: want[0]}},
	}
	if got := comments(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("program comments = %q, want %q", got, want)
	}
	wantData := "# csb.trace.os=linux\n"
	if got := string(Serialize(&prog.Prog{Comments: []string{want[0]}})); got != wantData {
		t.Fatalf("serialized metadata = %q, want %q", got, wantData)
	}
}
