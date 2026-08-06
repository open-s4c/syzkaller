// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package csbprog preserves CSB trace metadata while generator tools transform syz programs.
package csbprog

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/prog"
)

// CommentsFromData retains the trace metadata understood by CSB generator tools.
func CommentsFromData(data []byte) []string {
	var ret []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "#")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "csb.trace.") && !seen[line] {
			ret = append(ret, line)
			seen[line] = true
		}
	}
	return ret
}

// Serialize restores trace metadata that prog.Serialize omits.
func Serialize(p *prog.Prog) []byte {
	data := p.Serialize()
	comments := comments(p)
	if len(comments) == 0 {
		return data
	}
	var b strings.Builder
	for _, comment := range comments {
		fmt.Fprintf(&b, "# %s\n", comment)
	}
	b.Write(data)
	return []byte(b.String())
}

func comments(p *prog.Prog) []string {
	var ret []string
	seen := make(map[string]bool)
	add := func(comment string) {
		if strings.HasPrefix(comment, "csb.trace.") && !seen[comment] {
			ret = append(ret, comment)
			seen[comment] = true
		}
	}
	for _, comment := range p.Comments {
		add(comment)
	}
	for _, call := range p.Calls {
		add(call.Comment)
	}
	return ret
}

// SanitizeFilenames confines input paths to the benchmark working directory.
func SanitizeFilenames(p *prog.Prog) {
	for _, call := range p.Calls {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			typ, ok := arg.Type().(*prog.BufferType)
			if !ok || typ.Kind != prog.BufferFilename || arg.Dir() == prog.DirOut {
				return
			}
			data := arg.(*prog.DataArg).Data()
			sanitized := sanitizeFilename(data)
			if string(sanitized) != string(data) {
				arg.(*prog.DataArg).SetData(sanitized)
			}
		})
	}
}

func sanitizeFilename(data []byte) []byte {
	pathEnd := len(data)
	for pathEnd > 0 && data[pathEnd-1] == 0 {
		pathEnd--
	}
	if pathEnd == 0 {
		return data
	}
	path := string(data[:pathEnd])
	if path[0] == '/' {
		path = "." + path
	}
	// Each harmless component cancels one leading ".." after path cleaning.
	for escapingFilename(path) {
		path = "a/" + path
	}
	return append([]byte(path), data[pathEnd:]...)
}

func escapingFilename(file string) bool {
	file = filepath.Clean(file)
	return len(file) >= 1 && file[0] == '/' ||
		len(file) >= 2 && file[0] == '.' && file[1] == '.'
}
