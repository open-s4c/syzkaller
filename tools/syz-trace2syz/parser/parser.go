// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

func parseSyscall(data []byte) (int, *Syscall) {
	lex := newStraceLexer(data)
	ret := StraceParse(lex)
	return ret, lex.result
}

func normalizeStraceLine(line string) string {
	name, start := straceCall(line)
	// Large CPU sets are truncated with a trailing ellipsis.
	if name == "sched_setaffinity" {
		line = strings.Replace(line, ", ...]", "]", 1)
		line = strings.Replace(line, " ...]", "]", 1)
	}
	// strace 6.8 can render a zero statx flags argument as an empty field.
	// Normalize only that known form so malformed arguments in other calls
	// continue to fail parsing instead of being silently rewritten.
	if name == "statx" {
		lastComma, commas := start, 0
		quoted, escaped := false, false
		for i := lastComma + 1; i < len(line); i++ {
			switch {
			case escaped:
				escaped = false
			case quoted && line[i] == '\\':
				escaped = true
			case line[i] == '"':
				quoted = !quoted
			case !quoted && line[i] == ',':
				commas++
				if commas == 3 && strings.TrimSpace(line[lastComma+1:i]) == "" {
					return line[:lastComma+1] + " 0" + line[i:]
				}
				lastComma = i
			}
		}
	}
	return line
}

func straceCall(line string) (string, int) {
	quoted, escaped := false, false
	for i := 0; i < len(line); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && line[i] == '\\':
			escaped = true
		case line[i] == '"':
			quoted = !quoted
		case !quoted && line[i] == '(':
			start := i
			for start > 0 && (line[start-1] == '_' || line[start-1] >= 'a' && line[start-1] <= 'z' ||
				line[start-1] >= 'A' && line[start-1] <= 'Z' || line[start-1] >= '0' && line[start-1] <= '9') {
				start--
			}
			return line[start:i], i
		}
	}
	return "", -1
}

func shouldSkip(line string) bool {
	record := strings.TrimSpace(line)
	if space := strings.IndexByte(record, ' '); space >= 0 {
		if _, err := strconv.ParseInt(record[:space], 10, 64); err == nil {
			record = strings.TrimSpace(record[space+1:])
		}
	}
	unfinished := strings.LastIndex(record, "<unfinished ...>")
	// The final result delimiter is outside quoted arguments. Traced buffers can
	// contain arbitrary text that resembles a restart result.
	result := ""
	quoted, angled, escaped, depth := false, false, false, 0
	if strings.HasPrefix(record, "<... ") &&
		(strings.Contains(record, " resumed>") || strings.HasPrefix(record, "<... resuming ")) {
		// A resumed record contains the closing parenthesis but not its opener.
		depth = 1
	}
	for i, ch := range record {
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		if angled {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '>' {
				angled = false
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '<':
			if !strings.HasPrefix(record[i:], "<<") && (i == 0 || record[i-1] != '<') {
				angled = true
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
				if depth == 0 && result == "" {
					result = strings.TrimLeft(record[i+1:], " \t")
				}
			}
		}
	}
	resultFields := strings.Fields(result)
	restart := len(resultFields) >= 3 && resultFields[0] == "=" &&
		strings.HasPrefix(resultFields[2], "ERESTART")
	return restart ||
		(unfinished > strings.LastIndex(record, "\"") && strings.HasSuffix(record, " = ?")) ||
		strings.HasPrefix(record, "????(") ||
		strings.HasPrefix(record, "<... ???? resumed") ||
		strings.HasPrefix(record, "+++") || strings.HasPrefix(record, "---") ||
		strings.HasPrefix(record, "<ptrace(SYSCALL):No such process>")
}

func joinSplitValues(data []byte) ([]byte, int64) {
	// A value split immediately after '=' cannot be parsed as two partial trees.
	// Rejoin only matching PID/syscall pairs before parsing either line.
	type pendingCall struct {
		line int
		name string
	}
	lines := strings.Split(string(data), "\n")
	pending := make(map[string]pendingCall)
	removed := make(map[int]bool)
	var rootPid int64
	for i, line := range lines {
		fields := strings.Fields(line)
		if rootPid == 0 && len(fields) != 0 {
			rootPid = -1
			if pid, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				rootPid = pid
			}
		}
		start := strings.Index(line, "<... ")
		end := strings.Index(line, " resumed>")
		if start >= 0 && end >= start {
			pid := strings.TrimSpace(line[:start])
			if call, ok := pending[pid]; ok && line[start+5:end] == call.name {
				lines[i] = strings.TrimSuffix(lines[call.line], "<unfinished ...>") + line[end+9:]
				removed[call.line] = true
				delete(pending, pid)
				line = lines[i]
			}
		}
		if paren := strings.IndexByte(line, '('); strings.HasSuffix(line, "= <unfinished ...>") && paren > 0 {
			prefix := strings.TrimSpace(line[:paren])
			parts := strings.Fields(prefix)
			name := parts[len(parts)-1]
			pending[strings.TrimSpace(strings.TrimSuffix(prefix, name))] = pendingCall{i, name}
		}
	}
	joined := lines[:0]
	for i, line := range lines {
		if !removed[i] {
			joined = append(joined, line)
		}
	}
	return []byte(strings.Join(joined, "\n")), rootPid
}

// ParseData parses each line of a strace file in a loop.
func ParseData(data []byte, splitThreads bool, numLines int) (*TraceTree, *Trace, error) {
	var status string
	data, rootPid := joinSplitValues(data)
	tree := NewTraceTree()
	trace := &Trace{RootPid: rootPid}
	lastCalls := make(map[int64](*Syscall))
	// Creating the process tree
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 64<<20)
	curLine := 0
	for scanner.Scan() {
		if curLine%1000 == 0 && numLines > 0 {
			status = fmt.Sprintf("-- Progress [%03.1f/100%%] --", (100.0 * float32(curLine) / float32(numLines)))
			fmt.Fprintf(os.Stderr, "%s\r", status)
		}
		line := scanner.Text()
		curLine++
		if shouldSkip(line) {
			continue
		}
		log.Logf(4, "scanning call: %s", line)
		ret, call := parseSyscall([]byte(normalizeStraceLine(line)))
		if call == nil || ret != 0 {
			fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
			return nil, nil, fmt.Errorf("failed to parse line: %v", line)
		}
		if splitThreads {
			tree.add(call)
		} else {
			if !call.Resumed {
				lastCalls[call.Pid] = call
			} else {
				lastCall := lastCalls[call.Pid]
				if lastCall == nil {
					fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
					fmt.Fprintf(os.Stderr, "Problem line: %s\n", line)
					fmt.Fprintf(os.Stderr, "Problem call: %#v\n", call)
					panic("Cannot find call to resume!\n")
				}
				lastCall.Args = append(lastCall.Args, call.Args...)
				lastCall.Paused = false
				lastCall.Ret = call.Ret
				call = lastCall
			}

			if !call.Paused {
				trace.Calls = append(trace.Calls, call)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if splitThreads && tree.TraceMap[rootPid] != nil {
		tree.RootPid = rootPid
	}
	if splitThreads && len(tree.TraceMap) == 0 {
		return nil, nil, nil
	}
	if splitThreads {
		return tree, nil, nil
	}

	return nil, trace, nil
}
