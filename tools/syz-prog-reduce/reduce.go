// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type reduceOptions struct {
	MaxCalls          int
	MaxMotifInstances int
	MaxLiveResources  int
	KeepFirst         int
	KeepLast          int
	IncludeConsts     bool
	IncludeFilenames  bool
}

type reduceStats struct {
	InputCalls        int
	OutputCalls       int
	Motifs            int
	DroppedBudget     int
	DroppedMotif      int
	DroppedDependency int
	DroppedResources  int
}

var (
	flagOS                = flag.String("os", "linux", "target os")
	flagArch              = flag.String("arch", "amd64", "target arch")
	flagProg              = flag.String("prog", "", "input syz program")
	flagOut               = flag.String("out", "", "output syz program")
	flagMaxCalls          = flag.Int("max-calls", 4096, "maximum calls to keep; <=0 means unlimited")
	flagMaxMotifInstances = flag.Int("max-motif-instances", 8, "maximum sampled instances per dynamic motif; <=0 means unlimited")
	flagMaxLiveResources  = flag.Int("max-live-resources", 128, "maximum live syzkaller resources in the reduced program; <=0 means unlimited")
	flagKeepFirst         = flag.Int("keep-first", 2, "always keep the first N instances of each motif")
	flagKeepLast          = flag.Int("keep-last", 1, "always keep the last N instances of each motif")
	flagIncludeConsts     = flag.Bool("motif-consts", true, "include constant argument values in motif keys")
	flagIncludeFilenames  = flag.Bool("motif-filenames", false, "include exact filename strings in motif keys")
)

func main() {
	flag.Parse()
	if *flagProg == "" || *flagOut == "" {
		flag.Usage()
		os.Exit(1)
	}
	p, err := readProg(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	opts := reduceOptions{
		MaxCalls:          *flagMaxCalls,
		MaxMotifInstances: *flagMaxMotifInstances,
		MaxLiveResources:  *flagMaxLiveResources,
		KeepFirst:         *flagKeepFirst,
		KeepLast:          *flagKeepLast,
		IncludeConsts:     *flagIncludeConsts,
		IncludeFilenames:  *flagIncludeFilenames,
	}
	reduced, stats := reduceProg(p, opts)
	reduced.Comments = append([]string(nil), p.Comments...)
	if err := os.MkdirAll(filepath.Dir(*flagOut), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output directory: %v\n", err)
		os.Exit(1)
	}
	if err := osutil.WriteFile(*flagOut, serializeWithComments(reduced)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write reduced program: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Reduced %d -> %d calls across %d motifs (budget=%d motif=%d dependency=%d resources=%d)\n",
		stats.InputCalls, stats.OutputCalls, stats.Motifs, stats.DroppedBudget, stats.DroppedMotif,
		stats.DroppedDependency, stats.DroppedResources)
}

// serializeWithComments restores trace metadata after CloneFilter serializes only the syz program.
func serializeWithComments(p *prog.Prog) []byte {
	data := p.Serialize()
	comments := csbComments(p)
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

func csbComments(p *prog.Prog) []string {
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

func readProg(path string) (*prog.Prog, error) {
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	comments := csbCommentsFromData(data)
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		p, err = target.Deserialize(data, prog.NonStrictUnsafe)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize %s: %w", path, err)
		}
		sanitizeFilenames(p)
		p, err = target.Deserialize(p.Serialize(), prog.NonStrict)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize sanitized %s: %w", path, err)
		}
	}
	p.Comments = comments
	return p, nil
}

func csbCommentsFromData(data []byte) []string {
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

func sanitizeFilenames(p *prog.Prog) {
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

// reduceProg makes one forward pass so every retained resource use still follows its producer.
func reduceProg(p *prog.Prog, opts reduceOptions) (*prog.Prog, reduceStats) {
	stats := reduceStats{InputCalls: len(p.Calls)}
	motifKeys := make([]string, len(p.Calls))
	motifRanks := make([]int, len(p.Calls))
	motifCounts := make(map[string]int)
	for i, call := range p.Calls {
		key := motifKey(call, opts)
		motifKeys[i] = key
		motifRanks[i] = motifCounts[key]
		motifCounts[key]++
	}
	stats.Motifs = len(motifCounts)

	keep := make([]bool, len(p.Calls))
	available := make(map[*prog.ResultArg]bool)
	liveResources := make(map[*prog.ResultArg]bool)
	for i, call := range p.Calls {
		if opts.MaxCalls > 0 && stats.OutputCalls >= opts.MaxCalls {
			stats.DroppedBudget++
			continue
		}
		if !sampleMotif(motifRanks[i], motifCounts[motifKeys[i]], opts) {
			stats.DroppedMotif++
			continue
		}
		if !dependenciesAvailable(call, available) {
			stats.DroppedDependency++
			continue
		}
		produced := producedResources(call)
		newLive := 0
		for _, res := range produced {
			if !liveResources[res] {
				newLive++
			}
		}
		if opts.MaxLiveResources > 0 && len(liveResources)+newLive > opts.MaxLiveResources {
			stats.DroppedResources++
			continue
		}
		keep[i] = true
		stats.OutputCalls++
		for _, res := range produced {
			available[res] = true
			liveResources[res] = true
		}
		for _, res := range closedResources(call) {
			delete(liveResources, res)
		}
	}

	if stats.OutputCalls == 0 && len(p.Calls) != 0 {
		keep[0] = true
		stats.OutputCalls = 1
	}
	reduced := p.CloneFilter(keep)
	return reduced, stats
}

// sampleMotif preserves boundary instances and spreads the remaining samples across the motif.
func sampleMotif(rank, total int, opts reduceOptions) bool {
	if opts.MaxMotifInstances <= 0 || total <= opts.MaxMotifInstances {
		return true
	}
	if rank < opts.KeepFirst || rank >= total-opts.KeepLast {
		return true
	}
	remaining := opts.MaxMotifInstances - opts.KeepFirst - opts.KeepLast
	if remaining <= 0 {
		return false
	}
	span := total - opts.KeepFirst - opts.KeepLast
	pos := rank - opts.KeepFirst
	for sample := 0; sample < remaining; sample++ {
		if pos == (sample*span)/remaining {
			return true
		}
	}
	return false
}

func dependenciesAvailable(call *prog.Call, available map[*prog.ResultArg]bool) bool {
	for _, res := range usedResources(call) {
		if res.Res != nil && !available[res.Res] {
			return false
		}
	}
	return true
}

func usedResources(call *prog.Call) []*prog.ResultArg {
	var resources []*prog.ResultArg
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		// Inout resources consume their prior value before producing an updated one.
		if ok && res.Dir() != prog.DirOut {
			resources = append(resources, res)
		}
	})
	return resources
}

func producedResources(call *prog.Call) []*prog.ResultArg {
	var resources []*prog.ResultArg
	if call.Ret != nil {
		resources = append(resources, call.Ret)
	}
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if ok && res.Dir() != prog.DirIn {
			resources = append(resources, res)
		}
	})
	return uniqueResources(resources)
}

func closedResources(call *prog.Call) []*prog.ResultArg {
	if call.Meta.CallName != "close" || len(call.Args) == 0 {
		return nil
	}
	res, ok := call.Args[0].(*prog.ResultArg)
	if !ok || res.Res == nil {
		return nil
	}
	return []*prog.ResultArg{res.Res}
}

func uniqueResources(in []*prog.ResultArg) []*prog.ResultArg {
	seen := make(map[*prog.ResultArg]bool)
	var out []*prog.ResultArg
	for _, res := range in {
		if res == nil || seen[res] {
			continue
		}
		seen[res] = true
		out = append(out, res)
	}
	return out
}

func motifKey(call *prog.Call, opts reduceOptions) string {
	var b strings.Builder
	b.WriteString(call.Meta.Name)
	for _, arg := range call.Args {
		b.WriteByte('|')
		writeArgMotif(&b, arg, opts)
	}
	return b.String()
}

func writeArgMotif(b *strings.Builder, arg prog.Arg, opts reduceOptions) {
	switch a := arg.(type) {
	case *prog.ConstArg:
		if opts.IncludeConsts {
			fmt.Fprintf(b, "const:%s:%x", a.Type().TemplateName(), a.Val)
		} else {
			fmt.Fprintf(b, "const:%s", a.Type().TemplateName())
		}
	case *prog.ResultArg:
		fmt.Fprintf(b, "res:%s", a.Type().TemplateName())
	case *prog.PointerArg:
		fmt.Fprintf(b, "ptr:%s:", a.Type().TemplateName())
		if a.Res != nil {
			writeArgMotif(b, a.Res, opts)
		}
	case *prog.DataArg:
		kind := "data"
		if typ, ok := a.Type().(*prog.BufferType); ok {
			kind = "buffer:" + strconv.Itoa(int(typ.Kind))
			if typ.Kind == prog.BufferFilename && opts.IncludeFilenames && a.Dir() != prog.DirOut {
				kind += ":" + string(bytes.TrimRight(a.Data(), "\x00"))
			}
		}
		fmt.Fprintf(b, "%s:%d", kind, a.Size())
	case *prog.GroupArg:
		fmt.Fprintf(b, "group:%s[", a.Type().TemplateName())
		for i, inner := range a.Inner {
			if i != 0 {
				b.WriteByte(',')
			}
			writeArgMotif(b, inner, opts)
		}
		b.WriteByte(']')
	case *prog.UnionArg:
		fmt.Fprintf(b, "union:%s:%d:", a.Type().TemplateName(), a.Index)
		writeArgMotif(b, a.Option, opts)
	default:
		fmt.Fprintf(b, "%T", arg)
	}
}
