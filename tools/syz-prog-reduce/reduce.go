// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/internal/csbprog"
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
	WeightedCalls     int
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
	if err := osutil.WriteFile(*flagOut, csbprog.Serialize(reduced)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write reduced program: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Reduced %d -> %d calls (%d frequency-weighted) across %d motifs "+
		"(budget=%d motif=%d dependency=%d resources=%d)\n",
		stats.InputCalls, stats.OutputCalls, stats.WeightedCalls, stats.Motifs, stats.DroppedBudget, stats.DroppedMotif,
		stats.DroppedDependency, stats.DroppedResources)
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
	comments := csbprog.CommentsFromData(data)
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		p, err = target.Deserialize(data, prog.NonStrictUnsafe)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize %s: %w", path, err)
		}
		csbprog.SanitizeFilenames(p)
		p, err = target.Deserialize(p.Serialize(), prog.NonStrict)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize sanitized %s: %w", path, err)
		}
	}
	p.Comments = comments
	return p, nil
}

// reduceProg makes one forward pass so every retained resource use still follows its producer.
func reduceProg(p *prog.Prog, opts reduceOptions) (*prog.Prog, reduceStats) {
	stats := reduceStats{InputCalls: len(p.Calls)}
	motifKeys := make([]string, len(p.Calls))
	execKeys := executableCallKeys(p)
	motifRanks := make([]int, len(p.Calls))
	motifCounts := make(map[string]int)
	for i, call := range p.Calls {
		key := motifKey(call, opts)
		motifKeys[i] = key
		motifRanks[i] = motifCounts[key]
		motifCounts[key]++
	}
	stats.Motifs = len(motifCounts)

	// Every syscall variant must survive reduction. Select the representative
	// with the smallest dependency closure so that the invariant costs as few
	// calls as possible. Do not use executable argument identity here: pointer
	// addresses, copied-in data, and resource identities commonly differ for
	// every dynamic instance and would prevent motif reduction altogether.
	mandatory := mandatoryVariantCalls(p)
	keep := make([]bool, len(p.Calls))
	available := make(map[*prog.ResultArg]bool)
	liveResources := make(map[*prog.ResultArg]bool)
	keptMotifs := make(map[string]int)
	for i, call := range p.Calls {
		if mandatory[i] {
			keepCall(call, i, keep, available, liveResources, &stats)
			keptMotifs[motifKeys[i]]++
			continue
		}
		if opts.MaxCalls > 0 && stats.OutputCalls >= opts.MaxCalls {
			stats.DroppedBudget++
			continue
		}
		if opts.MaxMotifInstances > 0 && keptMotifs[motifKeys[i]] >= opts.MaxMotifInstances {
			stats.DroppedMotif++
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
		keepCall(call, i, keep, available, liveResources, &stats)
		keptMotifs[motifKeys[i]]++
	}

	if stats.OutputCalls == 0 && len(p.Calls) != 0 {
		keep[0] = true
		stats.OutputCalls = 1
	}
	reduced := p.CloneFilter(keep)
	stats.WeightedCalls = applyFrequencyWeights(p, reduced, keep, execKeys)
	return reduced, stats
}

func keepCall(call *prog.Call, index int, keep []bool, available, liveResources map[*prog.ResultArg]bool,
	stats *reduceStats) {
	keep[index] = true
	stats.OutputCalls++
	for _, res := range producedResources(call) {
		available[res] = true
		liveResources[res] = true
	}
	for _, res := range closedResources(call) {
		delete(liveResources, res)
	}
}

// executableCallKeys identifies calls that rerun can safely combine. Pointer
// addresses, copied-in data, and resource identities are executable arguments;
// differing in any of them requires retaining a separate structural call.
func executableCallKeys(p *prog.Prog) []string {
	resourceIDs := make(map[*prog.ResultArg]int)
	for _, call := range p.Calls {
		for _, res := range producedResources(call) {
			if _, ok := resourceIDs[res]; !ok {
				resourceIDs[res] = len(resourceIDs)
			}
		}
	}
	keys := make([]string, len(p.Calls))
	for i, call := range p.Calls {
		var b strings.Builder
		b.WriteString(call.Meta.Name)
		for _, arg := range call.Args {
			b.WriteByte('|')
			writeExecutableArgKey(&b, arg, resourceIDs)
		}
		keys[i] = b.String()
	}
	return keys
}

// canFrequencyWeight reports whether csource can repeat a call without losing
// per-invocation behavior. Copyins run only once before a rerun loop.
func canFrequencyWeight(call *prog.Call) bool {
	return call.Props.FailNth == 0 && !call.Props.Async && !hasCopyin(call) &&
		len(producedResources(call)) == 0 && len(usedResources(call)) == 0
}

func hasCopyin(call *prog.Call) bool {
	found := false
	prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
		if found || ctx.Base == nil {
			return
		}
		switch arg.(type) {
		case *prog.GroupArg, *prog.UnionArg:
			return
		}
		typ := arg.Type()
		found = arg.Dir() != prog.DirOut && !prog.IsPad(typ) &&
			(arg.Size() != 0 || typ.IsBitfield())
	})
	return found
}

func writeExecutableArgKey(b *strings.Builder, arg prog.Arg, resourceIDs map[*prog.ResultArg]int) {
	switch arg := arg.(type) {
	case *prog.ConstArg:
		fmt.Fprintf(b, "c:%x", arg.Val)
	case *prog.ResultArg:
		if arg.Res == nil {
			fmt.Fprintf(b, "r:v%x", arg.Val)
		} else {
			fmt.Fprintf(b, "r:%d/%x+%x", resourceIDs[arg.Res], arg.OpDiv, arg.OpAdd)
		}
	case *prog.PointerArg:
		fmt.Fprintf(b, "p:%x:%x(", arg.Address, arg.VmaSize)
		if arg.Res != nil {
			writeExecutableArgKey(b, arg.Res, resourceIDs)
		}
		b.WriteByte(')')
	case *prog.DataArg:
		if arg.Dir() == prog.DirOut {
			fmt.Fprintf(b, "d:out:%x", arg.Size())
		} else {
			fmt.Fprintf(b, "d:in:%x", arg.Data())
		}
	case *prog.GroupArg:
		b.WriteString("g[")
		for _, inner := range arg.Inner {
			writeExecutableArgKey(b, inner, resourceIDs)
			b.WriteByte(';')
		}
		b.WriteByte(']')
	case *prog.UnionArg:
		fmt.Fprintf(b, "u:%d(", arg.Index)
		writeExecutableArgKey(b, arg.Option, resourceIDs)
		b.WriteByte(')')
	default:
		panic(fmt.Sprintf("unsupported executable argument type %T", arg))
	}
}

func mandatoryVariantCalls(p *prog.Prog) []bool {
	producer := make(map[*prog.ResultArg]int)
	for i, call := range p.Calls {
		for _, res := range producedResources(call) {
			producer[res] = i
		}
	}
	closures := make([][]int, len(p.Calls))
	for i := range p.Calls {
		seen := make(map[int]bool)
		var visit func(int)
		visit = func(index int) {
			if seen[index] {
				return
			}
			seen[index] = true
			for _, res := range usedResources(p.Calls[index]) {
				if res.Res != nil {
					if dep, ok := producer[res.Res]; ok {
						visit(dep)
					}
				}
			}
		}
		visit(i)
		for index := range seen {
			closures[i] = append(closures[i], index)
		}
		sort.Ints(closures[i])
	}

	best := make(map[string]int)
	for i, call := range p.Calls {
		key := call.Meta.Name
		previous, ok := best[key]
		if !ok || len(closures[i]) < len(closures[previous]) {
			best[key] = i
		}
	}
	mandatory := make([]bool, len(p.Calls))
	addClosure := func(representative int) {
		for _, index := range closures[representative] {
			mandatory[index] = true
		}
	}
	for _, representative := range best {
		addClosure(representative)
	}
	return mandatory
}

// applyFrequencyWeights restores original invocations when the reduced program
// retains an executable-equivalent call. Only calls with identical executable
// arguments share a weight: csource performs copyins once and rerun repeats the
// retained call verbatim.
// Calls without a retained executable-equivalent representative are omitted
// from the frequency total; representing them with rerun would change behavior.
func applyFrequencyWeights(original, reduced *prog.Prog, keep []bool, execKeys []string) int {
	byExecutableCall := make(map[string][]int)
	originalToReduced := make([]int, len(original.Calls))
	for i := range originalToReduced {
		originalToReduced[i] = -1
	}
	for originalIndex, reducedIndex := 0, 0; originalIndex < len(keep); originalIndex++ {
		if !keep[originalIndex] {
			continue
		}
		originalToReduced[originalIndex] = reducedIndex
		if canFrequencyWeight(original.Calls[originalIndex]) {
			key := execKeys[originalIndex]
			byExecutableCall[key] = append(byExecutableCall[key], originalIndex)
		}
		reducedIndex++
	}

	weights := make([]int, len(reduced.Calls))
	for originalIndex, call := range original.Calls {
		if !canFrequencyWeight(call) {
			if reducedIndex := originalToReduced[originalIndex]; reducedIndex >= 0 {
				weights[reducedIndex] += 1 + call.Props.Rerun
			}
			continue
		}
		candidates := byExecutableCall[execKeys[originalIndex]]
		if len(candidates) == 0 {
			continue
		}
		representative := nearestIndex(candidates, originalIndex)
		weight := 1 + call.Props.Rerun
		weights[originalToReduced[representative]] += weight
	}
	total := 0
	for i, weight := range weights {
		// csource emits the call once, followed by Props.Rerun extra calls.
		reduced.Calls[i].Props.Rerun = weight - 1
		total += weight
	}
	return total
}

func nearestIndex(indices []int, target int) int {
	pos := sort.SearchInts(indices, target)
	if pos == 0 {
		return indices[0]
	}
	if pos == len(indices) {
		return indices[len(indices)-1]
	}
	if target-indices[pos-1] <= indices[pos]-target {
		return indices[pos-1]
	}
	return indices[pos]
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
