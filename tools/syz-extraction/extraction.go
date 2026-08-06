// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/internal/csbprog"
)

type TIDIndices struct {
	Tid     int64
	Indices []int
}

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	flagProg = flag.String("prog", "", "file with program to convert (required)")

	flagStrict      = flag.Bool("strict", false, "parse input program in strict mode")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagMinCalls    = flag.Int("minCalls", 1, "deprecated compatibility flag; non-empty components are always emitted")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
	flagJobs        = flag.Int("jobs", defaultJobs(), "number of extracted programs to build in parallel")
	flagMaxPerShape = flag.Int("maxComponentsPerShape", 8,
		"maximum representatives per structural call shape; 0 keeps every component")

	syscallIDxPerTid = make(map[int64][]int)
)

func defaultJobs() int {
	return min(runtime.NumCPU(), 4)
}

func help() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *flagMaxPerShape < 0 {
		fmt.Fprintln(os.Stderr, "-maxComponentsPerShape must be non-negative")
		os.Exit(1)
	}
}

func readProg() (p *prog.Prog) {
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	comments := csbprog.CommentsFromData(data)
	mode := prog.NonStrictUnsafe
	safeMode := prog.NonStrict
	if *flagStrict {
		mode = prog.StrictUnsafe
		safeMode = prog.Strict
	}
	p, err = target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	csbprog.SanitizeFilenames(p)
	p, err = target.Deserialize(p.Serialize(), safeMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize sanitized program: %v\n", err)
		os.Exit(1)
	}
	p.Comments = comments
	return
}

func generateMinimizedProg(p *prog.Prog, callIndex0 int, processedCallsIn []bool, c *prog.Cache) (pOut *prog.Prog, processedCalls []bool, keepCalls []bool) {
	pOut, processedCalls, keepCalls = prog.RemoveUnrelatedCallsFast(p, callIndex0, processedCallsIn, c)
	return
}

type extractedComponent struct {
	data  []byte
	calls int
	names []string
	shape string
}

type selectedComponent struct {
	component extractedComponent
	sequence  int
	digest    [sha256.Size]byte
}

type shapeSelection struct {
	first  []selectedComponent
	middle []selectedComponent
	last   *selectedComponent
}

type shapeSelector struct {
	limit     int
	generated int
	next      int
	shapes    map[string]*shapeSelection
	unlimited []selectedComponent
}

func newShapeSelector(limit int) *shapeSelector {
	return &shapeSelector{limit: limit, shapes: make(map[string]*shapeSelection)}
}

func (selector *shapeSelector) add(component extractedComponent) {
	if component.data == nil {
		return
	}
	selector.generated++
	candidate := selectedComponent{
		component: component,
		sequence:  selector.next,
		digest:    sha256.Sum256(component.data),
	}
	selector.next++
	if selector.limit == 0 {
		selector.unlimited = append(selector.unlimited, candidate)
		return
	}
	selection := selector.shapes[component.shape]
	if selection == nil {
		selection = new(shapeSelection)
		selector.shapes[component.shape] = selection
	}
	if selection.hasDigest(candidate.digest) {
		return
	}
	firstLimit := min(selector.limit, 2)
	if len(selection.first) < firstLimit {
		selection.first = append(selection.first, candidate)
		return
	}
	if selector.limit <= 2 {
		return
	}
	if selection.last != nil {
		selection.addMiddle(*selection.last, selector.limit-firstLimit-1)
	}
	selection.last = &candidate
}

func (selection *shapeSelection) hasDigest(digest [sha256.Size]byte) bool {
	for _, candidate := range selection.first {
		if candidate.digest == digest {
			return true
		}
	}
	for _, candidate := range selection.middle {
		if candidate.digest == digest {
			return true
		}
	}
	return selection.last != nil && selection.last.digest == digest
}

func (selection *shapeSelection) addMiddle(candidate selectedComponent, limit int) {
	if limit == 0 {
		return
	}
	selection.middle = append(selection.middle, candidate)
	slices.SortFunc(selection.middle, func(a, b selectedComponent) int {
		return bytes.Compare(a.digest[:], b.digest[:])
	})
	if len(selection.middle) > limit {
		selection.middle = selection.middle[:limit]
	}
}

func (selector *shapeSelector) selected() []extractedComponent {
	selected := append([]selectedComponent(nil), selector.unlimited...)
	for _, selection := range selector.shapes {
		selected = append(selected, selection.first...)
		selected = append(selected, selection.middle...)
		if selection.last != nil {
			selected = append(selected, *selection.last)
		}
	}
	slices.SortFunc(selected, func(a, b selectedComponent) int {
		return cmp.Compare(a.sequence, b.sequence)
	})
	ret := make([]extractedComponent, len(selected))
	for i := range selected {
		ret[i] = selected[i].component
	}
	return ret
}

func isPollLike(syscallName string) bool {
	pollLikes := []string{
		"epoll_pwait",
		"epoll_wait",
		"poll",
		"ppoll",
		"select",
	}
	for _, v := range pollLikes {
		if syscallName == v {
			return true
		}
	}
	return false
}

func filterOutPolls(p *prog.Prog) *prog.Prog {
	notPolls := make([]bool, len(p.Calls))
	prevPoll := make(map[int64]int)
	for idx, c := range p.Calls {
		if isPollLike(c.Meta.Name) {
			prevPoll[c.StraceTid] = idx
		} else if oldIdx, ok := prevPoll[c.StraceTid]; ok {
			notPolls[oldIdx] = true // Keep the last poll in the sequence.
			delete(prevPoll, c.StraceTid)
			notPolls[idx] = true
		} else {
			notPolls[idx] = true
		}
	}
	for _, idx := range prevPoll {
		notPolls[idx] = true // Keep the final poll in a trailing sequence.
	}
	px := p.CloneFilter(notPolls)
	return px
}

func filterOutPollIndices(p *prog.Prog, indices []int) []int {
	keep := make([]bool, len(indices))
	prevPoll := make(map[int64]int)
	for pos, index := range indices {
		call := p.Calls[index]
		if isPollLike(call.Meta.Name) {
			prevPoll[call.StraceTid] = pos
		} else {
			if oldPos, ok := prevPoll[call.StraceTid]; ok {
				keep[oldPos] = true
				delete(prevPoll, call.StraceTid)
			}
			keep[pos] = true
		}
	}
	for _, pos := range prevPoll {
		keep[pos] = true // Keep the final poll in a trailing sequence.
	}
	out := make([]int, 0, len(indices))
	for pos, index := range indices {
		if keep[pos] {
			out = append(out, index)
		}
	}
	return out
}

func getOutPrefix() string {
	prefixLen := 2
	progBase := filepath.Base(*flagProg)
	splitBase := strings.Split(progBase, "_")
	if len(splitBase) > 1 && (splitBase[0] == "thread" || splitBase[0] == "program") {
		progBase = strings.Join(splitBase[1:], "_")
		prefixLen = 1
	}
	splitBase = strings.Split(progBase, "_")
	if len(splitBase) < prefixLen {
		prefixLen = len(splitBase)
	}
	outPrefix := strings.Join(splitBase[:prefixLen], "_")
	return outPrefix
}

func newCache() *prog.Cache {
	return new(prog.Cache)
}

func generateAllProgs(p *prog.Prog, threadList []int64) {
	numCalls := len(p.Calls)
	outPrefixesIdx := make(map[string]int)
	outPrefix := getOutPrefix()

	fmt.Fprintf(os.Stderr, "Total number of syscalls: %d\n", numCalls)

	c := newCache()
	prog.PrepareDependencyIndex(p, c)
	selector := newShapeSelector(*flagMaxPerShape)

	totalStartSyscalls := 0
	usedStartSyscalls := 0
	for _, tid := range threadList {
		totalStartSyscalls += len(syscallIDxPerTid[tid])
	}
	// go over all thread IDs in decreasing depth starting with the highest depth
	for idx, tid := range threadList {
		numCallsTid := len(syscallIDxPerTid[tid])
		fmt.Printf("[%d/%d] Working on TID %d - %d syscalls\n", idx+1, len(threadList), tid, numCallsTid)

		usedStartSyscalls += numCallsTid
		status := fmt.Sprintf("-- Progress TID [100.0/100%%] -- Progress overall [%03.1f/100%%] --", (100 * float32(usedStartSyscalls) / float32(totalStartSyscalls)))
		fmt.Fprintf(os.Stderr, "%s\r", status)

		emit := func(results []extractedComponent) {
			for _, result := range results {
				selector.add(result)
			}
		}
		processThreadComponents(p, tid, syscallIDxPerTid[tid], c, emit)
		fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	}
	selected := selector.selected()
	fmt.Fprintf(os.Stderr, "Shape selection: generated %d components across %d shapes, retained %d, folded %d\n",
		selector.generated, len(selector.shapes), len(selected), selector.generated-len(selected))
	for _, result := range selected {
		prefix := outPrefix + "_" + strings.Join(result.names, "_")
		index := outPrefixesIdx[prefix]
		outPrefixesIdx[prefix] = index + 1
		fmt.Fprintf(os.Stderr, "    Extracted %d syscalls into %s_%d\n", result.calls, prefix, index)
		saveProg2File(result.data, prefix, index)
	}
}

func processThreadComponents(p *prog.Prog, tid int64, callIndices []int, c *prog.Cache,
	emit func([]extractedComponent)) {
	batchSize := max(*flagJobs, 1)
	components := make([]prog.RelatedCallComponent, 0, batchSize)
	flush := func() {
		if len(components) == 0 {
			return
		}
		emit(processComponents(p, components))
		components = components[:0]
	}
	// Flush bounded batches in discovery order so memory follows -jobs, not trace length.
	prog.ForEachRelatedCallComponentForThread(p, tid, callIndices, c, func(component prog.RelatedCallComponent) {
		components = append(components, component)
		if len(components) == batchSize {
			flush()
		}
	})
	flush()
}

// processComponents writes into fixed result slots so worker scheduling cannot change output order.
func processComponents(p *prog.Prog, components []prog.RelatedCallComponent) []extractedComponent {
	results := make([]extractedComponent, len(components))
	jobs := *flagJobs
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(components) {
		jobs = len(components)
	}
	if jobs == 0 {
		return results
	}

	work := make(chan int)
	var wg sync.WaitGroup
	wg.Add(jobs)
	for range jobs {
		go func() {
			defer wg.Done()
			for i := range work {
				component := components[i]
				indices := component.KeepCalls
				if !component.FilterCalls {
					indices = make([]int, len(p.Calls))
					for i := range indices {
						indices[i] = i
					}
				}
				indices = filterOutPollIndices(p, indices)
				if len(indices) == 0 {
					continue
				}
				pF := p.CloneCalls(indices)
				pF.Comments = append([]string(nil), p.Comments...)
				results[i].data = csbprog.Serialize(pF)
				results[i].calls = len(indices)
				scallHist := genSyscallHist(pF)
				results[i].names = stat.TopKNames(scallHist, *flagTopCalls)
				results[i].shape = componentShape(pF)
			}
		}()
	}
	for i := range components {
		work <- i
	}
	close(work)
	wg.Wait()

	return results
}

func componentShape(p *prog.Prog) string {
	var shape strings.Builder
	results := make(map[*prog.ResultArg]int)
	for callIndex, call := range p.Calls {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			result, ok := arg.(*prog.ResultArg)
			if ok && result.Res == nil && result.Dir() == prog.DirOut {
				results[result] = callIndex
			}
		})
	}
	for _, call := range p.Calls {
		fmt.Fprintf(&shape, "call:%s;props:%d,%t,%d;", call.Meta.Name,
			call.Props.FailNth, call.Props.Async, call.Props.Rerun)
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			fmt.Fprintf(&shape, "%T:%s:%s", arg, arg.Type().Name(), arg.Dir())
			switch typed := arg.(type) {
			case *prog.ResultArg:
				if typed.Res != nil {
					if producer, ok := results[typed.Res]; ok {
						fmt.Fprintf(&shape, ":ref=%d", producer)
					} else {
						shape.WriteString(":external-ref")
					}
				} else if typed.Dir() == prog.DirOut {
					shape.WriteString(":producer")
				} else {
					shape.WriteString(":literal")
				}
			case *prog.PointerArg:
				fmt.Fprintf(&shape, ":special=%t:vma=%t:pointee=%t", typed.IsSpecial(),
					typed.VmaSize != 0, typed.Res != nil)
			case *prog.DataArg:
				fmt.Fprintf(&shape, ":size=%d", typed.Size())
			case *prog.GroupArg:
				fmt.Fprintf(&shape, ":items=%d", len(typed.Inner))
			case *prog.UnionArg:
				fmt.Fprintf(&shape, ":option=%d", typed.Index)
			}
			shape.WriteByte(';')
		})
	}
	return shape.String()
}

func genSyscallHist(p *prog.Prog) map[string]int {
	hist := make(map[string]int)

	for _, call := range p.Calls {
		_, ok := hist[call.Meta.CallName]
		if !ok {
			hist[call.Meta.CallName] = 1
		} else {
			hist[call.Meta.CallName]++
		}
	}

	return hist
}

func saveProg2File(data []byte, prefix string, index int) {
	outName := filepath.Join(*flagDeserialize, "min_"+prefix+"_"+strconv.Itoa(index)+".prog")
	if err := osutil.WriteFile(outName, data); err != nil {
		log.Fatalf("failed to output file: %v", err)
	}
}

// a map from TID to clone depth
type ThreadSet map[int64]bool

func buildThreadList(p *prog.Prog) []int64 {
	tt := make(ThreadSet)
	tl := make([]int64, 0)

	for idx, c := range p.Calls {
		tt[c.StraceTid] = true
		tid := c.StraceTid
		syscallIDxPerTid[tid] = append(syscallIDxPerTid[tid], idx)
	}
	for t := range tt {
		tl = append(tl, t)
	}

	slices.SortStableFunc(tl, func(a, b int64) int {
		return cmp.Compare(a, b)
	})
	slices.Reverse(tl)

	return tl
}

func main() {
	help()

	p := readProg()

	threads := buildThreadList(p)

	generateAllProgs(p, threads)
}
