// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
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
	flagMinCalls    = flag.Int("minCalls", 5, "minimum number of remaining syscalls after minimization")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
	flagJobs        = flag.Int("jobs", defaultJobs(), "number of extracted programs to build in parallel")

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
	comments := csbCommentsFromData(data)
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
	sanitizeFilenames(p)
	p, err = target.Deserialize(p.Serialize(), safeMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize sanitized program: %v\n", err)
		os.Exit(1)
	}
	p.Comments = comments
	return
}

// csbCommentsFromData retains only trace metadata that must survive extraction and serialization.
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

func generateMinimizedProg(p *prog.Prog, callIndex0 int, processedCallsIn []bool, c *prog.Cache) (pOut *prog.Prog, processedCalls []bool, keepCalls []bool) {
	pOut, processedCalls, keepCalls = prog.RemoveUnrelatedCallsFast(p, callIndex0, processedCallsIn, c)
	return
}

type extractedComponent struct {
	data  []byte
	calls int
	names []string
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
				if result.data == nil {
					continue
				}
				prefix := outPrefix + "_" + strings.Join(result.names, "_")
				if _, ok := outPrefixesIdx[prefix]; ok {
					outPrefixesIdx[prefix]++
				} else {
					outPrefixesIdx[prefix] = 0
				}
				fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
				fmt.Fprintf(os.Stderr, "    Extracted %d syscalls into %s_%d\n",
					result.calls, prefix, outPrefixesIdx[prefix])
				saveProg2File(result.data, prefix, outPrefixesIdx[prefix])
			}
		}
		processThreadComponents(p, tid, syscallIDxPerTid[tid], c, emit)
		fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
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
				if len(indices) < *flagMinCalls {
					continue
				}
				pF := p.CloneCalls(indices)
				pF.Comments = append([]string(nil), p.Comments...)
				results[i].data = serializeWithComments(pF)
				results[i].calls = len(indices)
				scallHist := genSyscallHist(pF)
				results[i].names = stat.TopKNames(scallHist, *flagTopCalls)
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

// csbComments checks program and call comments because filtering can move metadata between them.
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
