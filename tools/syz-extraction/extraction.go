// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	flagProg = flag.String("prog", "", "file with program to convert (required)")

	flagStrict      = flag.Bool("strict", false, "parse input program in strict mode")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagMinCalls    = flag.Int("minCalls", 10, "minimum number of remaining syscalls after minimization")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
)

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
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err = target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	return
}

func generateMinimizedProg(p *prog.Prog, callIndex0 int, processedCallsIn []bool, c *prog.Cache, ) (pOut *prog.Prog, processedCalls []bool, keepCalls []bool) {
	pOut, processedCalls, keepCalls = prog.RemoveUnrelatedCallsFast(p, callIndex0, processedCallsIn, c)
	return
}

func generateAllProgs(p *prog.Prog, threadList []int64) (pF *prog.Prog) {
	numCalls := len(p.Calls)
	processedCalls := make([]bool, numCalls)
	processedCalls[numCalls-1] = false
	keepCalls := make([]bool, numCalls)
	nonStartCalls := make([]bool, numCalls)
	outPrefixesIdx := make(map[string]int)
	prefixLen := 2
	c := new(prog.Cache)
	c.Uses = make([]map[any]bool, numCalls)
	c.Rets = make([]map[any]bool, numCalls)
	c.UsesBFs = make([]*bloom.BloomFilter, numCalls)
	c.RetsBFs = make([]*bloom.BloomFilter, numCalls)
	fmt.Fprintf(os.Stderr, "Number of syscalls before: %d\n", numCalls)

	// go over all thread IDs in decreasing depth starting with the highest depth
	for _, tid := range threadList {
		fmt.Printf("Working on TID %d\n", tid)

		for i := numCalls - 1; i > 0; {
			// if i%1000 == 0 {
			// 	fmt.Fprintf(os.Stderr, "(%d/%d) Finished (cache: %d entries) @ %s.\n", i, numCalls, len(c.Uses), time.Now())
			// }
			if !nonStartCalls[i] && p.Calls[i].StraceTid == tid {
				pF, processedCalls, keepCalls = generateMinimizedProg(p, i, processedCalls, c)
				nonStartCalls = prog.Sliceor(prog.Sliceor(processedCalls, keepCalls), nonStartCalls)

				if len(pF.Calls) >= *flagMinCalls {
					fmt.Fprintf(os.Stderr, "(%d/%d) Number of syscalls after: %d\n", i, len(p.Calls), len(pF.Calls))
					prefixLen = 2
					progBase := filepath.Base(*flagProg)
					splitBase := strings.Split(progBase, "_")
					if len(splitBase) > 1 && (splitBase[0] == "thread" || splitBase[0] == "program") {
						progBase = strings.Join(splitBase[1:], "_")
						prefixLen = 1
					}

					scallHist := genSyscallHist(pF)
					topNames := stat.TopKNames(scallHist, *flagTopCalls)
					outPrefix := strings.Join(strings.Split(progBase, "_")[:prefixLen], "_") + "_" + strings.Join(topNames, "_")
					_, ok := outPrefixesIdx[outPrefix]
					if !ok {
						outPrefixesIdx[outPrefix] = 0
					} else {
						outPrefixesIdx[outPrefix]++
					}

					saveProg2File(pF, outPrefix, outPrefixesIdx[outPrefix])
				} else {
					fmt.Fprintf(os.Stderr, "(%d/%d) Number of syscalls after: %d, not saving the file.\n", i, len(p.Calls), len(pF.Calls))
				}
			}
			// p.RemoveCall(i)
			i--
		}

	}

	return
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

func saveProg2File(p *prog.Prog, prefix string, index int) {
	outName := filepath.Join(*flagDeserialize, "min_"+prefix+"_"+strconv.Itoa(index)+".prog")
	if err := osutil.WriteFile(outName, p.Serialize()); err != nil {
		log.Fatalf("failed to output file: %v", err)
	}
	log.Logf(0, "Stored program %s", outName)
}

func extractResources(c *prog.Call) map[any]bool {
	used := make(map[any]bool)

	prog.ForeachArg(c, func(arg prog.Arg, _ *prog.ArgCtx) {
		switch typ := arg.Type().(type) {
		case *prog.ResourceType:
			a := arg.(*prog.ResultArg)
			used[a] = true
			if a.Res != nil {
				used[a.Res] = true
			}
			for use := range prog.GetUses(a) {
				used[use] = true
			}
		case *prog.BufferType:
			a := arg.(*prog.DataArg)
			if a.Dir() != prog.DirOut && typ.Kind == prog.BufferFilename {
				val := string(bytes.TrimRight(a.Data(), "\x00"))
				used[val] = true
			}
		}
	})

	return used
}

// subtracts list1 from list, returns true if there are elements in list1, that are not present in list
func mapsNewInRightAny(list map[any]bool, list1 map[any]bool) bool {
	for what := range list1 {
		if !list[what] {
			return true
		}
	}
	return false
}

// a map from TID to clone depth
type ThreadSet map[int64]bool

func buildThreadList(p *prog.Prog) []int64 {
	tt := make(ThreadSet)
	tl := make([]int64, 0)

	for _, c := range p.Calls {
		tt[c.StraceTid] = true
	}
	for t, _ := range tt {
		tl = append(tl, t)
	}
	return tl
}

// a map from TID to clone depth
type ThreadDepth map[int64]int64

func addTid(tt ThreadDepth, tid int64, depth int64) {
	if tt == nil {
		panic("Cannot add child to nil Threat Tree")
	}

	d, ok := tt[tid]
	if !ok {
		tt[tid] = depth
		return
	}

	if d != depth {
		panic(fmt.Sprintf("TID %d already exists at depth %d. Trying to add at depth %d\n", tid, d, depth))
	}
}

func addChild(tt ThreadDepth, parent int64, child int64) {
	d, ok := tt[parent]
	if !ok {
		panic(fmt.Sprintf("Parent TID %d not found in thread tree\n", parent))
	}
	childDepth := d+1
	addTid(tt, child, childDepth)
}

func buildThreadTree(p *prog.Prog) ThreadDepth {
	tt := make(ThreadDepth)
	addTid(tt, p.Calls[0].StraceTid, 0)

	for _, c := range p.Calls {
		if c.Meta.CallName == "clone" || c.Meta.CallName == "clone3" {
			parentTid := c.StraceTid
			childTid := c.StraceRetVal
			addChild(tt, parentTid, childTid)
		}
	}
	return tt
}

func checks(p *prog.Prog) {
	for _, c := range p.Calls {
		if c.Meta.CallName == "io_getevents" {
			for idx, arg := range c.Args {
				fmt.Fprintf(os.Stderr, "Argument %d: %#v\n", idx, arg)
			}
		}
	}
}


type kv struct {
	Key   int64
	Value int64
}

func sortThreadTree(tt ThreadDepth) []kv {
	var ss []kv
    for k, v := range tt {
        ss = append(ss, kv{k, v})
    }

	sort.Slice(ss, func(i, j int) bool {
        return ss[i].Value > ss[j].Value
    })

	return ss
}

func main() {
	help()

	p := readProg()

	threads := buildThreadList(p)

	generateAllProgs(p, threads)
}
