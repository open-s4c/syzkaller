// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

// syz-trace2syz converts strace traces to syzkaller programs.
//
// Simple usage:
//
//	strace -o trace -a 1 -s 65500 -v -xx -f -Xraw --raw=wait4 ./a.out
//	syz-trace2syz -file trace
//
// Intended for seed selection or debugging
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/tools/syz-trace2syz/proggen"
)

var (
	flagFile         = flag.String("file", "", "file to parse")
	flagDir          = flag.String("dir", "", "directory to parse")
	flagDeserialize  = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagSkipCorpus   = flag.Bool("nocorpus", false, "(Optional) skip generating corpus.db")
	flagTopCalls     = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
	flagSplitThreads = flag.Bool("splitThreads", false, "stores one program program per thread")
	flagArgLength    = flag.Bool("argLength", false, "trim the length syscall arguments to the actual data size")
	flagMadviseSetup = flag.Bool("madviseSetup", false,
		"map a dedicated VMA before destructive madvise calls instead of using MADV_NORMAL")
	flagOS = flag.String("os", targets.Linux, "target OS")
	// Preserve the converter's historical amd64 behavior unless the trace architecture is explicit.
	flagArch = flag.String("arch", targets.AMD64, "target architecture")
)

func main() {
	flag.Parse()
	if err := validateTargetOS(*flagOS); err != nil {
		log.Fatalf("%v", err)
	}
	target := initializeTarget(*flagOS, *flagArch)
	progs := parseTraces(target)
	if !*flagSkipCorpus {
		log.Logf(0, "successfully converted traces; generating corpus.db")
		pack(progs)
	}
}

func validateTargetOS(os string) error {
	if os != targets.Linux {
		return fmt.Errorf("unsupported target OS %q: CSB lifecycle helpers require Linux", os)
	}
	return nil
}

func initializeTarget(os, arch string) *prog.Target {
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		log.Fatalf("failed to load target: %s", err)
	}
	// ConstMap exposes ABI values for the selected trace target, not the host running conversion.
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	return target
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

func parseTraces(target *prog.Target) []*prog.Prog {
	var ret []*prog.Prog
	var names []string
	progPrefix := make(map[*prog.Prog]string)

	outPrefixesIdx := make(map[string]int)

	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getTraceFiles(*flagDir)
	} else {
		log.Fatalf("-file or -dir must be specified")
	}

	deserializeDir := *flagDeserialize

	totalFiles := len(names)
	fmt.Fprintf(os.Stderr, "Parsing %v traces\n", totalFiles)
	for i, file := range names {
		fmt.Fprintf(os.Stderr, "Parsing file %v/%v: %v\n", i+1, totalFiles, filepath.Base(names[i]))
		progs, err := proggen.ParseFile(file, target, *flagSplitThreads, *flagArgLength, *flagMadviseSetup)
		fmt.Fprintf(os.Stderr, "Generated %d programs\n", len(progs))
		for idx, p := range progs {
			fmt.Fprintf(os.Stderr, "Length of program %d: %d\n", idx+1, len(p.Calls))
			progPrefix[p] = filepath.Base(names[i])[:5]
		}
		if err != nil {
			log.Fatalf("%v", err)
		}
		ret = append(ret, progs...)
	}

	i := 0
	for _, p := range ret {
		scallHist := genSyscallHist(p)
		topNames := stat.TopKNames(scallHist, *flagTopCalls)
		outPrefix := progPrefix[p] + "_" + strings.Join(topNames, "_")
		outDescr := "program"
		if *flagSplitThreads {
			outDescr = "thread"
		}
		_, ok := outPrefixesIdx[outPrefix]
		if !ok {
			outPrefixesIdx[outPrefix] = 0
		} else {
			outPrefixesIdx[outPrefix]++
		}
		progName := filepath.Join(deserializeDir, outDescr+"_"+outPrefix+"_"+strconv.Itoa(outPrefixesIdx[outPrefix])+".prog")
		data := appendProgMetadata(p.Serialize(), target.OS, target.Arch)
		if err := osutil.WriteFile(progName, data); err != nil {
			log.Fatalf("failed to output file: %v", err)
		}
		log.Logf(0, "Stored program %s", progName)
		i++
	}
	return ret
}

// appendProgMetadata records target identity in namespaced comments understood by downstream tools.
func appendProgMetadata(data []byte, os, arch string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# csb.trace.os=%s\n", os)
	fmt.Fprintf(&b, "# csb.trace.arch=%s\n", arch)
	b.Write(data)
	return []byte(b.String())
}

func getTraceFiles(dir string) []string {
	infos, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("%s", err)

	}
	var names []string
	for _, info := range infos {
		name := filepath.Join(dir, info.Name())
		names = append(names, name)
	}
	return names
}

func pack(progs []*prog.Prog) {
	var records []db.Record
	for _, prog := range progs {
		records = append(records, db.Record{Val: prog.Serialize()})
	}
	if err := db.Create("corpus.db", 0, records); err != nil {
		log.Fatalf("%v", err)
	}
	log.Logf(0, "finished!")
}
