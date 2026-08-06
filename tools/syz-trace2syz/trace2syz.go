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
	"regexp"
	"sort"
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
	target := initializeTarget(*flagOS, *flagArch)
	progs, stats := parseTraces(target)
	writeTranslationReport(*flagDeserialize, stats, progs)
	if !*flagSkipCorpus {
		log.Logf(0, "successfully converted traces; generating corpus.db")
		pack(progs)
	}
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

func makeOutputPrefix(fname string) string {
	name := filepath.Base(fname)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	invalidChar := regexp.MustCompile(`[^A-Za-z0-9_]`)
	name = invalidChar.ReplaceAllString(name, "_")
	name = strings.TrimLeft(name, "_")
	if len(name) == 0 {
		return "empty"
	} else if len(name) < 5 {
		return name
	} else {
		return name[:5]
	}
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

func parseTraces(target *prog.Target) ([]*prog.Prog, *proggen.TranslationStats) {
	var ret []*prog.Prog
	var names []string
	progPrefix := make(map[*prog.Prog]string)
	stats := proggen.NewTranslationStats()

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
		progs, fileStats, err := proggen.ParseFileWithStats(file, target, *flagSplitThreads,
			*flagArgLength, *flagMadviseSetup)
		stats.Merge(fileStats)
		fmt.Fprintf(os.Stderr, "Generated %d programs\n", len(progs))
		for idx, p := range progs {
			fmt.Fprintf(os.Stderr, "Length of program %d: %d\n", idx+1, len(p.Calls))
			progPrefix[p] = makeOutputPrefix(names[i])
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
	return ret, stats
}

func writeTranslationReport(dir string, stats *proggen.TranslationStats, progs []*prog.Prog) {
	if dir == "" {
		return
	}
	generated := make(map[string]int)
	for _, p := range progs {
		for name, count := range genSyscallHist(p) {
			generated[name] += count
		}
	}
	data := formatTranslationReport(stats, generated)
	if err := osutil.WriteFile(filepath.Join(dir, "translation_report.txt"), data); err != nil {
		log.Fatalf("failed to write translation report: %v", err)
	}
}

func formatTranslationReport(stats *proggen.TranslationStats, generated map[string]int) []byte {
	var report strings.Builder
	var absent []string
	inputCalls, representedCalls, representedNames := 0, 0, 0
	for name, count := range stats.Input {
		inputCalls += count
		representedCalls += stats.Represented[name]
		if stats.Represented[name] == 0 {
			absent = append(absent, name)
		} else {
			representedNames++
		}
	}
	sort.Strings(absent)
	fmt.Fprintf(&report, "Input syscall-name coverage: %d/%d (%.2f%%)\n",
		representedNames, len(stats.Input), percent(representedNames, len(stats.Input)))
	fmt.Fprintf(&report, "Absent input syscall names (%d):\n", len(absent))
	for _, name := range absent {
		fmt.Fprintf(&report, "  %s\n", name)
	}

	helpers := sortedKeys(stats.Helpers)
	fmt.Fprintf(&report, "Generated syzlang helpers (%d):\n", len(helpers))
	for _, helper := range helpers {
		var sources []string
		count := 0
		for source, sourceCount := range stats.Helpers[helper] {
			count += sourceCount
			sources = append(sources, fmt.Sprintf("%s=%d", source, sourceCount))
		}
		sort.Strings(sources)
		fmt.Fprintf(&report, "  %s (%d calls): %s\n", helper, count, strings.Join(sources, ", "))
	}

	generatedCalls := 0
	for _, count := range generated {
		generatedCalls += count
	}
	fmt.Fprintf(&report, "Input syscall-call coverage: %d/%d (%.2f%%)\n",
		representedCalls, inputCalls, percent(representedCalls, inputCalls))
	fmt.Fprintf(&report, "Raw syscall call counts (strace/generated syzlang): %d/%d\n",
		inputCalls, generatedCalls)
	return []byte(report.String())
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
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
