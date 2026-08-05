// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
)

func testDependencyCache(numCalls int) *Cache {
	return &Cache{
		Uses:    make([]map[any]bool, numCalls),
		Rets:    make([]map[any]bool, numCalls),
		UsesBFs: make([]*bloom.BloomFilter, numCalls),
		RetsBFs: make([]*bloom.BloomFilter, numCalls),
	}
}

func deserializeDependencyProg(t testing.TB, text string) *Prog {
	t.Helper()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRelatedCallsFullThreadIndexedMatchesScan(t *testing.T) {
	tests := []struct {
		name      string
		prog      string
		callIndex int
		processed []int
	}{
		{
			name: "same thread resource closure",
			prog: "" +
				"<1>r0 = test$res2()\n" +
				"<1>mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n" +
				"<1>test$res1(0xffff)\n",
			callIndex: 1,
		},
		{
			name: "cross thread non allowed return producer",
			prog: "" +
				"<1>r0 = mutate5(&(0x7f0000000000)='./shared\\x00', 0x0)\n" +
				"<2>mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n" +
				"<2>test$res1(0xffff)\n",
			callIndex: 1,
		},
		{
			name: "cross thread allowed call using same resource",
			prog: "" +
				"<1>r0 = socket(0x111, 0x1000, 0x10000)\n" +
				"<1>ioctl(r0, 0x333, 0x0)\n" +
				"<2>listen(r0)\n" +
				"<2>test$res1(0xffff)\n",
			callIndex: 2,
		},
		{
			name: "filename dependency",
			prog: "" +
				"<1>mutate5(&(0x7f0000000000)='./same-file\\x00', 0x0)\n" +
				"<1>mutate9(&(0x7f0000000040)='./same-file\\x00')\n" +
				"<1>mutate9(&(0x7f0000000100)='./other-file\\x00')\n",
			callIndex: 1,
		},
		{
			name: "processed calls are skipped",
			prog: "" +
				"<1>r0 = test$res2()\n" +
				"<1>mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n" +
				"<1>test$res1(0xffff)\n",
			callIndex: 1,
			processed: []int{0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := deserializeDependencyProg(t, test.prog)
			processed := make([]bool, len(p.Calls))
			for _, idx := range test.processed {
				processed[idx] = true
			}

			scanCache := testDependencyCache(len(p.Calls))
			scanKeep, scanRemove := relatedCallsFullThreadScan(p, test.callIndex, scanCache, processed)

			indexCache := testDependencyCache(len(p.Calls))
			indexKeep, indexRemove := relatedCallsFullThread(p, test.callIndex, indexCache, processed)

			if !reflect.DeepEqual(indexKeep, scanKeep) {
				t.Fatalf("keep calls differ\nindexed: %v\nscan:    %v", indexKeep, scanKeep)
			}
			if !reflect.DeepEqual(indexRemove, scanRemove) {
				t.Fatalf("remove calls differ\nindexed: %v\nscan:    %v", indexRemove, scanRemove)
			}

			if len(test.processed) == 0 {
				indexProg := p.CloneFilter(indexKeep).Serialize()
				scanProg := p.CloneFilter(scanKeep).Serialize()
				if string(indexProg) != string(scanProg) {
					t.Fatalf("filtered programs differ\nindexed:\n%s\nscan:\n%s", indexProg, scanProg)
				}
			}
		})
	}
}

func TestRelatedCallsFullThreadIndexedRebuildsForNewProg(t *testing.T) {
	cache := testDependencyCache(3)
	first := deserializeDependencyProg(t, ""+
		"<1>r0 = test$res2()\n"+
		"<1>mutate6(r0, &(0x7f0000000040)=\"abcd\", 0x4)\n"+
		"<1>test$res1(0xffff)\n")
	relatedCallsFullThread(first, 1, cache, make([]bool, len(first.Calls)))

	second := deserializeDependencyProg(t, ""+
		"<1>mutate5(&(0x7f0000000000)='./same-file\\x00', 0x0)\n"+
		"<1>mutate9(&(0x7f0000000040)='./same-file\\x00')\n"+
		"<1>mutate9(&(0x7f0000000100)='./other-file\\x00')\n")
	scanCache := testDependencyCache(len(second.Calls))
	scanKeep, scanRemove := relatedCallsFullThreadScan(second, 1, scanCache, make([]bool, len(second.Calls)))

	indexKeep, indexRemove := relatedCallsFullThread(second, 1, cache, make([]bool, len(second.Calls)))
	if !reflect.DeepEqual(indexKeep, scanKeep) {
		t.Fatalf("keep calls differ after cache reuse\nindexed: %v\nscan:    %v", indexKeep, scanKeep)
	}
	if !reflect.DeepEqual(indexRemove, scanRemove) {
		t.Fatalf("remove calls differ after cache reuse\nindexed: %v\nscan:    %v", indexRemove, scanRemove)
	}
}

func TestRelatedCallsIncludeParentPathSetup(t *testing.T) {
	p := deserializeDependencyProg(t, ""+
		"<1>mutate5(&(0x7f0000000000)='./db\\x00', 0x0)\n"+
		"<1>mutate9(&(0x7f0000000040)='./db/current\\x00')\n"+
		"<1>mutate9(&(0x7f0000000100)='./other/file\\x00')\n")

	keep, _ := relatedCallsFullThread(p, 1, testDependencyCache(len(p.Calls)),
		make([]bool, len(p.Calls)))
	if !keep[0] {
		t.Fatal("setup of parent path was not retained")
	}
	if keep[2] {
		t.Fatal("unrelated path was retained")
	}
}

func TestRelatedCallComponentsForThreadMatchesScanLoop(t *testing.T) {
	p := deserializeDependencyProg(t, ""+
		"<2>r0 = socket(0x111, 0x1000, 0x10000)\n"+
		"<2>ioctl(r0, 0x333, 0x0)\n"+
		"<1>listen(r0)\n"+
		"<1>test$res1(0xffff)\n"+
		"<1>r1 = mutate5(&(0x7f0000000000)='./same-file\\x00', 0x0)\n"+
		"<1>mutate9(&(0x7f0000000040)='./same-file\\x00')\n"+
		"<1>mutate9(&(0x7f0000000100)='./other-file\\x00')\n"+
		"<1>mutate6(r1, &(0x7f0000000140)=\"abcd\", 0x4)\n")

	callIndices := []int{2, 3, 4, 5, 6, 7}
	scanComponents := scanLoopComponents(p, 1, callIndices)
	indexComponents := RelatedCallComponentsForThread(p, 1, callIndices, testDependencyCache(len(p.Calls)))

	if len(indexComponents) != len(scanComponents) {
		t.Fatalf("got %d components, want %d", len(indexComponents), len(scanComponents))
	}
	for i := range scanComponents {
		if indexComponents[i].StartIndex != scanComponents[i].StartIndex {
			t.Fatalf("component %d start = %d, want %d", i, indexComponents[i].StartIndex, scanComponents[i].StartIndex)
		}
		if !reflect.DeepEqual(indexComponents[i].KeepCalls, scanComponents[i].KeepCalls) {
			t.Fatalf("component %d keep calls differ\nindexed: %v\nscan:    %v",
				i, indexComponents[i].KeepCalls, scanComponents[i].KeepCalls)
		}
		if !reflect.DeepEqual(indexComponents[i].RemoveCalls, scanComponents[i].RemoveCalls) {
			t.Fatalf("component %d remove calls differ\nindexed: %v\nscan:    %v",
				i, indexComponents[i].RemoveCalls, scanComponents[i].RemoveCalls)
		}
		if indexComponents[i].FilterCalls != scanComponents[i].FilterCalls {
			t.Fatalf("component %d filter = %v, want %v", i,
				indexComponents[i].FilterCalls, scanComponents[i].FilterCalls)
		}
		indexProg := p.CloneCalls(indexComponents[i].KeepCalls).Serialize()
		scanProg := p.CloneCalls(scanComponents[i].KeepCalls).Serialize()
		if string(indexProg) != string(scanProg) {
			t.Fatalf("component %d filtered programs differ\nindexed:\n%s\nscan:\n%s", i, indexProg, scanProg)
		}
	}
}

func scanLoopComponents(p *Prog, tid int64, callIndices []int) []RelatedCallComponent {
	cache := testDependencyCache(len(p.Calls))
	processedCalls := make([]bool, len(p.Calls))
	nonStartCalls := make([]bool, len(p.Calls))
	var components []RelatedCallComponent

	for _, callIndex := range callIndices {
		if nonStartCalls[callIndex] || p.Calls[callIndex].StraceTid != tid {
			continue
		}
		keepCalls, removeCalls := relatedCallsFullThreadScan(p, callIndex, cache, processedCalls)
		filterCalls := len(p.Calls)-cardinality(keepCalls) >= 3
		components = append(components, RelatedCallComponent{
			StartIndex:  callIndex,
			KeepCalls:   trueIndices(keepCalls),
			RemoveCalls: trueIndices(removeCalls),
			FilterCalls: filterCalls,
		})
		if filterCalls {
			for i, remove := range removeCalls {
				if remove {
					processedCalls[i] = true
					nonStartCalls[i] = true
				}
			}
		}
		for i, keep := range keepCalls {
			if keep {
				nonStartCalls[i] = true
			}
		}
	}
	return components
}

func trueIndices(mask []bool) []int {
	var indices []int
	for i, set := range mask {
		if set {
			indices = append(indices, i)
		}
	}
	return indices
}

func BenchmarkRelatedCallComponents(b *testing.B) {
	const numComponents = 500
	p, callIndices := benchmarkDependencyProg(b, numComponents)

	b.Run("scan-loop", func(b *testing.B) {
		for b.Loop() {
			components := scanLoopComponents(p, 1, callIndices)
			if len(components) != numComponents {
				b.Fatalf("got %d components, want %d", len(components), numComponents)
			}
		}
	})

	b.Run("indexed", func(b *testing.B) {
		for b.Loop() {
			components := RelatedCallComponentsForThread(p, 1, callIndices, testDependencyCache(len(p.Calls)))
			if len(components) != numComponents {
				b.Fatalf("got %d components, want %d", len(components), numComponents)
			}
		}
	})
}

func benchmarkDependencyProg(tb testing.TB, numComponents int) (*Prog, []int) {
	tb.Helper()
	var text strings.Builder
	callIndices := make([]int, 0, numComponents*2)
	for i := 0; i < numComponents; i++ {
		fmt.Fprintf(&text, "<1>r%d = mutate5(&(0x%x)='./file-%d\\x00', 0x0)\n", i, 0x7f0000000000+i*0x80, i)
		fmt.Fprintf(&text, "<1>mutate9(&(0x%x)='./file-%d\\x00')\n", 0x7f0000000040+i*0x80, i)
		callIndices = append(callIndices, i*2, i*2+1)
	}
	return deserializeDependencyProg(tb, text.String()), callIndices
}
