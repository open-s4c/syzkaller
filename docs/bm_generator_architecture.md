# Benchmark generator architecture

The benchmark generator is an optional pipeline layered on syzkaller. Normal
fuzzing, program serialization, and C reproducer generation remain the default.

## Boundaries

The pipeline has four stages with serialized syz programs between stages:

1. `syz-trace2syz` parses strace and creates target-specific programs.
2. `syz-extraction` selects dependency-complete call components.
3. `syz-prog-reduce` reduces repeated motifs while preserving their weights.
4. `syz-prog2c -csb` emits independently namespaced CSB benchmark headers.

Trace parsing, selection, and reduction live under `tools/`. The shared `prog`
package only provides program data and generic dependency operations. Linux
helper calls own bounded resources and never reuse process-local addresses from
the traced application.

## C-source integration API

`pkg/csource.sourceDialect` is the only format-policy interface used by the
Google-derived C generator. Its default implementation produces ordinary
syzkaller reproducers. `csbDialect` owns all CSB-specific naming, pointer
relocation, argument rewriting, result accounting, headers, and metadata.

New CSB behavior belongs in `csb_dialect.go`; avoid adding `Options.CSB`
branches to `csource.go`. Every C identifier emitted by a benchmark header must
use `UNIQUE_VAR()` or `UNIQUE_FUNC()` when another generated header can emit the
same identifier in the same translation unit.

## Updating from Google upstream

Rebase the `open-s4c` default branch first, then resolve the narrow shared seams:

- tool targets and their Makefile entries;
- program trace metadata and dependency APIs;
- the `sourceDialect` calls in `pkg/csource`;
- Linux syscall descriptions and bounded executor helpers.

Keep application policy out of these seams. In particular, the generator must
not contain MySQL-specific syscall, path, thread, or flamegraph assumptions.

## Validation

Run the focused packages and the end-to-end pipeline test:

```shell
make generate
make trace2syz extraction progreduce prog2c
go test ./prog ./pkg/csource
go test ./tools/syz-trace2syz/... ./tools/syz-extraction ./tools/syz-prog-reduce ./tools/syz-prog2c
go test ./tools/syz-bmgen-integration -run TestBMGeneratorPipeline -v
```

CSB additionally runs its `bm-generator/test.sh` smoke test and flamegraph
selection/fitting scripts against generated headers.
