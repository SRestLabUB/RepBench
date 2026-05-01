# PrimeVul Representation Pilot Plan

## Goal

This document resets the project back to the intended pre-APR evaluation track.

The immediate goal is not automated program repair yet. The immediate goal is to measure how different code representations affect LLM-based vulnerability analysis on PrimeVul, under controlled prompting and prompt-budget constraints.

APR will be added later. For now, this pilot focuses on the stages before repair:

1. testcase selection
2. graph extraction
3. graph-to-text serialization
4. prompt construction
5. LLM inference
6. representation comparison

## Scope Of This Phase

This phase is a representation study, not a repair study.

We currently evaluate:

- vulnerability classification accuracy
- confidence
- prompt size / token overhead
- practical prompt fit under budget

We are not yet evaluating:

- patch generation
- patch compilation
- CodeBLEU
- Exact Match
- regression testing

## Main Experimental Question

Which program representation gives the best tradeoff between useful vulnerability evidence and prompt cost for PrimeVul-based LLM analysis?

## Secondary Experimental Question

How much does graph extraction scope affect prompt usability and downstream prediction quality?

This second question is useful, but it is not the main representation ablation.

## Datasets

This pilot uses PrimeVul only.

Juliet is temporarily excluded from this phase.

Supported CWEs for the current pipeline:

- `CWE-122`
- `CWE-190`
- `CWE-191`
- `CWE-415`
- `CWE-416`

Current practical focus for PrimeVul pilot:

- `CWE-122`
- `CWE-190`
- `CWE-415`
- `CWE-416`

## Ground Rules

### Analysis unit

The analysis target is the vulnerable function in PrimeVul.

We do not use repository-wide graphs as the default analysis unit.

### Default Joern scope

The main experiment uses:

- `full_file_target_method`

Meaning:

1. import the checked-out full source file into Joern
2. run Joern dataflow
3. export only the target function graph with `cpg.method.name("<function_name>")`

This keeps parse correctness from the full file while keeping graph size focused on the target function.

### Secondary scope kept for comparison

We also keep:

- `full_file_all_methods`

Meaning:

1. import the checked-out full source file into Joern
2. run Joern dataflow
3. export all methods in that file

This is not the default mainline input. It is retained as a scope-study condition to quantify prompt inflation, truncation risk, and any accuracy changes.

### Scope explicitly not preferred

We are not using function-only snippet import as the mainline configuration.

Reason:

- it is less stable as a default preprocessing assumption
- full-file import is closer to real project context
- Joern parse behavior is safer when the full file is available

## Why Scope Study Still Matters

The scope comparison remains useful because it answers a different question than representation ablation.

Representation ablation asks:

- AST vs CFG vs PDG vs hybrids

Scope study asks:

- target-function graph vs all-method graph in the containing file

The current shapelib CWE-415 comparison already showed:

- `full_file_target_method` stays compact and preserves relevant evidence
- `full_file_all_methods` can massively increase prompt size and cause evidence truncation

This means scope must be controlled before representation comparisons are interpreted.

## Representation Variants

We want to separate the value of raw code from the value of graph representations.

Therefore, not every representation variant should include raw source code.

### Final pilot variants

| Variant | Source | AST | CFG | PDG | Type |
|---|---:|---:|---:|---:|---|
| `raw` | yes | no | no | no | source-only baseline |
| `ast` | no | yes | no | no | graph-only |
| `cfg` | no | no | yes | no | graph-only |
| `pdg` | no | no | no | yes | graph-only |
| `ast_cfg` | no | yes | yes | no | graph-only hybrid |
| `ast_pdg` | no | yes | no | yes | graph-only hybrid |
| `cfg_pdg` | no | no | yes | yes | graph-only hybrid |
| `full` | yes | yes | yes | yes | source + full graph |
| `ast_plus_source` | yes | yes | no | no | source + graph |
| `pdg_plus_source` | yes | no | no | yes | source + graph |

## Rationale For These Variants

These variants let us answer three different questions.

### 1. Can graph text stand on its own?

This is tested by:

- `ast`
- `cfg`
- `pdg`
- `ast_cfg`
- `ast_pdg`
- `cfg_pdg`

### 2. How strong is raw code alone?

This is tested by:

- `raw`

### 3. Is graph better used as a replacement or as augmentation?

This is tested by:

- `ast_plus_source`
- `pdg_plus_source`
- `full`

## Prompting Design

Prompt templates must match the actual input type.

We should not tell the model to inspect source code if the variant only contains graph text.

### Template families

#### 1. Source-only template

Used for:

- `raw`

Characteristics:

- contains source code section
- contains no graph section
- frames the task as direct code review

#### 2. Graph-only template

Used for:

- `ast`
- `cfg`
- `pdg`
- `ast_cfg`
- `ast_pdg`
- `cfg_pdg`

Characteristics:

- contains no raw source section
- contains only the selected graph sections
- explicitly states that code snippets are embedded inside graph node labels
- frames the task as graph-based program analysis

#### 3. Source + graph template

Used for:

- `full`
- `ast_plus_source`
- `pdg_plus_source`

Characteristics:

- contains source code section
- contains selected graph sections
- frames the task as code review assisted by structural program representations

## Prompt Budget Policy

The prompt budget will be increased from `12000` to approximately `20000` characters for this pilot.

Reason:

- `12000` was enough to expose truncation issues in all-method graphs
- `20000` is still conservative relative to the model's available context
- this gives more room to compare hybrid variants without aggressively clipping them
- we still avoid pushing prompt size too high in order to reduce account-risk / rate-based detection concerns

Important clarification:

- prompt size is not artificially padded to fill the budget
- if a prompt naturally renders at 5k, 8k, or 14k characters, it should remain that size
- the budget is a ceiling, not a target

## Graph Ordering Strategy For Long Prompts

For long prompts, graph order matters because of lost-in-the-middle behavior.

We will prefer CWE-aware ordering.

### Recommended order by CWE family

- `CWE-415`, `CWE-416`: prioritize `PDG`, then `CFG`, then `AST`
- `CWE-190`, `CWE-191`: prioritize `CFG`, then `AST`, then `PDG`
- `CWE-121`, `CWE-122`: prioritize `CFG`, then `PDG`, then `AST`

### Reasoning

- memory lifecycle issues benefit most from dependency evidence
- arithmetic issues benefit strongly from flow and operation order
- overflow-style bugs often need branch/path context plus data movement context

For mixed prompts, the source code remains near the front, followed by the most relevant graph type for that CWE.

## ePDG Status

ePDG is not blocked conceptually, but it is not part of the first pilot implementation.

Current expectation from teammate work:

- ePDG is generated at repo scale
- ePDG nodes include line information
- target-function-relevant ePDG nodes should therefore be filterable by line range

Current working assumption:

- if ePDG remains too large after filtering/serialization, it should be evaluated as a standalone representation
- ePDG should not be forced into combined prompts with AST/CFG/PDG if that makes prompt cost unreasonable

So for now:

- ePDG is a future extension branch
- main pilot proceeds with Joern AST/CFG/PDG variants first

## Pilot Size

We will start with a small PrimeVul-only pilot.

Target size:

- 5 to 10 vulnerable samples total

Current preferred pilot layout:

- about 8 vulnerable samples total

Suggested distribution:

- `CWE-415`: 3 samples
- `CWE-190`: 2 samples
- `CWE-416`: 2 samples
- `CWE-122`: 1 sample

This is large enough to validate the pipeline and observe cross-CWE behavior, while still being cheap enough to run safely.

## Main Metrics For This Phase

APR is deferred, so we prioritize metrics that are immediately available.

### Primary metric

- vulnerability classification accuracy

Reason:

- it is the easiest reliable metric to compute with the current pipeline
- it allows fast representation comparison before repair output exists

### Secondary metrics

- confidence
- prompt character count
- accuracy per prompt size
- representation efficiency

### Representation efficiency

For this pilot, representation efficiency is approximated as:

- `accuracy / prompt_chars`

This is not the final paper metric for APR, but it is a useful pre-APR proxy for cost effectiveness.

### Future extension metrics

Later, after we add patch generation, we will extend evaluation with:

- localization accuracy
- patch compilation success rate, where applicable
- CodeBLEU
- Exact Match
- patch correctness / token count

## Experimental Structure

### Main study

Use `full_file_target_method` only.

For each selected vulnerable PrimeVul testcase:

1. load metadata
2. load checked-out vulnerable file
3. generate AST/CFG/PDG for target function only
4. serialize graphs to text
5. construct prompts for all representation variants
6. call LLM
7. store one result row per variant

### Secondary scope study

Use a smaller subset of the same pilot samples.

Compare:

- `full_file_target_method`
- `full_file_all_methods`

Purpose:

- quantify prompt inflation
- observe truncation behavior
- document whether all-method scope changes prediction quality

This scope study is evidence for methodology choices, not the main ablation itself.

## Expected Outputs

### Per-call result records

Store one JSONL row per testcase x representation variant.

Suggested fields:

- testcase id
- project
- CWE
- variant
- scope
- expected label
- predicted label
- confidence
- prompt chars
- reasoning JSON
- timestamp

### Aggregated summary

Compute summary tables over:

- variant accuracy
- average confidence by variant
- average prompt size by variant
- efficiency proxy by variant
- per-CWE breakdown

## Why JSONL

JSONL is preferred for this pilot because:

- it supports append-only streaming writes
- partial results survive interruption
- it is easy to parse later for tables and plotting
- it works well with hidden-identity / low-friction batch operation needs

## Implementation Order

The agreed build order for the next stage is:

1. update prompt generator to support variant-specific templates and larger prompt budget
2. build a PrimeVul pilot experiment runner
3. generate target-function AST/CFG/PDG for selected pilot testcases
4. run the 5 to 10 sample representation pilot
5. compute summary statistics
6. run smaller all-method scope comparison on a subset

## Explicit Non-Goals For This Documented Phase

This phase does not yet attempt to answer:

- which representation yields the best patch
- whether the generated patch compiles
- whether the generated patch matches developer fixes semantically

Those questions belong to the later APR phase.

## APR Note For Later

APR is currently expected to have two possible operating styles.

### Option A

One pass for explanation / vulnerability analysis, then feed that result into a later patch-generation step.

### Option B

A single session produces both explanation and patch together.

We are intentionally postponing that decision until after the representation pilot stabilizes.

## Current Interpretation Of Existing Results

The existing shapelib comparison should be interpreted as a scope sanity check, not as the main representation result.

What it already tells us:

- target-function graph export is viable and compact
- all-method export can create prompt-size problems
- prompt truncation can hide vulnerability evidence

What it does not yet tell us:

- whether AST beats CFG
- whether PDG beats raw code
- whether graph-only input is competitive with source-only input
- whether hybrid inputs are worth their token cost

Those are the questions this pilot is meant to answer.
