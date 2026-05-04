# ePDG LLM Quickstart

This is the minimal path for testing Hector/VulChecker ePDG JSONL as an LLM pipeline input.

## Testcase Layout

Place ePDG files inside the matching PrimeVul testcase directory:

```text
primevul_testcases_output_clean/openexr/CWE-190/ImfTiledMisc.cpp/2a18ed424a854598c2a20b5dd7e782b436a1e753/cse713_vulnerable/
  metadata.json
  project_src/
  epdg/
    function_only.jsonl
    full_file.jsonl
    manifest.json
```

For the first pass, use `epdg/function_only.jsonl`. Whole-file ePDG can be too large for the prompt budget.

## ePDG-Only Run

Use the graph-only `pdg` prompt variant and feed converted ePDG text as `pdg_text` only. Do not include source, AST, or CFG.

```bash
python3 Joern_llm_implement/run_epdg_llm.py \
  --testcase-dir primevul_testcases_output_clean/openexr/CWE-190/ImfTiledMisc.cpp/2a18ed424a854598c2a20b5dd7e782b436a1e753/cse713_vulnerable \
  --epdg primevul_testcases_output_clean/openexr/CWE-190/ImfTiledMisc.cpp/2a18ed424a854598c2a20b5dd7e782b436a1e753/cse713_vulnerable/epdg/function_only.jsonl \
  --output-dir primevul_epdg_openexr_test \
  --variant pdg \
  --max-edges 500 \
  --run-llm
```

## OpenEXR Smoke Test Result

- Testcase: `openexr__CWE-190__ImfTiledMisc_cpp__2a18ed424a85__cse713_vulnerable`
- CVE: `CVE-2021-3475`
- CWE: `CWE-190`
- Scope: `epdg_function_only`
- Variant: `pdg`
- Input: ePDG only, no source/AST/CFG
- Prompt chars: `47057`
- Prompt clipped: `false`
- Prediction: `VULNERABLE`
- Expected: `VULNERABLE`
- Confidence: `0.85`

Output files:

```text
primevul_epdg_openexr_test/
  latest_result.json
  results.jsonl
  openexr__CWE-190__ImfTiledMisc_cpp__2a18ed424a85__cse713_vulnerable__pdg.prompt.txt
```
