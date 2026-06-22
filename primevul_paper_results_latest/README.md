# PrimeVul Paper Results Latest

This folder contains only the latest result artifacts used in the paper.

## Included

- `standard/standard_107_results_1068.jsonl`
  - Full standard Joern-track result set used in the paper.
  - Built from the retained historical 25-case standard set plus the completed 82-case new batch.
- `standard/standard_107_summary.json`
  - Corpus counts and evaluation summaries for the full 107-case standard track.
- `standard/standard_107_breakdowns.json`
  - Different groupings parsed from the full standard joren-track results.
- `standard/standard_107_token_counts.jsonl`
  - Per-prompt input-token counts returned by the evaluated `qwen3.6-plus` service.
  - Includes reconstructed prompt length/hash and an `exact` or `proxy_reconstructed` audit status.
- `standard/standard_107_token_summary.csv`
  - Family- and variant-level average input-token counts used in the paper's prompt-overhead table.
- `standard/standard_107_per_cwe_major.csv`
  - Curated accuracy by CWE for the raw and AST+PDG variants and the graph-containing families.
- `epdg/epdg_19_results.jsonl`
  - Latest retained 19-case auxiliary ePDG result set used in the paper.
- `epdg/epdg_overlap_11_results.jsonl`
  - The 11-case overlapping subset used for direct paired comparison references.
- `epdg/epdg_19_summary.json`
  - Summary statistics for the 19-case ePDG track and the overlapping 11-case subset.

## Visualizations

- `visualizations/`
  - Visualizations provided to arXiv paper submission.

## Intentionally Excluded

- Old snapshots
- Intermediate reruns and logs
- The older 11-row standalone ePDG retained file as a top-level artifact
- Other merged report-ready files that are not the current paper's primary result sources

## Provenance

- Standard track source files:
  - `primevul_report_ready_results/merged_jsonl/final_all_standard_unique_248.jsonl`
  - `primevul_new_batch_results/results.jsonl`
- ePDG track source files:
  - `primevul_report_ready_results/merged_jsonl/final_extend_epdg_19.jsonl`
  - `primevul_report_ready_results/merged_jsonl/final_extend_epdg_11.jsonl`

## Token-count reconstruction

The token-counting script requires the locally reconstructed testcase and
representation artifacts produced by the evaluation pipeline
(`primevul_testcases_output_clean`, `primevul_new_batch_results`, and
`primevul_token_count_reconstruction`). These large intermediate artifacts are not
included in this repository. Given those prerequisites and the API settings
documented in `Joern_llm_implement/README.md`, run
`Joern_llm_implement/count_paper_prompt_tokens.py` to reconstruct each retained
prompt, compare its character count with the historical result, and request tokenizer
usage from `qwen3.6-plus`.

For independent inspection without rerunning the API calls, this repository includes
the resulting per-prompt JSONL records and summary CSV. Of the 1,068 prompts, 918
matched exactly and 150 older prompts are explicitly marked as proxy reconstructions.
The exact-only sensitivity analysis preserves the reported family ordering.
