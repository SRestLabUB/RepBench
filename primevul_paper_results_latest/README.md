# PrimeVul Paper Results Latest

This folder contains only the latest result artifacts used in the paper.

## Included

- `standard/standard_107_results_1068.jsonl`
  - Full standard Joern-track result set used in the paper.
  - Built from the retained historical 25-case standard set plus the completed 82-case new batch.
- `standard/standard_107_summary.json`
  - Corpus counts and evaluation summaries for the full 107-case standard track.
- `epdg/epdg_19_results.jsonl`
  - Latest retained 19-case auxiliary ePDG result set used in the paper.
- `epdg/epdg_overlap_11_results.jsonl`
  - The 11-case overlapping subset used for direct paired comparison references.
- `epdg/epdg_19_summary.json`
  - Summary statistics for the 19-case ePDG track and the overlapping 11-case subset.

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
