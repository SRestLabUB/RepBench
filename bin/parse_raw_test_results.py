#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Aggregate test-case results from a JSONL file.

Each line in the input is one JSON object describing a test-case result
(fields like `variant`, `cwe`, `success`, `prediction`, `expected`, ...).

For the whole dataset and for any number of (possibly multi-level) group-bys
it computes:

  success_true / success_false   counts of success==true vs success==false,
                                 EXCLUDING rows whose prediction is UNKNOWN
  unknown_count                  rows with an UNKNOWN prediction (tracked,
                                 but kept out of the success true/false split)
  effective_accuracy             (prediction == expected) over ALL rows,
                                 including UNKNOWN predictions in the denominator
  curated_accuracy               (prediction == expected) over only rows that
                                 produced a VALID prediction (SAFE / VULNERABLE)

Output is JSON in tidy "long" format (one object per group), which loads
directly into pandas / plotting libraries.

Usage:
    ./aggregate_results.py results.jsonl                 # -> stdout
    ./aggregate_results.py results.jsonl -o agg.json
    ./aggregate_results.py results.jsonl \
        --group-by cwe --group-by cwe,variant --group-by cwe,prompt_family
"""

import argparse
import json
import sys
from collections import defaultdict
from typing import Any, Dict, List, Sequence

UNKNOWN_PREDICTION = "UNKNOWN"

VARIANT_TO_PROMPT_FAMILY = {
    # Source-only
    "raw": "source_only",
    # Graph-only
    "ast": "graph_only",
    "cfg": "graph_only",
    "pdg": "graph_only",
    "ast_cfg": "graph_only",
    "ast_pdg": "graph_only",
    "cfg_pdg": "graph_only",
    # Source-plus-graph
    "full": "source_plus_graph",
    "ast_plus_source": "source_plus_graph",
    "pdg_plus_source": "source_plus_graph",
}

# Group-by specs. Each entry is a list of fields. A single-element list is a
# flat group-by; multi-element lists are nested ("by cwe by variant", etc.).
# Add any field that exists on the record (or any derived field) here.
DEFAULT_GROUP_BYS: List[List[str]] = [
    ["variant"],
    ["cwe"],
    ["prompt_family"],
    ["cwe", "variant"],
    ["cwe", "prompt_family"],
]


def derive_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of `record` with computed fields added."""
    out = dict(record)
    out["prompt_family"] = VARIANT_TO_PROMPT_FAMILY.get(
        record.get("variant"), "unknown_family"
    )
    return out


def _ratio(num: int, den: int):
    """num/den, or None when there is nothing to divide by (avoids /0 in plots)."""
    return (num / den) if den else None


def compute_metrics(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the metric bundle for one collection of records."""
    total_len = len(records)
    cur_total_len = len([r for r in records if r.get('prediction') != UNKNOWN_PREDICTION])
    correct = [r for r in records if r.get('prediction') == r.get('expected')]
    confidences = [float(r.get('confidence') or 0.0) for r in records]
    prompt_chars = [int(r.get('prompt_chars') or 0) for r in records]
    clipped_count = sum(1 for r in records if r.get('prompt_clipped'))
    total_seconds = [float(r['total_seconds']) for r in records if r.get('total_seconds') is not None]
    ttft_seconds = [float(r['ttft_seconds']) for r in records if r.get('ttft_seconds') is not None]

    avg_chars = sum(prompt_chars) / len(prompt_chars) if prompt_chars else 0.0
    cur_accuracy = len(correct) / cur_total_len if records else 0.0
    return {
        'count': total_len,
        'curated_count': cur_total_len,
        'correct_count': len(correct),
        'unknown_count': total_len - cur_total_len,
        'effective_accuracy': len(correct) / total_len,
        'curated_accuracy': cur_accuracy,
        'avg_confidence': sum(confidences) / len(confidences) if confidences else 0.0,
        'avg_total_seconds': sum(total_seconds) / len(total_seconds) if total_seconds else None,
        'avg_ttft_seconds': sum(ttft_seconds) / len(ttft_seconds) if ttft_seconds else None,
        'avg_prompt_chars': avg_chars,
        'clipped_count': clipped_count,
        'curated_accuracy_per_1k_chars': cur_accuracy / (avg_chars / 1000) if avg_chars else 0.0,
    }


def aggregate_by(
    records: Sequence[Dict[str, Any]], fields: Sequence[str]
) -> Dict[str, Any]:
    """Group `records` by `fields` and return one tidy row of metrics per group."""
    groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        key = tuple(r.get(f) for f in fields)
        groups[key].append(r)

    rows: List[Dict[str, Any]] = []
    for key, recs in groups.items():
        row = {f: v for f, v in zip(fields, key)}
        row.update(compute_metrics(recs))
        rows.append(row)

    rows.sort(key=lambda d: tuple(str(d[f]) for f in fields))
    return rows


def aggregate_all(
    records: Sequence[Dict[str, Any]], group_bys: Sequence[Sequence[str]]
) -> Dict[str, Any]:
    """Build the full result object: overall metrics + every requested grouping."""
    result: Dict[str, Any] = {
        "overall": compute_metrics(records),
        "groupings": {},
    }
    for fields in group_bys:
        result["groupings"]["__".join(fields)] = aggregate_by(records, fields)
    return result


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"warning: skipping malformed line {lineno}: {exc}",
                      file=sys.stderr)
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate JSONL test-case results into plot-ready JSON."
    )
    parser.add_argument("input", help="Path to the JSONL file.")
    parser.add_argument("-o", "--output",
                        help="Write JSON here (default: stdout).")
    parser.add_argument(
        "--group-by", action="append", metavar="FIELDS",
        help="Comma-separated fields, e.g. 'cwe,variant'. Repeatable. "
             "If given at least once, replaces the built-in default set.",
    )
    parser.add_argument("--indent", type=int, default=2)
    args = parser.parse_args(argv)

    records = [derive_fields(r) for r in read_jsonl(args.input)]

    if args.group_by:
        group_bys = [g.split(",") for g in args.group_by]
    else:
        group_bys = DEFAULT_GROUP_BYS

    result = aggregate_all(records, group_bys)
    payload = json.dumps(result, indent=args.indent)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
