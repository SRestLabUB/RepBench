#!/usr/bin/env python3
"""Build the Joern-only manifest for PrimeVul testcases not yet in final results."""

import argparse
import json
from pathlib import Path
from typing import Iterable


ROOT = Path('/home/tangjiaoshou/CSE713')
DEFAULT_TESTCASE_ROOT = ROOT / 'primevul_testcases_output_clean'
DEFAULT_OUTPUT_DIR = ROOT / 'primevul_new_batch_results'
DEFAULT_EXISTING_RESULT_FILES = [
    ROOT / 'primevul_extended_usable_results' / 'standard' / 'results_standard_all_updated_150.jsonl',
    ROOT / 'primevul_extended_usable_results' / 'epdg_updated' / 'results_epdg_updated_11.jsonl',
    ROOT / 'primevul_report_ready_results' / 'merged_jsonl' / 'final_live4_unique_38.jsonl',
    ROOT / 'primevul_report_ready_results' / 'merged_jsonl' / 'final_live_verified8_unique_60.jsonl',
]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(errors='replace'))


def testcase_id(parts: Iterable[str]) -> str:
    safe = []
    for part in parts:
        safe.append(''.join(ch if ch.isalnum() or ch in {'-', '_'} else '_' for ch in part))
    return '__'.join(safe)


def function_name_from_label_dir(label_dir: Path) -> str | None:
    candidates = [p.name for p in label_dir.iterdir() if p.is_file() and p.name != 'metadata.json']
    return candidates[0] if len(candidates) == 1 else None


def load_existing_ids(paths: list[Path]) -> set[str]:
    ids: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(errors='replace').splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get('testcase_id'):
                ids.add(row['testcase_id'])
    return ids


def discover(testcase_root: Path, existing_ids: set[str]) -> tuple[list[dict], list[dict], list[dict]]:
    all_cases: list[dict] = []
    new_cases: list[dict] = []
    skipped: list[dict] = []

    for metadata_path in sorted(testcase_root.rglob('metadata.json')):
        label_dir = metadata_path.parent
        rel = metadata_path.relative_to(testcase_root).parts
        if len(rel) < 6:
            skipped.append({'metadata_path': str(metadata_path), 'healthy': False, 'skip_reason': 'malformed_path'})
            continue

        project, cwe_dir, source_name, commit_id, label = rel[:5]
        md = read_json(metadata_path)
        tc_id = testcase_id([project, cwe_dir, source_name, commit_id[:12], label])
        full_source = label_dir / 'project_src' / md.get('project_file_path', '')
        function_name = function_name_from_label_dir(label_dir)
        healthy = bool(full_source.exists() and function_name)
        record = {
            'testcase_id': tc_id,
            'project': project,
            'cwe': md.get('cwe', cwe_dir),
            'source_name': source_name,
            'commit_id': md.get('commit_id', commit_id),
            'label': label,
            'expected': 'VULNERABLE' if int(md.get('target', -1)) == 1 else 'SAFE',
            'target': int(md.get('target', -1)),
            'metadata_path': str(metadata_path),
            'label_dir': str(label_dir),
            'function_name': function_name,
            'project_file_path': md.get('project_file_path'),
            'full_source_path': str(full_source),
            'healthy': healthy,
            'already_in_results': tc_id in existing_ids,
            'skip_reason': None if healthy else 'missing_source_or_function_marker',
        }
        all_cases.append(record)
        if tc_id in existing_ids:
            continue
        if healthy:
            new_cases.append(record)
        else:
            skipped.append(record)

    return all_cases, new_cases, skipped


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--testcase-root', type=Path, default=DEFAULT_TESTCASE_ROOT)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    existing_ids = load_existing_ids(DEFAULT_EXISTING_RESULT_FILES)
    all_cases, new_cases, skipped = discover(args.testcase_root, existing_ids)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        'testcase_root': str(args.testcase_root),
        'existing_result_files': [str(path) for path in DEFAULT_EXISTING_RESULT_FILES],
        'counts': {
            'total_testcases': len(all_cases),
            'already_in_results': sum(1 for row in all_cases if row['already_in_results']),
            'new_healthy': len(new_cases),
            'new_skipped': len(skipped),
            'estimated_joern_rows': len(new_cases) * 10,
        },
        'new_testcases': new_cases,
        'skipped_testcases': skipped,
    }

    (args.output_dir / 'primevul_new_testcases_manifest.json').write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8'
    )
    write_jsonl(args.output_dir / 'verified_new_testcases.jsonl', new_cases)
    write_jsonl(args.output_dir / 'verified_new_testcases_smoke1.jsonl', new_cases[:1])

    print(json.dumps(manifest['counts'], indent=2))
    print(f'Manifest: {args.output_dir / "primevul_new_testcases_manifest.json"}')
    print(f'Verified IDs: {args.output_dir / "verified_new_testcases.jsonl"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
