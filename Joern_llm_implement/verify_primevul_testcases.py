#!/usr/bin/env python3
"""Verify extracted PrimeVul testcase quality before LLM experiments.

The extractor can produce testcases whose CWE label or selected function does not
match the actual CVE semantics. This script applies conservative, explainable
checks so the representation pilot can run on healthier samples.
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


from project_paths import PROJECT_ROOT


ROOT = PROJECT_ROOT
DEFAULT_TESTCASE_ROOT = ROOT / 'primevul_testcases_output_clean'
DEFAULT_PRIMEVUL_DATA = ROOT / 'Joern_llm_implement' / 'primevul_data'
DEFAULT_OUTPUT = ROOT / 'Joern_llm_implement' / 'primevul_testcase_verification.jsonl'
DEFAULT_RECOMMENDED = ROOT / 'Joern_llm_implement' / 'primevul_verified_recommended.json'

SUPPORTED_CWES = {'CWE-121', 'CWE-122', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416'}

DESC_KEYWORDS = {
    'CWE-121': ['stack-based buffer overflow', 'stack buffer overflow', 'buffer overflow'],
    'CWE-122': ['heap-based buffer overflow', 'heap buffer overflow', 'buffer overflow', 'out-of-bound write', 'out-of-bounds write'],
    'CWE-190': ['integer overflow', 'overflow'],
    'CWE-191': ['integer underflow', 'underflow'],
    'CWE-415': ['double free', 'double-free'],
    'CWE-416': ['use-after-free', 'use after free', 'after free'],
}

SOURCE_PATTERNS = {
    'CWE-121': [r'\b(strcpy|strncpy|strcat|sprintf|vsprintf|memcpy|memmove|alloca)\b', r'\[[^\]]+\]'],
    'CWE-122': [r'\b(malloc|calloc|realloc|new|memcpy|memmove|strcpy|strncpy|sprintf|vsprintf)\b', r'\[[^\]]+\]'],
    'CWE-190': [
        r'\b(size|len|length|count|width|height|offset|bytes|capacity|num|number)\b[^;\n]*(?:\+|\*|<<)',
        r'[A-Za-z_][\w\.\]\)]*\s*(?:\+|\*|<<)\s*[A-Za-z_0-9(]',
    ],
    'CWE-191': [
        r'\b(size|len|length|count|offset|index)\b[^;\n]*-',
        r'(?<!-)>?\b[A-Za-z_][\w\.\]\)]*\s*-\s*[A-Za-z_0-9(]',
    ],
    'CWE-415': [r'\b(free|delete|cfree|g_free|av_free|OPENSSL_free)\b'],
    'CWE-416': [r'\b(free|delete|cfree|g_free|av_free|OPENSSL_free)\b', r'->|\.'],
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8', errors='replace'))


def load_primevul_records(data_dir: Path) -> List[dict]:
    records = []
    for name in ['primevul_test_paired.jsonl', 'primevul_train_paired.jsonl', 'primevul_valid_paired.jsonl']:
        path = data_dir / name
        if not path.exists():
            continue
        with path.open(encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    record['_split'] = name.replace('primevul_', '').replace('_paired.jsonl', '')
                    records.append(record)
    return records


def load_file_info(data_dir: Path) -> Dict[str, dict]:
    path = data_dir / 'file_info.json'
    return read_json(path) if path.exists() else {}


def extract_function_name(func: str) -> Optional[str]:
    match = re.search(r'([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{', func)
    if match:
        return match.group(1)
    match = re.search(r'([A-Za-z_]\w*)\s*\(', func)
    return match.group(1) if match else None


def build_record_index(records: Iterable[dict], file_info: Dict[str, dict]) -> Dict[Tuple, List[dict]]:
    index: Dict[Tuple, List[dict]] = defaultdict(list)
    for record in records:
        func_hash = str(record.get('func_hash'))
        info = file_info.get(func_hash, {})
        enriched = dict(record)
        enriched['_function_name'] = extract_function_name(record.get('func', ''))
        enriched['_project_file_path'] = info.get('project_file_path')
        enriched['_start_line'] = info.get('start_line')
        enriched['_end_line'] = info.get('end_line')
        key = (
            record.get('project'),
            record.get('cve'),
            record.get('commit_id'),
            record.get('target'),
            info.get('project_file_path'),
            info.get('start_line'),
            info.get('end_line'),
        )
        index[key].append(enriched)
    return index


def function_marker(label_dir: Path) -> Optional[str]:
    candidates = [p.name for p in label_dir.iterdir() if p.is_file() and p.name != 'metadata.json']
    return candidates[0] if len(candidates) == 1 else None


def function_source(label_dir: Path, metadata: dict) -> str:
    marker = function_marker(label_dir)
    if marker:
        marker_path = label_dir / marker
        if marker_path.exists():
            lines = marker_path.read_text(encoding='utf-8', errors='replace').splitlines()
            start = int(metadata.get('function_start') or 1)
            end = int(metadata.get('function_end') or len(lines))
            if 1 <= start <= end <= len(lines):
                return '\n'.join(lines[start - 1:end])
            return marker_path.read_text(encoding='utf-8', errors='replace')
    full_source = label_dir / 'project_src' / metadata.get('project_file_path', '')
    if not full_source.exists():
        return ''
    lines = full_source.read_text(encoding='utf-8', errors='replace').splitlines()
    start = int(metadata.get('function_start') or 1)
    end = int(metadata.get('function_end') or len(lines))
    return '\n'.join(lines[max(0, start - 1):end])


def full_source_chars(label_dir: Path, metadata: dict) -> int:
    full_source = label_dir / 'project_src' / metadata.get('project_file_path', '')
    if full_source.exists():
        return len(full_source.read_text(encoding='utf-8', errors='replace'))
    marker = function_marker(label_dir)
    marker_path = label_dir / marker if marker else None
    if marker_path and marker_path.exists():
        return len(marker_path.read_text(encoding='utf-8', errors='replace'))
    return 0


def keyword_match(text: str, keywords: List[str]) -> bool:
    lower = text.lower()
    return any(keyword in lower for keyword in keywords)


def code_body_without_comments(source: str) -> str:
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    source = re.sub(r'//.*', '', source)
    brace = source.find('{')
    if brace >= 0:
        source = source[brace + 1:]
    return source


def source_match(cwe: str, source: str) -> bool:
    source = code_body_without_comments(source)
    patterns = SOURCE_PATTERNS.get(cwe, [])
    return any(re.search(pattern, source, flags=re.IGNORECASE) for pattern in patterns)


def verify_one(metadata_path: Path, testcase_root: Path, record_index: Dict[Tuple, List[dict]]) -> dict:
    metadata = read_json(metadata_path)
    label_dir = metadata_path.parent
    rel = metadata_path.relative_to(testcase_root).parts
    project, cwe_dir, source_name, commit_id, label = rel[:5]
    cwe = metadata.get('cwe')
    marker = function_marker(label_dir)
    source = function_source(label_dir, metadata)
    source_chars = full_source_chars(label_dir, metadata)

    key = (
        metadata.get('project') or project,
        metadata.get('cve'),
        metadata.get('commit_id'),
        metadata.get('target'),
        metadata.get('project_file_path'),
        metadata.get('function_start'),
        metadata.get('function_end'),
    )
    matched_records = record_index.get(key, [])

    desc_ok = keyword_match(metadata.get('cve_desc', ''), DESC_KEYWORDS.get(cwe, []))
    source_ok = source_match(cwe, source)
    record_ok = len(matched_records) > 0
    function_ok = True
    original_cwes: List[str] = []

    if matched_records:
        original_cwes = sorted({c for record in matched_records for c in record.get('cwe', [])})
        names = {record.get('_function_name') for record in matched_records if record.get('_function_name')}
        if marker and names:
            function_ok = marker in names

    issues = []
    if cwe not in SUPPORTED_CWES:
        issues.append('unsupported_cwe')
    if not desc_ok:
        issues.append('cve_description_not_matching_cwe')
    if not source_ok:
        issues.append('target_function_lacks_cwe_relevant_operations')
    if not record_ok:
        issues.append('metadata_not_matched_to_primevul_record')
    if not function_ok:
        issues.append('function_marker_mismatch')
    if original_cwes and cwe not in original_cwes:
        issues.append('metadata_cwe_differs_from_primevul_record')

    score = 0
    score += 2 if desc_ok else 0
    score += 2 if source_ok else 0
    score += 2 if record_ok else 0
    score += 1 if function_ok else 0
    score += 1 if original_cwes and cwe in original_cwes else 0

    return {
        'testcase_id': '__'.join([project, cwe_dir, source_name.replace('.', '_'), commit_id[:12], label]),
        'project': project,
        'cwe': cwe,
        'cve': metadata.get('cve'),
        'source_name': source_name,
        'commit_id': commit_id,
        'label': label,
        'target': metadata.get('target'),
        'function_name': marker,
        'function_start': metadata.get('function_start'),
        'function_end': metadata.get('function_end'),
        'full_source_chars': source_chars,
        'metadata_path': str(metadata_path),
        'primevul_record_count': len(matched_records),
        'primevul_cwes': original_cwes,
        'desc_cwe_match': desc_ok,
        'source_cwe_match': source_ok,
        'function_name_match': function_ok,
        'score': score,
        'healthy': score >= 7 and not issues,
        'issues': issues,
        'cve_desc': metadata.get('cve_desc', ''),
    }


def select_recommended(records: List[dict], per_cwe: int) -> Dict[str, List[dict]]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for record in records:
        if record['healthy'] and record['target'] == 1:
            grouped[record['cwe']].append(record)

    recommended = {}
    for cwe, items in sorted(grouped.items()):
        items = sorted(items, key=lambda r: (r.get('full_source_chars') or 0, r['project'], r['cve'], r['source_name']))
        recommended[cwe] = items[:per_cwe]
    return recommended


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify extracted PrimeVul testcases before LLM experiments.')
    parser.add_argument('--testcase-root', type=Path, default=DEFAULT_TESTCASE_ROOT)
    parser.add_argument('--primevul-data', type=Path, default=DEFAULT_PRIMEVUL_DATA)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--recommended-output', type=Path, default=DEFAULT_RECOMMENDED)
    parser.add_argument('--per-cwe', type=int, default=5)
    args = parser.parse_args()

    records = load_primevul_records(args.primevul_data)
    file_info = load_file_info(args.primevul_data)
    record_index = build_record_index(records, file_info)

    verified = []
    for metadata_path in sorted(args.testcase_root.rglob('metadata.json')):
        metadata = read_json(metadata_path)
        if metadata.get('target') != 1:
            continue
        verified.append(verify_one(metadata_path, args.testcase_root, record_index))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8') as f:
        for record in verified:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')

    recommended = select_recommended(verified, args.per_cwe)
    args.recommended_output.write_text(json.dumps(recommended, ensure_ascii=False, indent=2), encoding='utf-8')

    issue_counts = Counter(issue for record in verified for issue in record['issues'])
    healthy_by_cwe = Counter(record['cwe'] for record in verified if record['healthy'])
    total_by_cwe = Counter(record['cwe'] for record in verified)

    print(f'Verified vulnerable testcases: {len(verified)}')
    print(f'Healthy testcases: {sum(1 for record in verified if record["healthy"])}')
    print('Healthy by CWE:')
    for cwe in sorted(total_by_cwe):
        print(f'  {cwe}: {healthy_by_cwe[cwe]}/{total_by_cwe[cwe]}')
    print('Top issues:')
    for issue, count in issue_counts.most_common():
        print(f'  {issue}: {count}')
    print(f'Wrote detail JSONL: {args.output}')
    print(f'Wrote recommended samples: {args.recommended_output}')


if __name__ == '__main__':
    main()
