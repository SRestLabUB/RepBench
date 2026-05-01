#!/usr/bin/env python3
"""Convert Hector/VulChecker ePDG JSONL into compact LLM text."""

import json
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Tuple


LINK_ABBREV = {
    'control_flow': 'CF',
    'def_use': 'DU',
}


def load_epdg_jsonl(path: Path) -> List[dict]:
    records = []
    for line_no, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid JSONL at {path}:{line_no}: {exc}') from exc
    return records


def _tag_text(tags: Iterable[str]) -> str:
    tags = [str(tag) for tag in tags or []]
    return ','.join(tags) if tags else '-'


def _static_text(value: object) -> str:
    if value in (None, 'none', ''):
        return ''
    return f' static={value}'


def _node_label(node: dict) -> str:
    if not node:
        return 'unknown'
    line = node.get('line_number', '?')
    operation = node.get('operation', '?')
    tags = _tag_text(node.get('tag', []))
    dtype = node.get('node_dtype') or node.get('dtype') or '?'
    static_value = _static_text(node.get('static_value'))
    return f'L{line} {operation} tag={tags} dtype={dtype}{static_value}'


def convert_epdg_records_to_text(records: List[dict], max_edges: int = 1200) -> Tuple[str, dict]:
    """Return compact text plus simple stats for one merged ePDG JSONL file."""
    nodes = {record.get('id'): record for record in records if record.get('id') is not None}
    link_counts = Counter(record.get('link_type', 'unknown') for record in records)
    tag_counts = Counter(tag for record in records for tag in (record.get('tag') or []))
    operation_counts = Counter(record.get('operation', 'unknown') for record in records)
    line_numbers = [record.get('line_number') for record in records if isinstance(record.get('line_number'), int)]

    root_records = [record for record in records if 'root_cause' in (record.get('tag') or [])]
    manifestation_records = [record for record in records if 'manifestation' in (record.get('tag') or [])]
    other_records = [record for record in records if record not in root_records and record not in manifestation_records]

    # Keep vulnerability-tagged edges first, then data dependencies, then the remaining control-flow context.
    def sort_key(record: dict) -> tuple:
        link_rank = 0 if record.get('link_type') == 'def_use' else 1
        return (link_rank, int(record.get('line_number') or 0), int(record.get('id') or 0), int(record.get('target_id') or 0))

    ordered = sorted(root_records, key=sort_key)
    seen = {(record.get('id'), record.get('target_id'), record.get('link_type')) for record in ordered}
    for group in (manifestation_records, [r for r in other_records if r.get('link_type') == 'def_use'], other_records):
        for record in sorted(group, key=sort_key):
            key = (record.get('id'), record.get('target_id'), record.get('link_type'))
            if key in seen:
                continue
            ordered.append(record)
            seen.add(key)
            if len(ordered) >= max_edges:
                break
        if len(ordered) >= max_edges:
            break

    lines = [
        'ePDG JSONL compact representation',
        f'total_edges={len(records)} kept_edges={len(ordered)}',
        f'line_range={min(line_numbers) if line_numbers else "?"}-{max(line_numbers) if line_numbers else "?"}',
        f'link_counts={dict(link_counts)}',
        f'tag_counts={dict(tag_counts)}',
        f'top_operations={dict(operation_counts.most_common(12))}',
        '',
        'Format: edge_id: source_node --LINK:dtype--> target_node',
    ]

    for index, record in enumerate(ordered, 1):
        link = LINK_ABBREV.get(record.get('link_type'), record.get('link_type', '?'))
        link_dtype = record.get('link_dtype') or '?'
        source = _node_label(record)
        target = _node_label(nodes.get(record.get('target_id')))
        lines.append(f'{index:04d}: {source} --{link}:{link_dtype}--> {target}')

    stats = {
        'total_edges': len(records),
        'kept_edges': len(ordered),
        'line_min': min(line_numbers) if line_numbers else None,
        'line_max': max(line_numbers) if line_numbers else None,
        'link_counts': dict(link_counts),
        'tag_counts': dict(tag_counts),
        'operation_counts': dict(operation_counts),
        'text_chars': len('\n'.join(lines)),
    }
    return '\n'.join(lines), stats


def convert_epdg_jsonl_to_text(path: Path, max_edges: int = 1200) -> Tuple[str, dict]:
    return convert_epdg_records_to_text(load_epdg_jsonl(path), max_edges=max_edges)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description='Convert ePDG JSONL to compact LLM text')
    parser.add_argument('epdg_jsonl', type=Path)
    parser.add_argument('--max-edges', type=int, default=1200)
    args = parser.parse_args()

    text, stats = convert_epdg_jsonl_to_text(args.epdg_jsonl, max_edges=args.max_edges)
    print(text)
    print('\n--- stats ---')
    print(json.dumps(stats, indent=2))


if __name__ == '__main__':
    main()
