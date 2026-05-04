#!/usr/bin/env python3
"""Convert Hector/VulChecker ePDG JSONL into compact LLM text."""

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, List, Tuple


LINK_ABBREV = {
    'control_flow': 'CF',
    'def_use': 'DU',
}

GUARD_OPS = {
    'branch',
    'int_compare',
    'compare',
    'icmp',
    'fcmp',
}

INTEGER_RISK_OPS = {
    'add',
    'subtract',
    'multiply',
    'signed_divide',
    'unsigned_divide',
    'signed_remainder',
    'unsigned_remainder',
    'shift_left',
    'get_element_pointer',
    'sign_extend',
    'zero_extend',
    'truncate',
}

MEMORY_RISK_OPS = {
    'free',
    'malloc',
    'calloc',
    'realloc',
    'alloca',
    'alloc',
    'load',
    'store',
    'call',
    'invoke',
}

NULLISH_STATIC_VALUES = {'0', '-1', 'null', 'nullptr'}


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


def _operation(record: dict) -> str:
    return str(record.get('operation') or 'unknown')


def _line(record: dict) -> object:
    return record.get('line_number', '?')


def _is_guard(record: dict) -> bool:
    return _operation(record) in GUARD_OPS


def _is_integer_risk(record: dict) -> bool:
    return _operation(record) in INTEGER_RISK_OPS


def _is_memory_risk(record: dict) -> bool:
    return _operation(record) in MEMORY_RISK_OPS


def _is_cleanup_call(record: dict) -> bool:
    return _operation(record) in {'call', 'invoke'}


def _is_store_invalidation(record: dict) -> bool:
    if _operation(record) != 'store':
        return False
    static_value = str(record.get('static_value') or '').strip().lower()
    return static_value in NULLISH_STATIC_VALUES


def _line_operation_summary(records: Iterable[dict], operations: set, limit: int = 16) -> str:
    by_line = defaultdict(Counter)
    for record in records:
        operation = str(record.get('operation') or 'unknown')
        if operation not in operations:
            continue
        line = record.get('line_number', '?')
        tags = _tag_text(record.get('tag', []))
        by_line[line][f'{operation}[{tags}]'] += 1

    if not by_line:
        return 'none observed'

    parts = []
    for line in sorted(by_line, key=lambda item: (str(item) == '?', item))[:limit]:
        op_text = ', '.join(f'{name}x{count}' for name, count in by_line[line].most_common(6))
        parts.append(f'L{line}: {op_text}')
    if len(by_line) > limit:
        parts.append(f'... {len(by_line) - limit} more lines')
    return '; '.join(parts)


def _tagged_line_summary(records: Iterable[dict], limit: int = 16) -> str:
    by_line = defaultdict(Counter)
    for record in records:
        tags = record.get('tag') or []
        if not tags:
            continue
        line = record.get('line_number', '?')
        operation = str(record.get('operation') or 'unknown')
        for tag in tags:
            by_line[line][f'{operation}:{tag}'] += 1

    if not by_line:
        return 'none observed'

    parts = []
    for line in sorted(by_line, key=lambda item: (str(item) == '?', item))[:limit]:
        op_text = ', '.join(f'{name}x{count}' for name, count in by_line[line].most_common(6))
        parts.append(f'L{line}: {op_text}')
    if len(by_line) > limit:
        parts.append(f'... {len(by_line) - limit} more lines')
    return '; '.join(parts)


def _edge_example_summary(records: Iterable[dict], nodes: dict, predicate, limit: int = 8) -> str:
    examples = []
    seen = set()
    for record in records:
        if not predicate(record, nodes):
            continue
        target = nodes.get(record.get('target_id')) or {}
        text = (
            f'L{_line(record)} {_operation(record)} --{LINK_ABBREV.get(record.get("link_type"), record.get("link_type", "?"))}-->'
            f' L{target.get("line_number", "?")} {target.get("operation", "unknown")}'
        )
        if text in seen:
            continue
        examples.append(text)
        seen.add(text)
        if len(examples) >= limit:
            break
    return '; '.join(examples) if examples else 'none observed'


def _line_set_text(values: Iterable[object], limit: int = 16) -> str:
    ints = sorted({value for value in values if isinstance(value, int)})
    if not ints:
        return 'none observed'
    shown = ints[:limit]
    text = ', '.join(f'L{value}' for value in shown)
    if len(ints) > limit:
        text += f', ... {len(ints) - limit} more'
    return text


def _guard_relation_summary(records: List[dict], nodes: dict) -> List[str]:
    pre_guard_lines = set()
    post_check_lines = set()
    for record in records:
        target = nodes.get(record.get('target_id')) or {}
        if _is_guard(record) and _is_integer_risk(target) and record.get('link_type') == 'control_flow':
            pre_guard_lines.add(_line(record))
            pre_guard_lines.add(target.get('line_number'))
        if _is_integer_risk(record) and _is_guard(target):
            post_check_lines.add(_line(record))
            post_check_lines.add(target.get('line_number'))

    return [
        f'pre_guard_control_edges={_edge_example_summary(records, nodes, lambda r, n: _is_guard(r) and _is_integer_risk(n.get(r.get("target_id")) or {}) and r.get("link_type") == "control_flow")}',
        f'post_arithmetic_check_edges={_edge_example_summary(records, nodes, lambda r, n: _is_integer_risk(r) and _is_guard(n.get(r.get("target_id")) or {}))}',
        f'pre_guard_lines={_line_set_text(pre_guard_lines)}',
        f'post_check_lines={_line_set_text(post_check_lines)}',
    ]


def _cleanup_relation_summary(records: List[dict], nodes: dict) -> List[str]:
    invalidation_lines = set()
    repeated_call_lines = []
    call_counts = Counter(_line(record) for record in records if _is_cleanup_call(record))
    for line, count in sorted(call_counts.items()):
        if isinstance(line, int) and count > 1:
            repeated_call_lines.append(f'L{line}x{count}')

    for record in records:
        target = nodes.get(record.get('target_id')) or {}
        if _is_cleanup_call(record) and _is_store_invalidation(target):
            invalidation_lines.add(_line(record))
            invalidation_lines.add(target.get('line_number'))

    return [
        f'post_call_invalidation_edges={_edge_example_summary(records, nodes, lambda r, n: _is_cleanup_call(r) and _is_store_invalidation(n.get(r.get("target_id")) or {}))}',
        f'post_call_invalidation_lines={_line_set_text(invalidation_lines)}',
        f'repeated_cleanup_call_lines={", ".join(repeated_call_lines[:16]) if repeated_call_lines else "none observed"}',
    ]


def _risk_focused_summary(records: List[dict], nodes: dict) -> List[str]:
    return [
        'ePDG interpretation rules:',
        '- root_cause and manifestation are static candidate tags, not ground-truth labels.',
        '- Do not conclude VULNERABLE from these tags alone; fixed and vulnerable versions may share candidate tags.',
        '- Check whether guard/fix evidence blocks the sink: bounds checks, null checks, size checks, pointer state updates, cleanup ownership changes, or early returns.',
        '- For CWE-190/191, only treat guard -> sink control flow as protective evidence. If sink -> compare/branch appears after arithmetic, that is post-check evidence and does not prevent the overflow itself.',
        '- For CWE-415/416, treat call -> store(0/-1/null) as a partial cleanup hint only. It does not prove safety unless the same pointer is invalidated on all relevant paths before any later free or use.',
        '- Repeated cleanup calls on nearby lines should increase suspicion unless mutually exclusive control flow clearly prevents the later call from reusing the same pointer.',
        '',
        'Risk-focused summary:',
        f'guard_or_fix_candidates={_line_operation_summary(records, GUARD_OPS)}',
        f'integer_arithmetic_candidates={_line_operation_summary(records, INTEGER_RISK_OPS)}',
        f'memory_lifecycle_candidates={_line_operation_summary(records, MEMORY_RISK_OPS)}',
        f'tagged_candidate_lines={_tagged_line_summary(records)}',
        *_guard_relation_summary(records, nodes),
        *_cleanup_relation_summary(records, nodes),
    ]


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

    pre_guard_records = [
        record for record in records
        if _is_guard(record)
        and record.get('link_type') == 'control_flow'
        and _is_integer_risk(nodes.get(record.get('target_id')) or {})
    ]
    post_check_records = [
        record for record in records
        if _is_integer_risk(record)
        and _is_guard(nodes.get(record.get('target_id')) or {})
    ]
    cleanup_invalidation_records = [
        record for record in records
        if _is_cleanup_call(record)
        and _is_store_invalidation(nodes.get(record.get('target_id')) or {})
    ]

    # Keep sink-related def-use edges early, then explicit pre-guard evidence.
    # Post-check and post-free invalidation evidence is still kept, but later, so it does not
    # dominate the model into assuming the sink was already prevented.
    def sort_key(record: dict) -> tuple:
        operation = record.get('operation')
        target = nodes.get(record.get('target_id')) or {}
        if record in pre_guard_records:
            op_rank = 0
        elif record.get('link_type') == 'def_use' and ('root_cause' in (record.get('tag') or []) or operation in INTEGER_RISK_OPS):
            op_rank = 1
        elif 'root_cause' in (record.get('tag') or []):
            op_rank = 2
        elif operation in INTEGER_RISK_OPS or operation in MEMORY_RISK_OPS:
            op_rank = 3
        elif record in post_check_records or record in cleanup_invalidation_records:
            op_rank = 4
        elif _is_guard(record) or _is_guard(target):
            op_rank = 5
        else:
            op_rank = 6
        return (op_rank, int(record.get('line_number') or 0), int(record.get('id') or 0), int(record.get('target_id') or 0))

    ordered = sorted(root_records, key=sort_key)
    seen = {(record.get('id'), record.get('target_id'), record.get('link_type')) for record in ordered}
    risk_records = [record for record in records if record.get('operation') in INTEGER_RISK_OPS or record.get('operation') in MEMORY_RISK_OPS]
    def_use_records = [record for record in other_records if record.get('link_type') == 'def_use']
    for group in (pre_guard_records, manifestation_records, def_use_records, risk_records, cleanup_invalidation_records, post_check_records, other_records):
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
        *_risk_focused_summary(records, nodes),
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
