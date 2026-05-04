#!/usr/bin/env python3
"""Conservative DOT representation compression for LLM prompts."""

from copy import deepcopy
from pathlib import Path

from dot_converter import DOTConverter


CWE_SINK_HINTS = {
    'CWE-121': ['memcpy', 'strcpy', 'sprintf', 'strcat', 'gets', 'scanf'],
    'CWE-122': ['memcpy', 'malloc', 'realloc', 'strcpy', 'sprintf'],
    'CWE-190': ['addition', '+', 'increment', '++', 'RAND32', 'rand', 'MAX'],
    'CWE-191': ['subtraction', '-', 'decrement', '--', 'RAND32', 'rand', 'MIN'],
    'CWE-415': ['free', 'malloc', 'NULL'],
    'CWE-416': ['free', 'malloc', 'calloc', 'realloc', '[]', '->'],
}

DROP_GRAPH_NAMES = {
    'main', 'RAND32', 'printLine', 'printHexCharLine',
    '<operator>.cast', '<operator>.lessThan', '<operator>.assignment',
    '<operator>.addition', '<operator>.subtraction', '<operator>.multiplication',
}

DROP_NODE_TYPES = {
    'TYPE_REF', 'METHOD_RETURN', 'MODIFIER', 'METHOD_REF', 'PARAM',
}

LOW_VALUE_NODE_TYPES = {'BLOCK'}


class DOTCompressor:
    """Compress Joern DOT graphs while preserving vulnerability evidence."""

    def __init__(self, compression_level='conservative', max_edges_per_graph=25):
        if compression_level != 'conservative':
            raise ValueError('Only conservative compression is currently implemented')
        self.compression_level = compression_level
        self.max_edges_per_graph = max_edges_per_graph
        self.converter = DOTConverter()

    def compress_text(self, dot, cwe_id='CWE-190', graph_kind='generic', src=''):
        parsed = self.converter.parse_graphs(dot)
        compressed = self.compress_parsed(parsed, cwe_id, graph_kind)
        return self.to_text(compressed, src=src, cwe_id=cwe_id, graph_kind=graph_kind)

    def compress_file(self, path, cwe_id='CWE-190'):
        dot = Path(path).read_text()
        graph_kind = self._infer_graph_kind(path)
        return self.compress_text(dot, cwe_id=cwe_id, graph_kind=graph_kind, src=Path(path).stem)

    def compress_parsed(self, parsed, cwe_id='CWE-190', graph_kind='generic'):
        graphs = []
        for graph in deepcopy(parsed.get('graphs', [])):
            if not self._keep_graph(graph, cwe_id):
                continue
            graph['nodes'] = self._filter_nodes(graph.get('nodes', []), cwe_id)
            kept_ids = {node['id'] for node in graph['nodes']}
            graph['edges'] = self._filter_edges(graph.get('edges', []), kept_ids, graph_kind)
            if graph['nodes'] or graph['edges']:
                graphs.append(graph)
        return {'graphs': graphs}

    def to_text(self, parsed, src='', cwe_id='CWE-190', graph_kind='generic'):
        lines = ['=' * 70, 'COMPRESSED PROGRAM REPRESENTATION', '=' * 70]
        if src:
            lines.append(f'Source: {src}')
        lines.append(f'CWE Focus: {cwe_id}')
        lines.append(f'Graph Kind: {graph_kind.upper()}')

        for graph in parsed.get('graphs', []):
            lines.extend(['', f"### {graph['graph_name'].upper()} ###", ''])
            by_line = {}
            for node in graph.get('nodes', []):
                if node.get('line', 0) > 0:
                    by_line.setdefault(node['line'], []).append(node)
            for line_no in sorted(by_line):
                for node in by_line[line_no]:
                    code = node.get('code') or node.get('type', '')
                    lines.append(f'L{line_no:3d} | {node["type"]:15s} | {code}')

            if graph.get('edges'):
                lines.extend(['', 'Relevant Dependencies:'])
                for edge in graph['edges'][:self.max_edges_per_graph]:
                    label = edge.get('label', '')
                    edge_type = edge.get('type', '')
                    if label:
                        lines.append(f'  {edge["source"]} -> {edge["target"]} [{edge_type}: {label}]')
                    else:
                        lines.append(f'  {edge["source"]} -> {edge["target"]} [{edge_type}]')

        lines.extend(['', '=' * 70])
        return '\n'.join(lines)

    def _keep_graph(self, graph, cwe_id):
        raw_name = graph.get('graph_name', '')
        name = raw_name.replace('&lt;', '<').replace('&gt;', '>')
        if name in DROP_GRAPH_NAMES or name.startswith('<operator>'):
            return False
        nodes = graph.get('nodes', [])
        if not nodes:
            return False
        if any(marker in name.lower() for marker in ['bad', 'good', 'g2b', 'b2g']):
            return True
        return self._contains_cwe_evidence(nodes, cwe_id)

    def _filter_nodes(self, nodes, cwe_id):
        hints = [hint.lower() for hint in CWE_SINK_HINTS.get(cwe_id, [])]
        filtered = []
        seen = set()
        for node in nodes:
            ntype = node.get('type', '')
            code = node.get('code', '')
            if ntype in DROP_NODE_TYPES:
                continue
            if not code and ntype in LOW_VALUE_NODE_TYPES:
                continue

            text = f'{ntype} {code}'.lower()
            is_evidence = any(hint.lower() in text for hint in hints)
            if ntype == 'BLOCK' and not is_evidence:
                continue

            key = (node.get('line'), ntype, code)
            if key in seen:
                continue
            seen.add(key)
            filtered.append(node)
        return filtered

    def _filter_edges(self, edges, kept_ids, graph_kind):
        filtered = []
        for edge in edges:
            if edge.get('source') not in kept_ids or edge.get('target') not in kept_ids:
                continue
            edge_type = edge.get('type', '')
            label = edge.get('label', '')
            if graph_kind == 'ast':
                continue
            if graph_kind == 'pdg' and edge_type not in {'DDG', 'CDG'}:
                continue
            if graph_kind == 'cfg' and edge_type not in {'CFG', 'AST'}:
                continue
            if label == '' and graph_kind == 'pdg':
                continue
            filtered.append(edge)
        return filtered[:self.max_edges_per_graph]

    def _contains_cwe_evidence(self, nodes, cwe_id):
        hints = [hint.lower() for hint in CWE_SINK_HINTS.get(cwe_id, [])]
        for node in nodes:
            text = f"{node.get('type', '')} {node.get('code', '')}".lower()
            if any(hint in text for hint in hints):
                return True
        return False

    def _infer_graph_kind(self, path):
        suffixes = ''.join(Path(path).suffixes).lower()
        stem = Path(path).stem.lower()
        if '.ast.' in suffixes or stem.endswith('.ast'):
            return 'ast'
        if '.cfg.' in suffixes or stem.endswith('.cfg'):
            return 'cfg'
        if '.pdg.' in suffixes or stem.endswith('.pdg'):
            return 'pdg'
        return 'generic'


def compress_file(path, cwe_id='CWE-190', compression_level='conservative'):
    return DOTCompressor(compression_level=compression_level).compress_file(path, cwe_id=cwe_id)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Compress Joern DOT files for LLM prompts')
    parser.add_argument('file')
    parser.add_argument('--cwe', default='CWE-190')
    parser.add_argument('--level', default='conservative')
    args = parser.parse_args()

    print(compress_file(args.file, cwe_id=args.cwe, compression_level=args.level))
