#!/usr/bin/env python3
import re, json
from pathlib import Path

class DOTConverter:
    def parse_graphs(self, dot):
        graphs = []
        # Extract digraph content from Scala """ wrapper
        digraph_pattern = r'"""digraph\s+"([^"]+)"\s*\{(.*?)"""'
        for m in re.finditer(digraph_pattern, dot, re.DOTALL):
            name = m.group(1)
            content = m.group(2)
            g = {'graph_name': name, 'nodes': [], 'edges': []}
            # Parse labels with format: TYPE, line<BR/>code (with spaces around =)
            node_pattern = r'"(\d+)"\s*\[label\s*=\s*<(.+?)>\s*\]'
            for nm in re.finditer(node_pattern, content, re.DOTALL):
                nid, lbl = nm.group(1), nm.group(2).strip()
                parts = lbl.split('<BR/>')
                if len(parts) >= 2:
                    type_part = parts[0].strip()
                    # Handle "TYPE, line" format - extract type and line from first part
                    line = 0
                    if ',' in type_part:
                        type_line = type_part.rsplit(',', 1)
                        type_part = type_line[0].strip()
                        try:
                            line = int(type_line[1].strip())
                        except:
                            pass
                    # Handle (TYPE|operator) format
                    if type_part.startswith('(') and ')' in type_part:
                        match = re.match(r'\(([^)]+)\)', type_part)
                        if match:
                            ntype = match.group(1).strip()
                            if ntype.startswith('operator.'):
                                ntype = ntype.replace('operator.', '')
                        else:
                            ntype = type_part
                    else:
                        ntype = type_part
                        if ntype.startswith('operator.'):
                            ntype = ntype.replace('operator.', '')
                    # Decode HTML entities in type
                    ntype = ntype.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&amp;', '&')
                    code = ' '.join(p.strip() for p in parts[1:]) if len(parts) > 1 else ''
                    code = code.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&amp;', '&')
                    g['nodes'].append({'id': nid, 'type': ntype, 'line': line, 'code': code})
            # Parse edges with optional [ label = "DDG: var" ] format
            edge_pattern = r'"(\d+)"\s*->\s*"(\d+)"(?:\s*\[([^]]+)\])?'
            for em in re.finditer(edge_pattern, content):
                s, t = em.group(1), em.group(2)
                edge_attrs = em.group(3) if em.group(3) else ''
                lbl = ''
                if edge_attrs:
                    label_match = re.search(r'label\s*=\s*"([^"]*)"', edge_attrs)
                    if label_match:
                        lbl = label_match.group(1)
                edge_type = 'AST'
                if 'DDG' in lbl:
                    edge_type = 'DDG'
                elif 'CDG' in lbl:
                    edge_type = 'CDG'
                elif lbl:
                    edge_type = 'CFG'
                clean_lbl = lbl.replace('DDG: ', '').replace('CDG: ', '').strip() if lbl else ''
                g['edges'].append({'source': s, 'target': t, 'type': edge_type, 'label': clean_lbl})
            graphs.append(g)
        return {'graphs': graphs}
    
    def to_text(self, dot, src=''):
        p = self.parse_graphs(dot)
        lines = ['='*70, 'PROGRAM REPRESENTATION', '='*70]
        if src: lines.append(f'Source: {src}')
        for g in p['graphs']:
            lines.extend(['', f"### {g['graph_name'].upper()} ###", ''])
            by_line = {}
            for n in g['nodes']:
                if n['line'] > 0: by_line.setdefault(n['line'], []).append(n)
            for ln in sorted(by_line.keys()):
                for n in by_line[ln]:
                    if n['code']: lines.append(f'L{ln:3d} | {n["type"]:15s} | {n["code"]}')
            if g['edges']:
                lines.extend(['', 'Dependencies:'])
                for e in [x for x in g['edges'] if x.get('label')][:15]:
                    lines.append(f'  {e["source"]} -> {e["target"]} [{e["label"]}]')
        lines.extend(['', '='*70])
        return '\n'.join(lines)

def convert_file(path, fmt='text', cwe_id='CWE-190', compress=False):
    if compress:
        from dot_compressor import compress_file
        return compress_file(path, cwe_id=cwe_id)
    cvt = DOTConverter()
    with open(path) as f: dot = f.read()
    src = Path(path).stem
    if fmt == 'text': return cvt.to_text(dot, src)
    return json.dumps(cvt.parse_graphs(dot), indent=2)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2: print('Usage: python dot_converter.py <file> [--format text|json] [--compress] [--cwe CWE-190]'); sys.exit(1)
    fmt = 'text'
    cwe_id = 'CWE-190'
    compress = '--compress' in sys.argv
    if '--format' in sys.argv:
        i = sys.argv.index('--format')
        if i+1 < len(sys.argv): fmt = sys.argv[i+1]
    if '--cwe' in sys.argv:
        i = sys.argv.index('--cwe')
        if i+1 < len(sys.argv): cwe_id = sys.argv[i+1]
    print(convert_file(sys.argv[1], fmt, cwe_id=cwe_id, compress=compress))
