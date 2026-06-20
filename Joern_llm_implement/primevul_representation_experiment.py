#!/usr/bin/env python3
"""PrimeVul representation pilot runner.

This script runs the pre-APR representation comparison described in
PRIMEVUL_REPRESENTATION_PILOT_PLAN.md. The default main scope is
full_file_target_method: import the full checked-out source file into Joern,
then export only the target function's AST/CFG/PDG.
"""

import argparse
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from dot_converter import DOTConverter
from joern_http_client import JoernServer
from llm_client import LLMClient
from llm_prompt_generator import ALL_VARIANTS, PromptGenerator


from project_paths import PROJECT_ROOT


ROOT = PROJECT_ROOT
DEFAULT_TESTCASE_ROOT = ROOT / 'primevul_testcases_output_clean'
DEFAULT_OUTPUT_DIR = ROOT / 'primevul_representation_pilot'
SUPPORTED_CWES = {'CWE-122', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416'}
DEFAULT_VARIANTS = [
    'raw',
    'ast',
    'cfg',
    'pdg',
    'ast_cfg',
    'ast_pdg',
    'cfg_pdg',
    'full',
    'ast_plus_source',
    'pdg_plus_source',
]
DEFAULT_PILOT_QUOTAS = {
    'CWE-415': 3,
    'CWE-190': 2,
    'CWE-416': 2,
    'CWE-122': 1,
}

GRAPH_VARIANTS = set(DEFAULT_VARIANTS) - {'raw'}


@dataclass(frozen=True)
class PrimeVulTestcase:
    id: str
    project: str
    cwe: str
    source_name: str
    commit_id: str
    label: str
    expected: str
    metadata_path: str
    label_dir: str
    function_name: str
    full_source_path: str
    project_file_path: str
    function_start: int
    function_end: int
    target: int


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(errors='replace'))


def jsonl_append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def testcase_id(parts: Iterable[str]) -> str:
    safe = []
    for part in parts:
        safe.append(''.join(ch if ch.isalnum() or ch in {'-', '_'} else '_' for ch in part))
    return '__'.join(safe)


def function_name_from_label_dir(label_dir: Path) -> str:
    candidates = [p.name for p in label_dir.iterdir() if p.is_file() and p.name != 'metadata.json']
    if len(candidates) != 1:
        raise RuntimeError(f'Expected one function/source marker file in {label_dir}, found {candidates}')
    return candidates[0]


class PrimeVulRepresentationExperiment:
    def __init__(
        self,
        testcase_root: Path = DEFAULT_TESTCASE_ROOT,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
        max_prompt_chars: int = 50000,
        model: str = 'qwen',
        stream_llm: bool = True,
        connect_timeout: float = 10,
        stream_idle_timeout: float = 60,
    ):
        self.testcase_root = testcase_root
        self.output_dir = output_dir
        self.max_prompt_chars = max_prompt_chars
        self.stream_llm = stream_llm
        self.connect_timeout = connect_timeout
        self.stream_idle_timeout = stream_idle_timeout
        self.converter = DOTConverter()
        self.prompt_generator = PromptGenerator(max_prompt_chars=max_prompt_chars, dynamic_few_shot=True)
        self.client = LLMClient(model=model)
        self.extraction_errors_path = self.output_dir / 'extraction_errors.jsonl'

    def discover_testcases(
        self,
        cwes: Optional[Set[str]] = None,
        include_fixed: bool = False,
        limit: int = 8,
        quotas: Optional[Dict[str, int]] = None,
        verified_ids: Optional[Set[str]] = None,
    ) -> List[PrimeVulTestcase]:
        cwes = cwes or SUPPORTED_CWES
        candidates: List[PrimeVulTestcase] = []
        for metadata_path in sorted(self.testcase_root.rglob('metadata.json')):
            md = read_json(metadata_path)
            cwe = md.get('cwe')
            if cwe not in cwes:
                continue
            if not include_fixed and md.get('target') != 1:
                continue

            label_dir = metadata_path.parent
            try:
                rel = metadata_path.relative_to(self.testcase_root).parts
                project, cwe_dir, source_name, commit_id, label = rel[:5]
                function_name = function_name_from_label_dir(label_dir)
            except Exception as exc:
                print(f'Skipping malformed testcase {metadata_path}: {exc}')
                continue

            full_source = label_dir / 'project_src' / md['project_file_path']
            if not full_source.exists():
                print(f'Skipping missing source {full_source}')
                continue

            target = int(md.get('target', -1))
            expected = 'VULNERABLE' if target == 1 else 'SAFE'
            tc_id = testcase_id([project, cwe_dir, source_name, commit_id[:12], label])
            if verified_ids is not None and tc_id not in verified_ids:
                continue
            candidates.append(PrimeVulTestcase(
                id=tc_id,
                project=project,
                cwe=cwe,
                source_name=source_name,
                commit_id=commit_id,
                label=label,
                expected=expected,
                metadata_path=str(metadata_path),
                label_dir=str(label_dir),
                function_name=function_name,
                full_source_path=str(full_source),
                project_file_path=md['project_file_path'],
                function_start=int(md.get('function_start', 0)),
                function_end=int(md.get('function_end', 0)),
                target=target,
            ))

        if verified_ids is not None:
            candidates.sort(key=lambda tc: (
                tc.cwe,
                Path(tc.full_source_path).stat().st_size if Path(tc.full_source_path).exists() else 0,
                tc.project,
                tc.source_name,
            ))

        if quotas:
            return self._select_by_quota(candidates, quotas, limit)
        return candidates[:limit]

    def _select_by_quota(self, candidates: List[PrimeVulTestcase], quotas: Dict[str, int], limit: int) -> List[PrimeVulTestcase]:
        by_cwe: Dict[str, List[PrimeVulTestcase]] = defaultdict(list)
        for tc in candidates:
            by_cwe[tc.cwe].append(tc)

        selected: List[PrimeVulTestcase] = []
        for cwe, quota in quotas.items():
            selected.extend(by_cwe.get(cwe, [])[:quota])
        if len(selected) < limit:
            seen = {tc.id for tc in selected}
            for tc in candidates:
                if tc.id not in seen:
                    selected.append(tc)
                    seen.add(tc.id)
                if len(selected) >= limit:
                    break
        return selected[:limit]

    def representation_dir(self, testcase: PrimeVulTestcase, scope: str) -> Path:
        return self.output_dir / 'representations' / testcase.id / scope

    def extract_representations(self, testcases: List[PrimeVulTestcase], scope: str = 'full_file_target_method') -> None:
        server = JoernServer()
        if not server.start():
            raise RuntimeError('Could not start Joern server')
        try:
            for index, testcase in enumerate(testcases, 1):
                out_dir = self.representation_dir(testcase, scope)
                if all((out_dir / f'{rep}.dot').exists() for rep in ['ast', 'cfg', 'pdg']):
                    print(f'[{index}/{len(testcases)}] Reusing existing representations: {testcase.id}')
                    continue
                print(f'[{index}/{len(testcases)}] Extracting {scope}: {testcase.id}')
                out_dir.mkdir(parents=True, exist_ok=True)
                try:
                    self._extract_one(server, testcase, scope, out_dir)
                except Exception as exc:
                    print(f'  ERROR extracting {testcase.id}: {exc}')
                    jsonl_append(self.extraction_errors_path, {
                        'testcase_id': testcase.id,
                        'scope': scope,
                        'timestamp': datetime.now().isoformat(),
                        'error': str(exc),
                    })
        finally:
            server.stop()

    def _extract_one(self, server: JoernServer, testcase: PrimeVulTestcase, scope: str, out_dir: Path) -> None:
        source_file = testcase.full_source_path.replace('"', '\\"')
        result = server.query(f'importCode("{source_file}")', timeout=600)
        if not result['success'] and 'Cpg[' not in result['stdout']:
            raise RuntimeError(f'importCode failed for {testcase.id}: {result}')
        server.query('run.ossdataflow', timeout=600)

        method_query = 'cpg.method'
        if scope == 'full_file_target_method':
            method_name = testcase.function_name.replace('"', '\\"')
            method_query = f'cpg.method.name("{method_name}")'
        elif scope != 'full_file_all_methods':
            raise ValueError(f'Unknown scope: {scope}')

        for rep_type, query_name in [('ast', 'dotAst'), ('cfg', 'dotCfg'), ('pdg', 'dotPdg')]:
            query = f'{method_query}.{query_name}.l'
            result = server.query(query, timeout=300)
            dot_text = result['stdout'] or ''
            if 'digraph' not in dot_text:
                print(f'  WARNING: no {rep_type.upper()} digraph for {testcase.id}: {result.get("stderr", "")[:120]}')
            (out_dir / f'{rep_type}.dot').write_text(dot_text, encoding='utf-8')

        metadata_record = asdict(testcase) | {'scope': scope, 'extracted_at': datetime.now().isoformat()}
        (out_dir / 'metadata.json').write_text(json.dumps(metadata_record, indent=2), encoding='utf-8')

    def load_representation_texts(self, testcase: PrimeVulTestcase, scope: str) -> Dict[str, str]:
        rep_dir = self.representation_dir(testcase, scope)
        texts = {}
        for rep_type in ['ast', 'cfg', 'pdg']:
            path = rep_dir / f'{rep_type}.dot'
            if not path.exists():
                texts[rep_type] = ''
                continue
            dot = path.read_text(errors='replace')
            texts[rep_type] = self.converter.to_text(dot, src=f'{testcase.id}/{scope}/{rep_type}') if dot else ''
        return texts

    def graph_stats(self, testcase: PrimeVulTestcase, scope: str) -> Dict[str, dict]:
        rep_dir = self.representation_dir(testcase, scope)
        stats = {}
        for rep_type in ['ast', 'cfg', 'pdg']:
            path = rep_dir / f'{rep_type}.dot'
            dot = path.read_text(errors='replace') if path.exists() else ''
            parsed = self.converter.parse_graphs(dot)
            graphs = parsed.get('graphs', [])
            stats[rep_type] = {
                'graphs': len(graphs),
                'nodes': sum(len(g.get('nodes', [])) for g in graphs),
                'edges': sum(len(g.get('edges', [])) for g in graphs),
                'dot_chars': len(dot),
            }
        return stats

    def generate_prompt(self, testcase: PrimeVulTestcase, variant: str, scope: str) -> Dict[str, object]:
        reps = self.load_representation_texts(testcase, scope)
        source = Path(testcase.full_source_path).read_text(errors='replace')
        return self.prompt_generator.generate_prompt(
            cwe_id=testcase.cwe,
            source_code=source,
            ast_text=reps['ast'],
            cfg_text=reps['cfg'],
            pdg_text=reps['pdg'],
        ).render(variant=variant)

    def has_complete_graphs(self, testcase: PrimeVulTestcase, scope: str) -> bool:
        rep_dir = self.representation_dir(testcase, scope)
        return all((rep_dir / f'{rep}.dot').exists() for rep in ['ast', 'cfg', 'pdg'])

    def run(
        self,
        testcases: List[PrimeVulTestcase],
        variants: List[str],
        scope: str = 'full_file_target_method',
        dry_run: bool = False,
        resume: bool = True,
    ) -> Path:
        results_path = self.output_dir / 'results.jsonl'
        completed = self._completed_keys(results_path) if resume else set()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for testcase in testcases:
            if any(variant in GRAPH_VARIANTS for variant in variants) and not self.has_complete_graphs(testcase, scope):
                print(f'Skipping testcase without complete graphs: {testcase.id}')
                continue
            stats = self.graph_stats(testcase, scope)
            for variant in variants:
                key = (testcase.id, variant, scope)
                if key in completed:
                    print(f'Skipping completed: {testcase.id} {variant} {scope}')
                    continue

                prompt_meta = self.generate_prompt(testcase, variant, scope)
                prompt = str(prompt_meta['prompt'])
                record = {
                    'testcase_id': testcase.id,
                    'project': testcase.project,
                    'cwe': testcase.cwe,
                    'source_name': testcase.source_name,
                    'commit_id': testcase.commit_id,
                    'label': testcase.label,
                    'scope': scope,
                    'variant': variant,
                    'expected': testcase.expected,
                    'prompt_chars': len(prompt),
                    'prompt_original_chars': int(prompt_meta['original_chars']),
                    'prompt_final_chars': int(prompt_meta['final_chars']),
                    'prompt_clipped': bool(prompt_meta['clipped']),
                    'max_prompt_chars': self.max_prompt_chars,
                    'llm_streamed': self.stream_llm,
                    'llm_connect_timeout_seconds': self.connect_timeout,
                    'llm_stream_idle_timeout_seconds': self.stream_idle_timeout,
                    'graph_stats': stats,
                    'timestamp': datetime.now().isoformat(),
                }

                if dry_run:
                    record.update({
                        'success': None,
                        'prediction': None,
                        'confidence': None,
                        'reasoning': {},
                        'explanation': '',
                        'error': None,
                        'ttft_seconds': None,
                        'total_seconds': None,
                        'stream_chunks': 0,
                    })
                    print(
                        f'DRY {testcase.id} {variant}: '
                        f'prompt_chars={len(prompt)} original={prompt_meta["original_chars"]} '
                        f'clipped={prompt_meta["clipped"]}'
                    )
                else:
                    print(
                        f'LLM {testcase.id} {variant}: '
                        f'prompt_chars={len(prompt)} original={prompt_meta["original_chars"]} '
                        f'clipped={prompt_meta["clipped"]} expected={testcase.expected}'
                    )
                    response = self.client.call(
                        prompt,
                        stream=self.stream_llm,
                        connect_timeout=self.connect_timeout,
                        stream_idle_timeout=self.stream_idle_timeout,
                        total_timeout=180,
                    )
                    record.update({
                        'success': response.success,
                        'prediction': response.conclusion,
                        'confidence': response.confidence,
                        'reasoning': response.reasoning,
                        'explanation': response.explanation,
                        'error': response.error,
                        'model_used': response.model_used,
                        'ttft_seconds': response.ttft_seconds,
                        'total_seconds': response.total_seconds,
                        'stream_chunks': response.stream_chunks,
                        'response_streamed': response.streamed,
                        'response_stream_idle_timeout_seconds': response.stream_idle_timeout_seconds,
                    })
                    timing = f' total={response.total_seconds:.1f}s' if response.total_seconds is not None else ''
                    ttft = f' ttft={response.ttft_seconds:.1f}s' if response.ttft_seconds is not None else ''
                    print(f'  -> success={response.success} prediction={response.conclusion} confidence={response.confidence}{ttft}{timing} chunks={response.stream_chunks}')

                jsonl_append(results_path, record)

        self.write_summary(results_path)
        return results_path

    def _completed_keys(self, results_path: Path) -> Set[tuple]:
        completed = set()
        if not results_path.exists():
            return completed
        for line in results_path.read_text(errors='replace').splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get('prediction') or row.get('success') is not None:
                completed.add((row.get('testcase_id'), row.get('variant'), row.get('scope')))
        return completed

    def write_summary(self, results_path: Path) -> None:
        rows = []
        if results_path.exists():
            for line in results_path.read_text(errors='replace').splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        by_variant: Dict[str, List[dict]] = defaultdict(list)
        for row in rows:
            if row.get('prediction'):
                by_variant[row['variant']].append(row)

        summary = []
        for variant, items in sorted(by_variant.items()):
            correct = [r for r in items if r.get('prediction') == r.get('expected')]
            confidences = [float(r.get('confidence') or 0.0) for r in items]
            prompt_chars = [int(r.get('prompt_chars') or 0) for r in items]
            total_seconds = [float(r['total_seconds']) for r in items if r.get('total_seconds') is not None]
            ttft_seconds = [float(r['ttft_seconds']) for r in items if r.get('ttft_seconds') is not None]
            avg_chars = sum(prompt_chars) / len(prompt_chars) if prompt_chars else 0.0
            accuracy = len(correct) / len(items) if items else 0.0
            summary.append({
                'variant': variant,
                'count': len(items),
                'accuracy': accuracy,
                'avg_confidence': sum(confidences) / len(confidences) if confidences else 0.0,
                'avg_prompt_chars': avg_chars,
                'avg_total_seconds': sum(total_seconds) / len(total_seconds) if total_seconds else None,
                'avg_ttft_seconds': sum(ttft_seconds) / len(ttft_seconds) if ttft_seconds else None,
                'clipped_count': sum(1 for r in items if r.get('prompt_clipped')),
                'efficiency_accuracy_per_1k_chars': accuracy / (avg_chars / 1000) if avg_chars else 0.0,
            })

        summary_path = self.output_dir / 'summary.json'
        summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
        if summary:
            print(f'Summary written to {summary_path}')


def parse_quotas(value: Optional[str]) -> Optional[Dict[str, int]]:
    if not value:
        return DEFAULT_PILOT_QUOTAS
    if value.lower() == 'none':
        return None
    quotas = {}
    for item in value.split(','):
        cwe, count = item.split(':', 1)
        quotas[cwe.strip()] = int(count.strip())
    return quotas


def load_verified_ids(path: Optional[Path]) -> Optional[Set[str]]:
    if not path:
        return None
    verified_ids = set()
    for line in path.read_text(errors='replace').splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get('healthy'):
            verified_ids.add(row['testcase_id'])
    return verified_ids


def main() -> int:
    parser = argparse.ArgumentParser(description='PrimeVul representation pilot runner')
    parser.add_argument('--testcase-root', type=Path, default=DEFAULT_TESTCASE_ROOT)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument('--scope', choices=['full_file_target_method', 'full_file_all_methods'], default='full_file_target_method')
    parser.add_argument('--variants', nargs='+', default=DEFAULT_VARIANTS, choices=sorted(ALL_VARIANTS))
    parser.add_argument('--cwes', nargs='+', default=['CWE-122', 'CWE-190', 'CWE-415', 'CWE-416'])
    parser.add_argument('--limit', type=int, default=8)
    parser.add_argument('--quotas', help='Comma-separated CWE quota, e.g. CWE-415:3,CWE-190:2. Use none for plain sorted selection.')
    parser.add_argument('--verified-jsonl', type=Path, help='Optional verification JSONL from verify_primevul_testcases.py; only healthy IDs are selected.')
    parser.add_argument('--include-fixed', action='store_true', help='Also include fixed/Safe PrimeVul samples')
    parser.add_argument('--max-prompt-chars', type=int, default=50000)
    parser.add_argument('--model', default='qwen')
    parser.add_argument('--no-stream', action='store_true', help='Disable streaming LLM responses and use one blocking response')
    parser.add_argument('--connect-timeout', type=float, default=10, help='LLM API connection timeout in seconds')
    parser.add_argument('--stream-idle-timeout', type=float, default=60, help='Abort only if no stream chunk arrives for this many seconds')
    parser.add_argument('--extract', action='store_true', help='Extract Joern AST/CFG/PDG before generating prompts')
    parser.add_argument('--run-llm', action='store_true', help='Call the LLM API. If omitted, runs a dry prompt-length pass.')
    parser.add_argument('--no-resume', action='store_true')
    args = parser.parse_args()

    experiment = PrimeVulRepresentationExperiment(
        testcase_root=args.testcase_root,
        output_dir=args.output_dir,
        max_prompt_chars=args.max_prompt_chars,
        model=args.model,
        stream_llm=not args.no_stream,
        connect_timeout=args.connect_timeout,
        stream_idle_timeout=args.stream_idle_timeout,
    )
    testcases = experiment.discover_testcases(
        cwes=set(args.cwes),
        include_fixed=args.include_fixed,
        limit=args.limit,
        quotas=parse_quotas(args.quotas),
        verified_ids=load_verified_ids(args.verified_jsonl),
    )
    print(f'Selected {len(testcases)} testcases')
    for tc in testcases:
        print(f'  {tc.id}: {tc.cwe} {tc.project}/{tc.source_name} {tc.expected}')

    if args.extract:
        experiment.extract_representations(testcases, scope=args.scope)

    missing = []
    if any(variant in GRAPH_VARIANTS for variant in args.variants):
        for tc in testcases:
            rep_dir = experiment.representation_dir(tc, args.scope)
            for rep in ['ast', 'cfg', 'pdg']:
                if not (rep_dir / f'{rep}.dot').exists():
                    missing.append(str(rep_dir / f'{rep}.dot'))
    if missing:
        print('Missing representation files for some testcases; those testcases will be skipped during LLM phase:')
        for path in missing[:20]:
            print(f'  {path}')
        if len(missing) > 20:
            print(f'  ... {len(missing) - 20} more')

    results_path = experiment.run(
        testcases=testcases,
        variants=args.variants,
        scope=args.scope,
        dry_run=not args.run_llm,
        resume=not args.no_resume,
    )
    print(f'Results written to {results_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
