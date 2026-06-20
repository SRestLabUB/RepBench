#!/usr/bin/env python3
"""Run PrimeVul representation comparison on test/ ePDG cases.

This batch runner uses the ePDG files produced under Joern_llm_implement/test
as the testcase set, maps them back to primevul_testcases_output_clean, runs the
normal Joern variants, then runs an additional ePDG-only variant.
"""

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from epdg_jsonl_converter import convert_epdg_jsonl_to_text
from llm_client import LLMClient
from llm_prompt_generator import PromptGenerator
from primevul_representation_experiment import (
    DEFAULT_VARIANTS,
    PrimeVulRepresentationExperiment,
    PrimeVulTestcase,
    function_name_from_label_dir,
    jsonl_append,
    read_json,
    testcase_id,
)


from project_paths import PROJECT_ROOT


ROOT = PROJECT_ROOT
DEFAULT_TEST_ROOT = ROOT / 'Joern_llm_implement' / 'test'
DEFAULT_TESTCASE_ROOT = ROOT / 'primevul_testcases_output_clean'
DEFAULT_OUTPUT_DIR = ROOT / 'primevul_epdg_comparison_expanded'


@dataclass(frozen=True)
class EpdgMappedCase:
    testcase: PrimeVulTestcase
    epdg_path: Optional[Path]
    epdg_scope: str
    epdg_available_files: List[str]
    epdg_test_dir: Path
    epdg_issue: Optional[str] = None


def safe_json_dump(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def is_jsonl_epdg(path: Path) -> bool:
    for line in path.read_text(errors='replace').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        return isinstance(row, dict) and 'link_type' in row and 'source_id' in row and 'target_id' in row
    return False


def find_epdg_files(epdg_label_dir: Path) -> Tuple[Optional[Path], str, List[str], Optional[str]]:
    epdg_dir = epdg_label_dir / 'epdg'
    search_dir = epdg_dir if epdg_dir.is_dir() else epdg_label_dir
    files = sorted([path for path in search_dir.iterdir() if path.is_file()])
    available = [path.name for path in files]
    function_only = [path for path in files if path.stem.endswith('_function_only')]
    if function_only:
        chosen = function_only[0]
        if is_jsonl_epdg(chosen):
            return chosen, 'function_only', available, None
        return None, 'none', available, f'function_only_not_jsonl:{chosen.name}'

    # The teammate output stores the full-file ePDG as a file named after the source stem.
    full_candidates = [path for path in files if not path.name.endswith('_function_only')]
    if full_candidates:
        chosen = full_candidates[0]
        if is_jsonl_epdg(chosen):
            return chosen, 'full_file', available, None
        return None, 'none', available, f'full_file_not_jsonl:{chosen.name}'
    return None, 'none', available, 'no_files'


def build_testcase_from_label_dir(testcase_root: Path, label_dir: Path) -> PrimeVulTestcase:
    metadata_path = label_dir / 'metadata.json'
    if not metadata_path.exists():
        raise FileNotFoundError(f'Missing metadata.json: {metadata_path}')

    metadata = read_json(metadata_path)
    rel = metadata_path.relative_to(testcase_root).parts
    project, cwe_dir, source_name, commit_id, label = rel[:5]
    full_source = label_dir / 'project_src' / metadata['project_file_path']
    if not full_source.exists():
        raise FileNotFoundError(f'Missing source file: {full_source}')
    function_name = resolve_function_name(label_dir, full_source, metadata)

    target = int(metadata.get('target', -1))
    expected = 'VULNERABLE' if target == 1 else 'SAFE'
    return PrimeVulTestcase(
        id=testcase_id([project, cwe_dir, source_name, commit_id[:12], label]),
        project=project,
        cwe=metadata['cwe'],
        source_name=source_name,
        commit_id=commit_id,
        label=label,
        expected=expected,
        metadata_path=str(metadata_path),
        label_dir=str(label_dir),
        function_name=function_name,
        full_source_path=str(full_source),
        project_file_path=metadata['project_file_path'],
        function_start=int(metadata.get('function_start', 0)),
        function_end=int(metadata.get('function_end', 0)),
        target=target,
    )


def resolve_function_name(label_dir: Path, full_source: Path, metadata: dict) -> str:
    marker_name = function_name_from_label_dir(label_dir)
    if marker_name != 'BGD_DECLARE':
        return marker_name

    line_no = int(metadata.get('function_start', 0))
    if line_no <= 0:
        return marker_name
    lines = full_source.read_text(errors='replace').splitlines()
    window = ' '.join(lines[max(line_no - 2, 0): min(line_no + 3, len(lines))])

    # PrimeVul sometimes stores the export macro as the function marker, e.g.
    # BGD_DECLARE(void *) gdImageBmpPtr(...). Joern stores the real function name.
    match = re.search(r'\bBGD_DECLARE\s*\([^)]*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(', window)
    if match:
        return match.group(1)
    return marker_name


def discover_epdg_cases(test_root: Path, testcase_root: Path) -> Tuple[List[EpdgMappedCase], List[dict]]:
    cases: Dict[str, EpdgMappedCase] = {}
    issues: List[dict] = []

    for epdg_label_dir in sorted(test_root.glob('*/*/*/*/cse713_*')):
        if not epdg_label_dir.is_dir():
            continue
        rel = epdg_label_dir.relative_to(test_root)
        parts = rel.parts
        if len(parts) != 5:
            issues.append({'epdg_dir': str(epdg_label_dir), 'issue': 'unexpected_path_shape'})
            continue
        project, cwe, source_name, commit_id, label = parts

        epdg_path, epdg_scope, available, epdg_issue = find_epdg_files(epdg_label_dir)

        mapped_label_dir = testcase_root / project / cwe / source_name / commit_id / label
        try:
            testcase = build_testcase_from_label_dir(testcase_root, mapped_label_dir)
        except Exception as exc:
            issues.append({
                'epdg_dir': str(epdg_label_dir),
                'mapped_label_dir': str(mapped_label_dir),
                'issue': type(exc).__name__,
                'message': str(exc),
                'available_files': available,
            })
            continue

        cases[testcase.id] = EpdgMappedCase(
            testcase=testcase,
            epdg_path=epdg_path,
            epdg_scope=epdg_scope,
            epdg_available_files=available,
            epdg_test_dir=epdg_label_dir,
            epdg_issue=epdg_issue,
        )
        if epdg_issue:
            issues.append({
                'epdg_dir': str(epdg_label_dir),
                'mapped_label_dir': str(mapped_label_dir),
                'testcase_id': testcase.id,
                'issue': epdg_issue,
                'available_files': available,
                'standard_variants': 'will_run',
                'epdg_variant': 'skipped',
            })

    return list(cases.values()), issues


def completed_keys(results_path: Path) -> Set[Tuple[str, str, str]]:
    done = set()
    if not results_path.exists():
        return done
    for line in results_path.read_text(errors='replace').splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get('prediction') or row.get('success') is not None:
            done.add((row.get('testcase_id'), row.get('variant'), row.get('scope')))
    return done


def run_epdg_variant(
    mapped_cases: List[EpdgMappedCase],
    output_dir: Path,
    max_prompt_chars: int,
    max_edges: int,
    model: str,
    dry_run: bool,
    resume: bool,
    connect_timeout: float,
    stream_idle_timeout: float,
) -> None:
    results_path = output_dir / 'results.jsonl'
    prompt_dir = output_dir / 'prompts' / 'epdg'
    done = completed_keys(results_path) if resume else set()
    generator = PromptGenerator(max_prompt_chars=max_prompt_chars, dynamic_few_shot=True)
    client = None if dry_run else LLMClient(model=model)
    epdg_cases = [mapped for mapped in mapped_cases if mapped.epdg_path is not None]
    skipped_cases = [mapped for mapped in mapped_cases if mapped.epdg_path is None]
    if skipped_cases:
        safe_json_dump(
            output_dir / 'epdg_skipped_cases.json',
            [
                {
                    'testcase_id': mapped.testcase.id,
                    'label': mapped.testcase.label,
                    'expected': mapped.testcase.expected,
                    'epdg_scope': mapped.epdg_scope,
                    'epdg_issue': mapped.epdg_issue,
                    'epdg_available_files': mapped.epdg_available_files,
                    'epdg_test_dir': str(mapped.epdg_test_dir),
                }
                for mapped in skipped_cases
            ],
        )

    for index, mapped in enumerate(epdg_cases, 1):
        testcase = mapped.testcase
        assert mapped.epdg_path is not None
        scope = f'epdg_{mapped.epdg_scope}'
        key = (testcase.id, 'epdg', scope)
        if key in done:
            print(f'Skipping completed: {testcase.id} epdg {scope}')
            continue

        epdg_text, epdg_stats = convert_epdg_jsonl_to_text(mapped.epdg_path, max_edges=max_edges)
        prompt_meta = generator.generate_prompt(
            cwe_id=testcase.cwe,
            source_code='',
            ast_text='',
            cfg_text='',
            pdg_text=epdg_text,
        ).render(variant='pdg')
        prompt = str(prompt_meta['prompt'])

        prompt_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = prompt_dir / f'{testcase.id}__epdg.prompt.txt'
        prompt_path.write_text(prompt, encoding='utf-8')

        record = {
            'testcase_id': testcase.id,
            'project': testcase.project,
            'cwe': testcase.cwe,
            'source_name': testcase.source_name,
            'commit_id': testcase.commit_id,
            'label': testcase.label,
            'scope': scope,
            'variant': 'epdg',
            'expected': testcase.expected,
            'prompt_chars': len(prompt),
            'prompt_original_chars': int(prompt_meta['original_chars']),
            'prompt_final_chars': int(prompt_meta['final_chars']),
            'prompt_clipped': bool(prompt_meta['clipped']),
            'max_prompt_chars': max_prompt_chars,
            'llm_streamed': True,
            'llm_connect_timeout_seconds': connect_timeout,
            'llm_stream_idle_timeout_seconds': stream_idle_timeout,
            'epdg_path': str(mapped.epdg_path),
            'epdg_scope': mapped.epdg_scope,
            'epdg_available_files': mapped.epdg_available_files,
            'epdg_stats': epdg_stats,
            'metadata_path': testcase.metadata_path,
            'source_path': testcase.full_source_path,
            'prompt_path': str(prompt_path),
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
                'model_used': None,
                'ttft_seconds': None,
                'total_seconds': None,
                'stream_chunks': 0,
            })
            print(
                f'DRY [{index}/{len(epdg_cases)}] {testcase.id} epdg/{mapped.epdg_scope}: '
                f'prompt_chars={len(prompt)} original={prompt_meta["original_chars"]} '
                f'clipped={prompt_meta["clipped"]}'
            )
        else:
            print(
                f'LLM [{index}/{len(epdg_cases)}] {testcase.id} epdg/{mapped.epdg_scope}: '
                f'prompt_chars={len(prompt)} original={prompt_meta["original_chars"]} '
                f'clipped={prompt_meta["clipped"]} expected={testcase.expected}'
            )
            assert client is not None
            response = client.call(
                prompt,
                stream=True,
                connect_timeout=connect_timeout,
                stream_idle_timeout=stream_idle_timeout,
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
            print(
                f'  -> success={response.success} prediction={response.conclusion} '
                f'confidence={response.confidence}{ttft}{timing} chunks={response.stream_chunks}'
            )

        jsonl_append(results_path, record)


def write_manifest(output_dir: Path, mapped_cases: List[EpdgMappedCase], issues: List[dict], variants: List[str]) -> None:
    epdg_runnable_count = sum(1 for mapped in mapped_cases if mapped.epdg_path is not None)
    manifest = {
        'created_at': datetime.now().isoformat(),
        'testcase_count': len(mapped_cases),
        'epdg_runnable_count': epdg_runnable_count,
        'epdg_skipped_count': len(mapped_cases) - epdg_runnable_count,
        'variants': variants + ['epdg'],
        'standard_variant_count': len(variants),
        'total_expected_records': len(mapped_cases) * len(variants) + epdg_runnable_count,
        'mapped_cases': [
            {
                **asdict(mapped.testcase),
                'epdg_path': str(mapped.epdg_path) if mapped.epdg_path is not None else None,
                'epdg_scope': mapped.epdg_scope,
                'epdg_issue': mapped.epdg_issue,
                'epdg_available_files': mapped.epdg_available_files,
                'epdg_test_dir': str(mapped.epdg_test_dir),
            }
            for mapped in mapped_cases
        ],
        'mapping_issues': issues,
    }
    safe_json_dump(output_dir / 'epdg_comparison_manifest.json', manifest)


def print_mapping_summary(mapped_cases: List[EpdgMappedCase], issues: List[dict], variants: List[str]) -> None:
    epdg_runnable_count = sum(1 for mapped in mapped_cases if mapped.epdg_path is not None)
    print(f'Mapped ePDG cases: {len(mapped_cases)}')
    print(f'Runnable ePDG cases: {epdg_runnable_count}')
    print(f'Standard-only cases: {len(mapped_cases) - epdg_runnable_count}')
    print(f'Mapping issues: {len(issues)}')
    for mapped in mapped_cases:
        tc = mapped.testcase
        epdg_name = mapped.epdg_path.name if mapped.epdg_path is not None else 'SKIPPED'
        print(
            f'  {tc.id}: {tc.cwe} {tc.project}/{tc.source_name} {tc.expected} '
            f'epdg_scope={mapped.epdg_scope} epdg={epdg_name}'
        )
    if issues:
        print('Issues:')
        for issue in issues:
            print(f'  {issue}')
    print(
        f'Expected records: {len(mapped_cases)} * {len(variants)} standard + '
        f'{epdg_runnable_count} epdg = {len(mapped_cases) * len(variants) + epdg_runnable_count}'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description='Run Joern-vs-ePDG comparison on test/ ePDG cases')
    parser.add_argument('--test-root', type=Path, default=DEFAULT_TEST_ROOT)
    parser.add_argument('--testcase-root', type=Path, default=DEFAULT_TESTCASE_ROOT)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument('--scope', choices=['full_file_target_method', 'full_file_all_methods'], default='full_file_target_method')
    parser.add_argument('--variants', nargs='+', default=DEFAULT_VARIANTS)
    parser.add_argument('--max-prompt-chars', type=int, default=50000)
    parser.add_argument('--epdg-max-edges', type=int, default=450)
    parser.add_argument('--model', default='qwen')
    parser.add_argument('--connect-timeout', type=float, default=10)
    parser.add_argument('--stream-idle-timeout', type=float, default=60)
    parser.add_argument('--extract', action='store_true', help='Extract Joern AST/CFG/PDG before running standard variants')
    parser.add_argument('--run-llm', action='store_true', help='Call LLM. If omitted, dry-runs prompt construction only')
    parser.add_argument('--epdg-only', action='store_true', help='Run only the ePDG variant')
    parser.add_argument('--standard-only', action='store_true', help='Run only standard Joern variants')
    parser.add_argument('--projects', nargs='+', help='Optional project-name filter, e.g. libgd')
    parser.add_argument('--testcase-ids', nargs='+', help='Optional exact testcase_id filter')
    parser.add_argument('--no-resume', action='store_true')
    args = parser.parse_args()

    if args.epdg_only and args.standard_only:
        raise ValueError('--epdg-only and --standard-only cannot be used together')

    mapped_cases, issues = discover_epdg_cases(args.test_root, args.testcase_root)
    if args.projects:
        allowed_projects = set(args.projects)
        mapped_cases = [mapped for mapped in mapped_cases if mapped.testcase.project in allowed_projects]
    if args.testcase_ids:
        allowed_ids = set(args.testcase_ids)
        mapped_cases = [mapped for mapped in mapped_cases if mapped.testcase.id in allowed_ids]
    mapped_cases = sorted(mapped_cases, key=lambda m: (m.testcase.cwe, m.testcase.project, m.testcase.source_name, m.testcase.label))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_variants = [] if args.epdg_only else args.variants
    write_manifest(args.output_dir, mapped_cases, issues, manifest_variants)
    print_mapping_summary(mapped_cases, issues, manifest_variants)

    if issues:
        print('Continuing with successfully mapped cases only.')
    if not mapped_cases:
        return 1

    testcases = [mapped.testcase for mapped in mapped_cases]

    if not args.epdg_only:
        experiment = PrimeVulRepresentationExperiment(
            testcase_root=args.testcase_root,
            output_dir=args.output_dir,
            max_prompt_chars=args.max_prompt_chars,
            model=args.model,
            stream_llm=True,
            connect_timeout=args.connect_timeout,
            stream_idle_timeout=args.stream_idle_timeout,
        )
        if args.extract:
            experiment.extract_representations(testcases, scope=args.scope)
        experiment.run(
            testcases=testcases,
            variants=args.variants,
            scope=args.scope,
            dry_run=not args.run_llm,
            resume=not args.no_resume,
        )

    if not args.standard_only:
        run_epdg_variant(
            mapped_cases=mapped_cases,
            output_dir=args.output_dir,
            max_prompt_chars=args.max_prompt_chars,
            max_edges=args.epdg_max_edges,
            model=args.model,
            dry_run=not args.run_llm,
            resume=not args.no_resume,
            connect_timeout=args.connect_timeout,
            stream_idle_timeout=args.stream_idle_timeout,
        )

    # Reuse the existing summary writer so the ePDG variant appears beside the Joern variants.
    experiment = PrimeVulRepresentationExperiment(output_dir=args.output_dir, max_prompt_chars=args.max_prompt_chars, model=args.model)
    experiment.write_summary(args.output_dir / 'results.jsonl')
    print(f'Results written to {args.output_dir / "results.jsonl"}')
    print(f'Manifest written to {args.output_dir / "epdg_comparison_manifest.json"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
