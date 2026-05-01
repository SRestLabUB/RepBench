#!/usr/bin/env python3
"""Run one PrimeVul testcase through the LLM with ePDG JSONL as the only graph input."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from epdg_jsonl_converter import convert_epdg_jsonl_to_text
from llm_client import LLMClient
from llm_prompt_generator import ALL_VARIANTS, PromptGenerator


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(errors='replace'))


def infer_testcase_id(testcase_dir: Path) -> str:
    parts = testcase_dir.resolve().parts
    try:
        label = parts[-1]
        commit_id = parts[-2]
        source_name = parts[-3].replace('.', '_')
        cwe = parts[-4]
        project = parts[-5]
        return '__'.join([project, cwe, source_name, commit_id[:12], label])
    except IndexError:
        return testcase_dir.name


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def main() -> None:
    parser = argparse.ArgumentParser(description='Run ePDG-only LLM test for one PrimeVul testcase')
    parser.add_argument('--testcase-dir', type=Path, required=True, help='Directory containing metadata.json and project_src')
    parser.add_argument('--epdg', type=Path, required=True, help='ePDG JSONL file, usually epdg/function_only.jsonl')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--variant', default='pdg', choices=sorted(ALL_VARIANTS), help='Use pdg for graph-only ePDG')
    parser.add_argument('--max-prompt-chars', type=int, default=50000)
    parser.add_argument('--max-edges', type=int, default=1200)
    parser.add_argument('--model', default='qwen')
    parser.add_argument('--include-source', action='store_true', help='Include source code; use with pdg_plus_source for source+ePDG')
    parser.add_argument('--run-llm', action='store_true', help='Actually call the LLM; otherwise only writes prompt metadata')
    parser.add_argument('--connect-timeout', type=float, default=10)
    parser.add_argument('--stream-idle-timeout', type=float, default=60)
    args = parser.parse_args()

    metadata_path = args.testcase_dir / 'metadata.json'
    if not metadata_path.exists():
        raise FileNotFoundError(f'Missing metadata.json: {metadata_path}')
    if not args.epdg.exists():
        raise FileNotFoundError(f'Missing ePDG JSONL: {args.epdg}')

    metadata = read_json(metadata_path)
    source_path = args.testcase_dir / 'project_src' / metadata['project_file_path']
    if not source_path.exists():
        raise FileNotFoundError(f'Missing source file: {source_path}')

    epdg_text, epdg_stats = convert_epdg_jsonl_to_text(args.epdg, max_edges=args.max_edges)
    source_code = source_path.read_text(errors='replace') if args.include_source else ''

    generator = PromptGenerator(max_prompt_chars=args.max_prompt_chars, dynamic_few_shot=True)
    prompt_meta = generator.generate_prompt(
        cwe_id=metadata['cwe'],
        source_code=source_code,
        ast_text='',
        cfg_text='',
        pdg_text=epdg_text,
    ).render(variant=args.variant)
    prompt = str(prompt_meta['prompt'])

    testcase_id = infer_testcase_id(args.testcase_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = args.output_dir / f'{testcase_id}__{args.variant}.prompt.txt'
    prompt_path.write_text(prompt, encoding='utf-8')

    record = {
        'testcase_id': testcase_id,
        'cwe': metadata.get('cwe'),
        'cve': metadata.get('cve'),
        'commit_id': metadata.get('commit_id'),
        'label': args.testcase_dir.name,
        'expected': 'VULNERABLE' if int(metadata.get('target', -1)) == 1 else 'SAFE',
        'variant': args.variant,
        'scope': 'epdg_function_only',
        'epdg_path': str(args.epdg),
        'source_path': str(source_path),
        'include_source': args.include_source,
        'prompt_path': str(prompt_path),
        'prompt_chars': len(prompt),
        'prompt_original_chars': int(prompt_meta['original_chars']),
        'prompt_final_chars': int(prompt_meta['final_chars']),
        'prompt_clipped': bool(prompt_meta['clipped']),
        'max_prompt_chars': args.max_prompt_chars,
        'epdg_stats': epdg_stats,
        'timestamp': datetime.now().isoformat(),
    }

    if args.run_llm:
        print(
            f'LLM {testcase_id} {args.variant}: prompt_chars={len(prompt)} '
            f'original={prompt_meta["original_chars"]} clipped={prompt_meta["clipped"]} '
            f'expected={record["expected"]}'
        )
        client = LLMClient(model=args.model)
        response = client.call(
            prompt,
            stream=True,
            connect_timeout=args.connect_timeout,
            stream_idle_timeout=args.stream_idle_timeout,
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
    else:
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
            f'DRY {testcase_id} {args.variant}: prompt_chars={len(prompt)} '
            f'original={prompt_meta["original_chars"]} clipped={prompt_meta["clipped"]}'
        )

    append_jsonl(args.output_dir / 'results.jsonl', record)
    (args.output_dir / 'latest_result.json').write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    main()
