#!/usr/bin/env python3
"""Run a small end-to-end validation on generated Juliet representations."""

import json
from dataclasses import asdict
from pathlib import Path

from llm_client import LLMClient
from vulnerability_detector import VulnerabilityDetector


CWES = ["CWE-121", "CWE-122", "CWE-191", "CWE-415", "CWE-416"]


def sample_files(cwe_id: str, limit: int) -> list[str]:
    ast_dir = Path("juliet_representations_real") / cwe_id.replace("-", "_") / "ast"
    return sorted(p.name.replace(".ast.dot", ".c") for p in ast_dir.glob("*.ast.dot"))[:limit]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Validate LLM pipeline on small CWE samples")
    parser.add_argument("--limit", type=int, default=3, help="Files per CWE")
    parser.add_argument("--model", default="qwen")
    parser.add_argument("--max-prompt-chars", type=int, default=12000)
    parser.add_argument("--output", default="validation_results_small.json")
    parser.add_argument("--dry-run", action="store_true", help="Only generate prompts and lengths")
    args = parser.parse_args()

    detector = VulnerabilityDetector(
        compress_representations=True,
        max_prompt_chars=args.max_prompt_chars,
        dynamic_few_shot=True,
    )
    client = None if args.dry_run else LLMClient(model=args.model)

    results = []
    for cwe_id in CWES:
        files = sample_files(cwe_id, args.limit)
        print(f"\n=== {cwe_id}: {len(files)} files ===")
        for filename in files:
            prompt = detector.generate_prompt_for_file(cwe_id, filename)
            record = {
                "cwe_id": cwe_id,
                "filename": filename,
                "prompt_chars": len(prompt),
                "expected_contains_issue": True,
            }
            print(f"{filename}: prompt={len(prompt)} chars")
            if client:
                response = client.call(prompt)
                record.update({
                    "success": response.success,
                    "model": response.model_used,
                    "conclusion": response.conclusion,
                    "confidence": response.confidence,
                    "reasoning": response.reasoning,
                    "explanation": response.explanation,
                    "error": response.error,
                })
                print(f"  -> success={response.success} conclusion={response.conclusion} confidence={response.confidence}")
            results.append(record)

    output = Path(args.output)
    output.write_text(json.dumps(results, indent=2))
    print(f"\nSaved results to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
