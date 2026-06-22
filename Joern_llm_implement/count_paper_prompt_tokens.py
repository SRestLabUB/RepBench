#!/usr/bin/env python3
"""Reconstruct paper prompts and obtain qwen3.6-plus input-token counts."""

import argparse
import hashlib
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from primevul_representation_experiment import (
    DEFAULT_VARIANTS,
    PrimeVulRepresentationExperiment,
)
from project_paths import PROJECT_ROOT


SYSTEM_PROMPT = """You are a senior C/C++ developer performing code review.
Analyze the given C/C++ code for security issues.
Respond with a JSON object in the exact format specified."""


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_jsonl(path: Path, record: dict, lock: threading.Lock) -> None:
    with lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()


def request_token_count(
    session: requests.Session,
    endpoint: str,
    api_key: str,
    prompt: str,
    attempts: int = 6,
) -> dict:
    payload = {
        "model": "qwen3.6-plus",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "enable_thinking": True,
        "thinking_budget": 1,
        "temperature": 0.2,
        "max_tokens": 1,
        "response_format": {"type": "json_object"},
        "stream": False,
    }
    for attempt in range(1, attempts + 1):
        try:
            response = session.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=(15, 180),
            )
            data = response.json()
            if response.status_code == 200:
                usage = data.get("usage") or {}
                if usage.get("prompt_tokens") is None:
                    raise RuntimeError("Successful response omitted usage.prompt_tokens")
                return {
                    "prompt_tokens": usage["prompt_tokens"],
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                    "token_count_model": data.get("model", "qwen3.6-plus"),
                    "token_count_request_id": data.get("id"),
                }
            if response.status_code not in {408, 429, 500, 502, 503, 504}:
                error = data.get("error") or {}
                raise RuntimeError(
                    f"HTTP {response.status_code}: {error.get('code') or error.get('type')}"
                )
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            if attempt == attempts:
                raise RuntimeError(str(exc)) from exc
        time.sleep(min(30, 2 ** (attempt - 1)))
    raise RuntimeError("Token-count request exhausted retries")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results",
        type=Path,
        default=PROJECT_ROOT
        / "primevul_paper_results_latest/standard/standard_107_results_1068.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "primevul_paper_results_latest/standard/standard_107_token_counts.jsonl",
    )
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--include-proxy", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    api_key = os.environ.get("LLM_API_KEY")
    base_url = os.environ.get("LLM_API_BASE_URL", "").rstrip("/")
    if not api_key or not base_url:
        raise SystemExit("Set LLM_API_KEY and LLM_API_BASE_URL")
    endpoint = f"{base_url}/chat/completions"

    rows = load_jsonl(args.results)
    completed = {}
    if args.output.exists():
        completed = {
            (row["testcase_id"], row["variant"]): row for row in load_jsonl(args.output)
        }

    testcase_root = PROJECT_ROOT / "primevul_testcases_output_clean"
    new_experiment = PrimeVulRepresentationExperiment(
        testcase_root=testcase_root,
        output_dir=PROJECT_ROOT / "primevul_new_batch_results",
    )
    old_experiment = PrimeVulRepresentationExperiment(
        testcase_root=testcase_root,
        output_dir=PROJECT_ROOT / "primevul_token_count_reconstruction",
    )
    testcases = {
        testcase.id: testcase
        for testcase in new_experiment.discover_testcases(
            include_fixed=True, limit=10000
        )
    }
    new_ids = {
        path.parent.parent.name
        for path in (
            PROJECT_ROOT / "primevul_new_batch_results/representations"
        ).glob("*/full_file_target_method/ast.dot")
    }

    tasks = []
    blocked = 0
    proxy_skipped = 0
    for row in rows:
        key = (row["testcase_id"], row["variant"])
        if key in completed:
            continue
        testcase = testcases.get(row["testcase_id"])
        if testcase is None:
            blocked += 1
            continue
        experiment = new_experiment if row["testcase_id"] in new_ids else old_experiment
        rendered = experiment.generate_prompt(
            testcase, row["variant"], "full_file_target_method"
        )
        prompt = str(rendered["prompt"])
        reconstructed_chars = len(prompt)
        status = (
            "exact"
            if reconstructed_chars == row["prompt_chars"]
            else "proxy_reconstructed"
        )
        if status != "exact" and not args.include_proxy:
            proxy_skipped += 1
            continue
        tasks.append((row, prompt, reconstructed_chars, status))
    if args.limit is not None:
        tasks = tasks[: args.limit]

    print(
        f"queued={len(tasks)} resumed={len(completed)} "
        f"proxy_skipped={proxy_skipped} blocked={blocked}",
        flush=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_lock = threading.Lock()
    local = threading.local()

    def run(task):
        row, prompt, reconstructed_chars, status = task
        if not hasattr(local, "session"):
            local.session = requests.Session()
        usage = request_token_count(local.session, endpoint, api_key, prompt)
        return {
            "testcase_id": row["testcase_id"],
            "project": row.get("project"),
            "cwe": row.get("cwe"),
            "variant": row["variant"],
            "expected": row.get("expected"),
            "historical_prompt_chars": row["prompt_chars"],
            "reconstructed_prompt_chars": reconstructed_chars,
            "prompt_reconstruction_status": status,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            **usage,
        }

    succeeded = failed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {pool.submit(run, task): task for task in tasks}
        for index, future in enumerate(as_completed(future_map), 1):
            row = future_map[future][0]
            try:
                record = future.result()
                append_jsonl(args.output, record, write_lock)
                succeeded += 1
            except Exception as exc:
                failed += 1
                print(
                    f"FAILED {row['testcase_id']} {row['variant']}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            if index % 20 == 0 or index == len(tasks):
                print(
                    f"progress={index}/{len(tasks)} succeeded={succeeded} failed={failed}",
                    flush=True,
                )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
