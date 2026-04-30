#!/usr/bin/env python3
"""Prompt generation with dynamic few-shot selection for vulnerability detection."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


CWE_INFO = {
    'CWE-121': 'Stack-based Buffer Overflow',
    'CWE-122': 'Heap-based Buffer Overflow',
    'CWE-190': 'Integer Overflow',
    'CWE-191': 'Integer Underflow',
    'CWE-415': 'Double Free',
    'CWE-416': 'Use After Free',
}

CWE_SINK_HINTS = {
    'CWE-121': ['memcpy', 'strcpy', 'sprintf', 'strcat', 'gets', 'scanf'],
    'CWE-122': ['memcpy', 'malloc', 'realloc', 'strcpy', 'sprintf'],
    'CWE-190': ['addition', '+', 'increment', '++', 'RAND32', 'rand'],
    'CWE-191': ['subtraction', '-', 'decrement', '--', 'RAND32', 'rand'],
    'CWE-415': ['free'],
    'CWE-416': ['free', 'malloc', 'calloc', 'realloc', 'pointer access'],
}


@dataclass
class VulnerabilityPrompt:
    cwe_id: str
    source_code: str
    ast_text: str
    cfg_text: str
    pdg_text: str
    few_shot_examples: List[Dict]
    max_prompt_chars: int = 32000

    def to_message(self) -> str:
        cwe_name = CWE_INFO.get(self.cwe_id, 'Unknown')
        hints = ', '.join(CWE_SINK_HINTS.get(self.cwe_id, []))
        examples = self._format_examples()
        prompt = self._render_message(
            cwe_name=cwe_name,
            hints=hints,
            examples=examples,
            source_code=self.source_code,
            ast_text=self.ast_text,
            cfg_text=self.cfg_text,
            pdg_text=self.pdg_text,
        )
        if len(prompt) <= self.max_prompt_chars:
            return prompt

        examples = 'No examples included because the input representation is already near the prompt budget.'
        fixed_prompt = self._render_message(
            cwe_name=cwe_name,
            hints=hints,
            examples=examples,
            source_code='',
            ast_text='',
            cfg_text='',
            pdg_text='',
        )
        remaining = max(self.max_prompt_chars - len(fixed_prompt), 1200)
        source_budget = min(len(self.source_code), max(1500, remaining // 4))
        graph_budget = max((remaining - source_budget) // 3, 800)
        return self._render_message(
            cwe_name=cwe_name,
            hints=hints,
            examples=examples,
            source_code=self._clip(self.source_code, source_budget, 'source code'),
            ast_text=self._clip(self.ast_text, graph_budget, 'AST'),
            cfg_text=self._clip(self.cfg_text, graph_budget, 'CFG'),
            pdg_text=self._clip(self.pdg_text, graph_budget, 'PDG'),
        )

    def _render_message(self, cwe_name: str, hints: str, examples: str, source_code: str, ast_text: str, cfg_text: str, pdg_text: str) -> str:
        return f"""Analyze the following C/C++ code for potential issues related to {self.cwe_id} ({cwe_name}).

## Task
Review the code structure and data flows to identify if issues exist for {self.cwe_id} ({cwe_name}). Focus on the target CWE only.

## Input Code
```c
{source_code}
```

## Program Representations
AST lists code structure by source line. CFG dependencies describe execution order. PDG dependencies describe data/control flow; DDG means data dependence and CDG means control dependence.

### AST
{ast_text}

### CFG
{cfg_text}

### PDG
{pdg_text}

## Few-Shot Examples
{examples}

## Chain-of-Thought Checklist
Use the following reasoning steps internally and summarize the evidence in JSON:
1. Identify Sink: find dangerous operations for {self.cwe_id}. Look for: {hints}.
2. Trace Source: use PDG/DDG edges to find where sink inputs originate.
3. Check Validation: look for bounds checks, null checks, size checks, or pointer state updates before the sink.
4. Analyze Flow: use CFG/CDG evidence to decide whether validation always guards the sink.
5. Determine: classify as VULNERABLE or SAFE and assign confidence.

## Output Format
Return only valid JSON with this schema:
{{
  "reasoning": {{
    "sink_identified": "line and operation",
    "data_source": "origin of dangerous data or pointer",
    "validation_present": true,
    "control_flow_analysis": "whether validation guards the sink",
    "pdg_dependencies": ["relevant DDG/CDG evidence"]
  }},
  "conclusion": "VULNERABLE or SAFE",
  "confidence": 0.0,
  "cwe_mapping": "{self.cwe_id}",
  "explanation": "brief explanation"
}}"""

    def _clip(self, text: str, budget: int, label: str) -> str:
        if len(text) <= budget:
            return text
        marker = f'\n...[{label} truncated to fit prompt budget]'
        return text[:max(budget - len(marker), 0)] + marker

    def _format_examples(self) -> str:
        if not self.few_shot_examples:
            return 'No examples included because the input representation is already near the prompt budget.'

        blocks = []
        for idx, example in enumerate(self.few_shot_examples, 1):
            blocks.append(
                f"""### Example {idx} ({example['label']})
```c
{example['source_code']}
```
Reasoning:
{example['cot_reasoning']}
Label: {example['label']}"""
            )
        return '\n\n'.join(blocks)


class PromptGenerator:
    """Generate LLM prompts with dynamic few-shot budgeting."""

    def __init__(self, few_shot_path: str = None, max_prompt_chars: int = 32000, dynamic_few_shot: bool = True):
        if few_shot_path is None:
            few_shot_path = Path(__file__).parent / 'few_shot_examples.json'
        self.few_shot_path = few_shot_path
        self.max_prompt_chars = max_prompt_chars
        self.dynamic_few_shot = dynamic_few_shot
        self.examples = self._load_examples()

    def _load_examples(self) -> Dict:
        try:
            with open(self.few_shot_path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {'examples': []}

    def get_examples_for_cwe(self, cwe_id: str) -> Optional[Dict]:
        for example in self.examples.get('examples', []):
            if example['cwe_id'] == cwe_id:
                return example
        return None

    def generate_prompt(self, cwe_id: str, source_code: str, ast_text: str = '', cfg_text: str = '', pdg_text: str = '') -> VulnerabilityPrompt:
        few_shot_examples = self.select_few_shot_examples(cwe_id, source_code, ast_text, cfg_text, pdg_text)
        return VulnerabilityPrompt(
            cwe_id=cwe_id,
            source_code=source_code,
            ast_text=ast_text,
            cfg_text=cfg_text,
            pdg_text=pdg_text,
            few_shot_examples=few_shot_examples,
            max_prompt_chars=self.max_prompt_chars,
        )

    def select_few_shot_examples(self, cwe_id: str, source_code: str, ast_text: str, cfg_text: str, pdg_text: str) -> List[Dict]:
        cwe_examples = self.get_examples_for_cwe(cwe_id)
        if cwe_examples is None:
            cwe_examples = self.examples.get('examples', [None])[0]
        if not cwe_examples:
            return []

        candidates = []
        if 'vulnerable' in cwe_examples:
            candidates.append(cwe_examples['vulnerable'])
        if 'safe' in cwe_examples:
            candidates.append(cwe_examples['safe'])
        if not candidates:
            return []
        if not self.dynamic_few_shot:
            return candidates

        base_chars = len(source_code) + len(ast_text) + len(cfg_text) + len(pdg_text) + 3500
        remaining = self.max_prompt_chars - base_chars
        selected = []
        for candidate in candidates:
            candidate_chars = len(candidate.get('source_code', '')) + len(candidate.get('cot_reasoning', '')) + 250
            if remaining >= candidate_chars:
                selected.append(candidate)
                remaining -= candidate_chars
        return selected


def _read_optional(path):
    return Path(path).read_text() if path else ''


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate LLM prompts')
    parser.add_argument('--cwe', default='CWE-190', choices=list(CWE_INFO.keys()))
    parser.add_argument('--source', help='Source code file')
    parser.add_argument('--ast', help='AST text file')
    parser.add_argument('--cfg', help='CFG text file')
    parser.add_argument('--pdg', help='PDG text file')
    parser.add_argument('--max-prompt-chars', type=int, default=32000)
    parser.add_argument('--no-dynamic-few-shot', action='store_true')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()

    generator = PromptGenerator(
        max_prompt_chars=args.max_prompt_chars,
        dynamic_few_shot=not args.no_dynamic_few_shot,
    )
    prompt = generator.generate_prompt(
        cwe_id=args.cwe,
        source_code=_read_optional(args.source),
        ast_text=_read_optional(args.ast),
        cfg_text=_read_optional(args.cfg),
        pdg_text=_read_optional(args.pdg),
    ).to_message()

    if args.output:
        Path(args.output).write_text(prompt)
        print(f'Prompt written to {args.output} ({len(prompt)} chars)')
    else:
        print(prompt)


if __name__ == '__main__':
    main()
