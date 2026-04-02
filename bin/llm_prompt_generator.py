#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

CWE_INFO = {'CWE-121': 'Stack-based Buffer Overflow', 'CWE-122': 'Heap-based Buffer Overflow', 'CWE-190': 'Integer Overflow', 'CWE-191': 'Integer Underflow', 'CWE-415': 'Double Free', 'CWE-416': 'Use After Free'}
CWE_SINK_HINTS = {'CWE-121': ['memcpy', 'strcpy'], 'CWE-122': ['memcpy', 'malloc'], 'CWE-190': ['addition', '+', 'RAND32'], 'CWE-191': ['subtraction', '-', 'RAND32'], 'CWE-415': ['free'], 'CWE-416': ['free', 'malloc']}

@dataclass
class VulnerabilityPrompt:
    cwe_id: str
    source_code: str
    ast_text: str
    cfg_text: str
    pdg_text: str
    few_shot_examples: List[Dict]
    def to_message(self) -> str:
        ex = self.few_shot_examples[0] if self.few_shot_examples else None
        vuln_code = ex['vulnerable']['source_code'] if ex and 'vulnerable' in ex else ''
        vuln_cot = ex['vulnerable']['cot_reasoning'] if ex and 'vulnerable' in ex else ''
        vuln_label = ex['vulnerable']['label'] if ex and 'vulnerable' in ex else ''
        safe_code = ex['safe']['source_code'] if ex and 'safe' in ex else ''
        safe_cot = ex['safe']['cot_reasoning'] if ex and 'safe' in ex else ''
        safe_label = ex['safe']['label'] if ex and 'safe' in ex else ''
        hints = ', '.join(CWE_SINK_HINTS.get(self.cwe_id, []))
        cwe_name = CWE_INFO.get(self.cwe_id, 'Unknown')
        return f'You are a vulnerability detection expert analyzing C/C++ code for {self.cwe_id} ({cwe_name}). Task: Determine if the code contains a {cwe_name}. Input Code: {self.source_code}. AST: {self.ast_text}. CFG: {self.cfg_text}. PDG: {self.pdg_text}. Few-Shot Examples: VULNERABLE: {vuln_code} Reasoning: {vuln_cot} Label: {vuln_label}. SAFE: {safe_code} Reasoning: {safe_cot} Label: {safe_label}. Instructions: 1. Identify Sink (look for: {hints}). 2. Trace Source. 3. Check Validation. 4. Analyze Flow. 5. Determine VULNERABLE or SAFE. Output JSON with reasoning, conclusion, confidence, cwe_mapping, explanation.'

class PromptGenerator:
    def __init__(self, few_shot_path: str = None):
        if few_shot_path is None: few_shot_path = Path(__file__).parent / 'few_shot_examples.json'
        self.few_shot_path = few_shot_path
        self.examples = self._load_examples()
    def _load_examples(self) -> Dict:
        try:
            with open(self.few_shot_path) as f: return json.load(f)
        except FileNotFoundError: return {'examples': []}
    def get_examples_for_cwe(self, cwe_id: str) -> Optional[Dict]:
        for ex in self.examples.get('examples', []):
            if ex['cwe_id'] == cwe_id: return ex
        return None
    def generate_prompt(self, cwe_id: str, source_code: str, ast_text: str = '', cfg_text: str = '', pdg_text: str = '') -> VulnerabilityPrompt:
        examples = self.get_examples_for_cwe(cwe_id)
        if examples is None: examples = self.examples['examples'][0] if self.examples['examples'] else None
        return VulnerabilityPrompt(cwe_id=cwe_id, source_code=source_code, ast_text=ast_text, cfg_text=cfg_text, pdg_text=pdg_text, few_shot_examples=[examples] if examples else [])

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate LLM prompts')
    parser.add_argument('--cwe', default='CWE-190', choices=list(CWE_INFO.keys()))
    parser.add_argument('--source', help='Source code file')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()
    generator = PromptGenerator()
    source_code = open(args.source).read() if args.source else ''
    prompt = generator.generate_prompt(cwe_id=args.cwe, source_code=source_code)
    if args.output:
        with open(args.output, 'w') as f: f.write(prompt.to_message())
        print(f'Prompt written to {args.output}')
    else: print(prompt.to_message())

if __name__ == '__main__': main()
