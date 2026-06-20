#!/usr/bin/env python3
"""Complete End-to-End Demo: DOT -> Text -> CoT Prompt -> LLM -> Result"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dot_converter import convert_file
from llm_prompt_generator import PromptGenerator
from llm_client import LLMClient
from project_paths import PROJECT_ROOT

DATA_ROOT = PROJECT_ROOT / "Joern_llm_implement"
DOT_FILE = DATA_ROOT / "juliet_representations_real/CWE_190/ast/CWE190_Integer_Overflow__char_rand_add_01.ast.dot"
CFG_FILE = DATA_ROOT / "juliet_representations_real/CWE_190/cfg/CWE190_Integer_Overflow__char_rand_add_01.cfg.dot"
PDG_FILE = DATA_ROOT / "juliet_representations_real/CWE_190/pdg/CWE190_Integer_Overflow__char_rand_add_01.pdg.dot"
SOURCE_FILE = DATA_ROOT / "juliet-test-suite-for-c-cplusplus-v1-3/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_rand_add_01.c"
CWE_ID = "CWE-190"
MODEL = "qwen"

def main():
    parser = argparse.ArgumentParser(description="Run the DOT-to-LLM demonstration pipeline")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--dry-run", action="store_true", help="Generate the prompt without calling an API")
    args = parser.parse_args()

    print("=" * 70)
    print("PIPELINE: Joern DOT -> LLM Vulnerability Detection")
    print("=" * 70)
    
    # Step 1
    print("\nSTEP 1: Convert DOT to Text")
    ast_text = convert_file(DOT_FILE, "text") if Path(DOT_FILE).exists() else "N/A"
    cfg_text = convert_file(CFG_FILE, "text") if Path(CFG_FILE).exists() else "N/A"
    pdg_text = convert_file(PDG_FILE, "text") if Path(PDG_FILE).exists() else "N/A"
    print(f"AST: {len(ast_text)} chars, CFG: {len(cfg_text)} chars, PDG: {len(pdg_text)} chars")
    
    # Step 2
    print("\nSTEP 2: Generate CoT Prompt")
    source_code = open(SOURCE_FILE).read() if Path(SOURCE_FILE).exists() else ""
    generator = PromptGenerator()
    prompt = generator.generate_prompt(CWE_ID, source_code, ast_text, cfg_text, pdg_text)
    full_prompt = prompt.to_message()
    print(f"Prompt: {len(full_prompt)} chars")
    
    with open("generated_prompt.txt", "w") as f:
        f.write(full_prompt)
    print("Saved to: generated_prompt.txt")

    if args.dry_run:
        print("Dry run complete; API call skipped.")
        return
    
    # Step 3
    print("\nSTEP 3: Call LLM API")
    client = LLMClient(model=args.model)
    print(f"Testing connection to {client.model}...")
    if not client.test_connection():
        print("Connection failed!")
        return
    print("Connection OK, sending prompt...")
    
    response = client.call(full_prompt)
    
    # Step 4
    print("\nSTEP 4: Results")
    print("=" * 60)
    if response.success:
        print(f"Conclusion: {response.conclusion}")
        print(f"Confidence: {response.confidence:.1%}")
        print(f"Explanation: {response.explanation[:200]}")
        
        result = {
            "cwe_id": CWE_ID, "model": response.model_used,
            "conclusion": response.conclusion, "confidence": response.confidence,
            "reasoning": response.reasoning, "explanation": response.explanation
        }
        with open("detection_result.json", "w") as f:
            json.dump(result, f, indent=2)
        print("Saved to: detection_result.json")
    else:
        print(f"Failed: {response.error}")
    print("=" * 60)

if __name__ == "__main__":
    main()
