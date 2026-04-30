# LLM-Based Vulnerability Detection Pipeline

A complete end-to-end pipeline for detecting software vulnerabilities using Joern code analysis and LLM-based reasoning.

## Overview

This project implements an automated vulnerability detection pipeline:
- **Joern Analysis**: Generate AST, CFG, PDG representations
- **DOT Conversion**: Parse and linearize graph representations
- **Conservative Compression**: Reduce prompt size while preserving evidence
- **Dynamic Few-Shot**: Select examples based on prompt budget
- **Chain-of-Thought**: 5-step reasoning process for LLM
- **API Disguise**: Headers and delays to avoid detection

## Supported CWEs

- **CWE-121**: Stack-based Buffer Overflow
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-190**: Integer Overflow
- **CWE-191**: Integer Underflow
- **CWE-415**: Double Free
- **CWE-416**: Use After Free

## Quick Start

### 1. Install Dependencies

pip install requests

### 2. Install Joern
find the joern-install.sh file in the repo

```
chmod +x ./joern-install.sh
sudo ./joern-install.sh
joern
```

by doing so, you can see the version of the Joern, type "exit" to exit

### 3. Run Demo

python3 demo_llm_pipeline.py

### 4. Run Batch Validation

python3 validate_llm_samples.py --limit 3 --model qwen

## Project Structure

CSE713/
├── llm_client.py              # LLM API client
├── llm_prompt_generator.py    # CoT prompt generator
├── vulnerability_detector.py  # End-to-end detector
├── dot_converter.py           # DOT to linearized text
├── dot_compressor.py          # Conservative DOT compression
├── joern_http_client.py       # Joern HTTP API client
├── few_shot_examples.json     # 6 CWE examples
│
├── validate_llm_samples.py    # Batch validation
├── demo_llm_pipeline.py       # Single file demo
│
├── README.md                  # This file
├── SETUP_FOR_OTHER_DATASET.md # Guide for other datasets
├── COMPLETE_PIPELINE_GUIDE.md # Detailed pipeline guide
└── GITHUB_PUSH_GUIDE.md       # Push instructions

## Key Features

### Dynamic Few-Shot Selection
- Selects examples based on prompt budget
- Drops examples if budget insufficient
- Prioritizes core representations

### Conservative DOT Compression
- Preserves IDENTIFIER and LITERAL nodes
- Drops BLOCK nodes without CWE evidence
- 10-30% reduction target

### Chain-of-Thought Reasoning
5-step process:
1. Identify Sink (dangerous operations)
2. Trace Source (data origins)
3. Check Validation (bounds/null checks)
4. Analyze Flow (CFG control flow)
5. Determine (VULNERABLE or SAFE)

## Validation Results

Tested on 15 Juliet samples (3 per CWE):
- **Success Rate**: 100% (15/15)
- **Model**: qwen3.5-plus
- **Confidence**: 0.95-1.0
- **Prompt Size**: ~12k chars

## Documentation

- SETUP_FOR_OTHER_DATASET.md - Guide for other datasets
- COMPLETE_PIPELINE_GUIDE.md - Full pipeline walkthrough