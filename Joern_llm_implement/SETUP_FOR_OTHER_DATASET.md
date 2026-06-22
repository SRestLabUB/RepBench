# How to Use the Pipeline with Other Datasets

## Target Audience

This document is intended for researchers who want to apply this project to other vulnerability detection datasets.

---

## Part 1: Environment Setup

### 1. Python Environment

Requirement: Python 3.10+ (Python 3.11 recommended)

```bash
# Check the Python version
python3 --version

# Install Python dependencies
python -m pip install -r ../requirements.txt
```

### 2. Joern Installation

Find the joern-install.sh file in the repository.

```bash
chmod +x ./joern-install.sh
sudo ./joern-install.sh
joern
```

After that, you should be able to see the Joern version. Type "exit" to leave the Joern shell.

### 3. LLM API Configuration

Do not edit credentials into `llm_client.py`. Configure an OpenAI-compatible provider through environment variables:

```bash
export LLM_API_KEY="your-key"
export LLM_API_BASE_URL="https://provider.example/v1"
```

The default model alias is `qwen` (`qwen3.6-plus`). A provider model identifier can also be passed with `--model`. See `README.md` for PowerShell syntax and optional runtime settings.

---

## Part 2: Dataset Adaptation

### 1. Required Directory Structure

```text
your_dataset/
+-- testcases/
|   +-- CWE121_Stack_Based_Buffer_Overflow/
|   |   +-- s01/
|   |   |   +-- test_case_01.c
|   |   +-- ...
|   +-- CWE190_Integer_Overflow/
|   +-- ...
+-- representations/
```

### 2. Configure Dataset Paths

Do not edit absolute paths in Python files. Point the pipeline at an external Juliet-style dataset and representation directory with:

```bash
export CSE713_JULIET_BASE="/path/to/your/juliet-suite"
export CSE713_REPRESENTATIONS_BASE="/path/to/your/representations"
```

`CSE713_ROOT` is normally unnecessary; it is only a fallback when automatic repository discovery cannot see `README.md` and `Joern_llm_implement/`.

### 3. CWE Type Mapping

Edit joern_http_client.py (lines 15-22) and vulnerability_detector.py (lines 22-29):

```python
CWE_DIR_MAP = {
    "CWE-121": "CWE121_Stack_Based_Buffer_Overflow",
    "CWE-122": "CWE122_Heap_Based_Buffer_Overflow",
    "CWE-190": "CWE190_Integer_Overflow",
    "CWE-191": "CWE191_Integer_Underflow",
    "CWE-415": "CWE415_Double_Free",
    "CWE-416": "CWE416_Use_After_Free",
    "CWE-XXX": "CWEXXX_Your_Vulnerability_Type",
}
```

---

## Part 3: Few-Shot Configuration

### 1. Create High-Quality Few-Shot Examples

Edit few_shot_examples.json and add the following for each CWE:

```json
{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Your Vulnerability Type",
  "vulnerable": {
    "source_code": "...",
    "linearized_repr": "...",
    "cot_reasoning": "Step 1 - ... Step 5 - ...",
    "label": "VULNERABLE"
  },
  "safe": {
    "source_code": "...",
    "cot_reasoning": "...",
    "label": "SAFE"
  }
}
```

**Key Points**:
- Keep code snippets short, usually 10-20 lines
- Include the key sink and source operations
- Provide detailed chain-of-thought reasoning with explanation in each step
- Supply both vulnerable and safe examples

### 2. Configure Sink Hints

Edit llm_prompt_generator.py (lines 22-28) and dot_compressor.py (lines 18-24):

```python
CWE_SINK_HINTS = {
    'CWE-121': ['memcpy', 'strcpy', 'sprintf', 'strcat', 'gets', 'scanf'],
    'CWE-122': ['malloc', 'realloc', 'memcpy', 'strcpy', 'heap'],
    'CWE-190': ['addition', '+', 'increment', '++', 'RAND32', 'rand', 'MAX'],
    'CWE-191': ['subtraction', '-', 'decrement', '--', 'RAND32', 'rand'],
    'CWE-415': ['free', 'malloc', 'NULL'],
    'CWE-416': ['free', 'malloc', 'calloc', 'realloc', 'use'],
    'CWE-XXX': ['dangerous_func1', 'dangerous_func2'],
}
```

**Sink Hint Selection Principles**:
- Choose common dangerous function names (memcpy, free)
- Choose operators (+, -, ++, --)
- Choose characteristic variable names (RAND32, MAX)

### 3. Dynamic Few-Shot Selection

The pipeline automatically selects few-shot examples based on prompt budget:

```python
detector = VulnerabilityDetector(
    max_prompt_chars=12000,      # Prompt budget
    dynamic_few_shot=True,       # Enable dynamic selection
)
```

**Mechanism**:
- If prompt size > budget, few-shot examples are dropped
- Priority: Task description > Core representations > Few-shot examples
- This ensures core representations are preserved

### 4. Few-Shot Quality Check

```bash
# Check the number of few-shot examples
python3 -c "import json; d=json.load(open('few_shot_examples.json')); print(len(d['examples']))"

# Check the CWE ID list
python3 -c "import json; d=json.load(open('few_shot_examples.json')); print([e['cwe_id'] for e in d['examples']])"
```

---

## Part 4: DOT Compression

**Enable Compression** (vulnerability_detector.py, lines 46-51):

```python
detector = VulnerabilityDetector(
    compress_representations=True,   # Enable compression
    max_prompt_chars=12000,
)
```

**Compression Rules** (dot_compressor.py):
- Drop graphs: main, RAND32, printLine, helper functions
- Drop nodes: TYPE_REF, METHOD_RETURN, MODIFIER
- Keep nodes: IDENTIFIER, LITERAL, BLOCK (if has CWE evidence)
- **Result**: 10-30% size reduction, target ~12k chars

**Note**: Only conservative level is implemented. Aggressive compression may lose vulnerability evidence.

---

## Part 5: Chain-of-Thought Process

The LLM follows a 5-step CoT reasoning process:

1. **Identify Sink**: Find dangerous operations (memcpy, free, +, etc.)
2. **Trace Source**: Track data origins via PDG edges
3. **Check Validation**: Look for bounds/null checks
4. **Analyze Control Flow**: Use CFG to verify validation guards
5. **Determine Conclusion**: VULNERABLE or SAFE

---

## Part 6: Run the Pipeline

### 1. Generate Joern Representations

Single-file:

```bash
python3 joern_http_client.py --cwe CWE-190 --file your_test_case_01.c
```

Batch generation (recommended):

```bash
python3 joern_http_client.py --cwe CWE-190 --batch --limit 10
```

Notes:
- Joern server auto-starts at http://localhost:8080
- Server reused in batch mode (faster)
- Each file takes about 30-60 seconds

### 2. Verify DOT File Generation

```bash
ls representations/CWE_190/ast/*.ast.dot
ls representations/CWE_190/cfg/*.cfg.dot
ls representations/CWE_190/pdg/*.pdg.dot
```

### 3. Run Vulnerability Detection

Option 1: Single-file demo

```bash
python3 demo_llm_pipeline.py
```

Option 2: Batch validation

```bash
python3 validate_llm_samples.py --limit 5 --model qwen --max-prompt-chars 12000 --output validation_results.json
```

Option 3: Dry-run (no LLM calls)

```bash
python3 validate_llm_samples.py --limit 5 --dry-run --output validation_dry_run.json
```

### 4. Review Results

```bash
cat validation_results.json
```

**Reference Results** (validation_results_small.json):
- 15 files tested (3 per CWE)
- 100% success rate
- Confidence range: 0.95-1.0

---

## Part 7: Parameter Tuning

### 1. Prompt Budget Adjustment

Default: 12000 chars. Recommended range: 8000-20000 chars

```bash
python3 validate_llm_samples.py --max-prompt-chars 8000
python3 validate_llm_samples.py --max-prompt-chars 18000
```

**Effects**:
- Smaller budget: few-shot examples may be truncated
- Larger budget: more graph detail preserved, higher API cost

### 2. Model Selection

```bash
python3 validate_llm_samples.py --model qwen
python3 validate_llm_samples.py --model <provider-model-id>
```

### 3. Temperature Adjustment

Pass a consistent value to `LLMClient.call` when writing a custom runner:

```python
temperature: float = 0.2  # Default 0.2, range 0.0-0.5
```

**Why 0.2**: It provides mostly repeatable results while retaining limited sampling variation.

---

## Part 8: Troubleshooting

### Joern server fails to start

```bash
joern --version
netstat -tlnp | grep 8080
joern --server
```

### DOT file is empty

```bash
cat representations/CWE_190/ast/*.ast.dot | head -20
```

### API call fails

```bash
python3 llm_client.py --test --model qwen
echo $LLM_API_KEY
```

### Prompt too long

```bash
python3 validate_llm_samples.py --max-prompt-chars 8000
```

### Few-shot missing

- Check few_shot_examples.json exists
- Check the CWE ID is present
- Add missing examples

### Result parsing fails

- Check LLM output is valid JSON
- Lower temperature to 0.1
- Check response_format configuration

---

## Part 9: Full Run Example

### Scenario: Run the full pipeline for a new dataset CWE-XXX

Step 1: Prepare the environment

```bash
python -m pip install -r ../requirements.txt
export PATH=$HOME/joern:$PATH
export LLM_API_KEY="your-key"
export LLM_API_BASE_URL="https://provider.example/v1"
```

Step 2: Configure paths with `CSE713_JULIET_BASE` and `CSE713_REPRESENTATIONS_BASE`. Only edit the CWE mappings and prompt/compression hints when adding a new CWE category.

Step 3: Create few-shot examples for CWE-XXX

Step 4: Generate representations

```bash
python3 joern_http_client.py --cwe CWE-XXX --batch --limit 10
```

Step 5: Verify generation

```bash
ls representations/CWE_XXX/ast/*.ast.dot | wc -l
```

Step 6: Dry-run test

```bash
python3 validate_llm_samples.py --limit 5 --dry-run
```

Step 7: Run detection

```bash
python3 validate_llm_samples.py --limit 10 --model qwen --output results_cwe_xxx.json
```

Step 8: Analyze results

---

## Part 10: FAQ

### Q1: Can I skip few-shot examples?

Yes, but quality will drop. Set dynamic_few_shot=False.

### Q2: Can I use other programming languages?

In theory yes (Java, Python), but ensure Joern supports the language.

### Q3: Can I add more CWE types?

Yes. Add CWE_DIR_MAP mapping, CWE_SINK_HINTS entry, and few-shot examples.

### Q4: Why are compatibility headers and a short delay used?

They provide request tracing and reduce accidental rate-limit bursts. They do not bypass provider authentication or usage policies.

### Q5: Why is temperature 0.2?

A low value improves repeatability while retaining limited sampling variation. Use the same value across variants for a controlled comparison.

### Q6: What is response_format?

Forces LLM to output JSON: response_format = {"type": "json_object"}

---

## Appendix A: File Function Quick Reference

| File | Main Function | When to Modify |
|------|---------------|----------------|
| llm_client.py | LLM API calls | Model or request behavior; use environment variables for credentials/URL |
| llm_prompt_generator.py | Prompt generation | Sink hints, CoT process |
| vulnerability_detector.py | Pipeline entry | CWE mapping and budget; use environment variables for paths |
| dot_converter.py | DOT parsing | Usually not modified |
| dot_compressor.py | DOT compression | Sink hints synchronization |
| joern_http_client.py | Joern client | CWE mapping and server behavior; use environment variables for paths |
| few_shot_examples.json | Few-shot data | Add new CWE examples |
| validation_results_small.json | Reference results | Review expected output |

---

## Appendix B: Configuration Locations

| Configuration item | Location |
|-------------------|----------|
| API base URL | `LLM_API_BASE_URL` environment variable |
| API key | `LLM_API_KEY` environment variable |
| Model aliases and request defaults | `llm_client.py` |
| CWE guidance and sink hints | `llm_prompt_generator.py` |
| Dataset paths | `CSE713_JULIET_BASE`, `CSE713_REPRESENTATIONS_BASE` |
| Project root fallback | `CSE713_ROOT` |
| Java fallback | `JOERN_JAVA_HOME` |

---

## Appendix C: Supported CWEs

| CWE ID | Name | Sink Hints |
|--------|------|------------|
| CWE-121 | Stack-based Buffer Overflow | memcpy, strcpy, sprintf, strcat, gets, scanf |
| CWE-122 | Heap-based Buffer Overflow | malloc, realloc, memcpy, strcpy, heap |
| CWE-190 | Integer Overflow | +, ++, RAND32, rand, MAX |
| CWE-191 | Integer Underflow | -, --, RAND32, rand |
| CWE-415 | Double Free | free, malloc, NULL |
| CWE-416 | Use After Free | free, malloc, calloc, realloc |

---

## Appendix D: Contact and Support

If you have questions:
1. Check the troubleshooting section in this document
2. Check `README.md` for installation, runtime configuration, and the standard pipeline
3. Check README.md for project overview

---

**Document Version**: 2.0
**Last Updated**: 2026-04-29
**Author**: CSE713_as_jt_vulnerability_analysis Team
