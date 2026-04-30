# GitHub Push 操作指南

## 一、推送前检查

### 1. 检查必须文件

ls -la llm_client.py llm_prompt_generator.py vulnerability_detector.py        dot_converter.py dot_compressor.py joern_http_client.py        few_shot_examples.json README.md SETUP_FOR_OTHER_DATASET.md

### 2. 语法检查

python3 -m py_compile llm_client.py llm_prompt_generator.py vulnerability_detector.py            dot_converter.py dot_compressor.py joern_http_client.py

### 3. Few-Shot 检查

python3 -c "import json; d=json.load(open(\"few_shot_examples.json\"));             print([e[\"cwe_id\"] for e in d[\"examples\"]])"

### 4. 清理临时文件

rm -f temp_*.py temp_*.json validation_dry_run.json
rm -rf __pycache__

---

## 二、初始化 Git

git init
git add .gitignore

---

## 三、添加文件

git add llm_client.py llm_prompt_generator.py vulnerability_detector.py        dot_converter.py dot_compressor.py joern_http_client.py        few_shot_examples.json        validate_llm_samples.py demo_llm_pipeline.py        README.md SETUP_FOR_OTHER_DATASET.md COMPLETE_PIPELINE_GUIDE.md        GITHUB_PUSH_GUIDE.md .gitignore

---

## 四、创建 Commit

git commit -m "Initial commit: LLM vulnerability detection pipeline

Features:
- Joern HTTP client for AST/CFG/PDG
- DOT converter with compression
- Dynamic Few-Shot selection
- CoT reasoning (5 steps)
- API disguise and delays

Supported CWEs: 121, 122, 190, 191, 415, 416
"

---

## 五、连接 GitHub

### 1. 创建 GitHub 仓库

访问 https://github.com/new

### 2. 连接远程

git remote add origin https://github.com/你的用户名/你的仓库.git
git branch -M main
git push -u origin main

### 3. 或使用 GitHub CLI

gh repo create 你的仓库 --public --source=. --remote=origin --push

---

## 六、交付给朋友

### 方式 1：GitHub 克隆（推荐）

git clone https://github.com/你的用户名/vulnerability-detection-pipeline.git

### 方式 2：ZIP 打包

zip -r cse713_pipeline_delivery.zip     llm_client.py llm_prompt_generator.py vulnerability_detector.py     dot_converter.py dot_compressor.py joern_http_client.py     few_shot_examples.json     validate_llm_samples.py demo_llm_pipeline.py     README.md SETUP_FOR_OTHER_DATASET.md COMPLETE_PIPELINE_GUIDE.md

---

## 七、核心文件清单（共 14 个）

llm_client.py                    # LLM API 客户端
llm_prompt_generator.py          # Prompt 生成器
vulnerability_detector.py        # 检测 Pipeline
dot_converter.py                 # DOT 转换
dot_compressor.py                # DOT 压缩
joern_http_client.py             # Joern 客户端
few_shot_examples.json           # Few-Shot 数据

validate_llm_samples.py          # 验证脚本
demo_llm_pipeline.py             # 演示脚本

README.md                        # 项目说明
SETUP_FOR_OTHER_DATASET.md       # 使用指南
COMPLETE_PIPELINE_GUIDE.md       # Pipeline 指南
GITHUB_PUSH_GUIDE.md             # 本文档
.gitignore                       # Git 配置

---

**文档版本**: 1.0
**创建日期**: 2026-04-29
