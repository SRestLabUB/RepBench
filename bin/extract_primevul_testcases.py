#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import argparse
import re

parser = argparse.ArgumentParser(description='Parse and preprocess PrimeVul files into different projects based on the supported CWEs.')

parser.add_argument('-i', '--input', help='PrimeVul data directory')
parser.add_argument('-o', '--output', default='.', help='Output path')
args = parser.parse_args()

cwes = {'CWE-121', 'CWE-122', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416'}
files = ['primevul_test_paired', 'primevul_train_paired', 'primevul_valid_paired']
primevul_path = args.input
output_path = args.output

approved_projects = []

with open(primevul_path + '/approved_projects.json', 'r') as f:
    approved_projects = json.load(f)

data = []
for file in files:
    with open(primevul_path + '/' + file + '.jsonl', 'r') as f:
        for line in f:
            line_json = json.loads(line)
            if line_json['cwe'] and len(line_json['cwe']) > 0:
                if line_json['cwe'][0] in cwes and line_json['project'] in approved_projects:
                   data.append(line_json)

file_info = []
with open (primevul_path + '/file_info.json', 'r') as f:
    file_info = json.load(f)

for testcase in data:
    # Create dir for testcase if not exists
    if not testcase['project'] or not testcase['func_hash']:
        continue

    name = testcase['project']
    func_hash = str(testcase['func_hash'])

    if func_hash not in file_info:
        continue

    # Create metadata file
    metadata = {}
    # Test case metadata
    metadata['cwe'] = testcase['cwe'][0]
    metadata['cve'] = testcase['cve']
    metadata['cve_desc'] = testcase['cve_desc']
    metadata['nvd_url'] = testcase['nvd_url']
    metadata['patch'] = testcase['commit_url']
    metadata['project_url'] = testcase['project_url']
    metadata['project_file_path'] = file_info[func_hash]['project_file_path']
    metadata['function_start'] = file_info[func_hash]['start_line']
    metadata['function_end'] = file_info[func_hash]['end_line']
    metadata['target'] = testcase['target']
    metadata['commit_id'] = testcase['commit_id']
    label = 'fixed' if testcase['target'] == 0 else 'vulnerable'

    github_url = metadata['project_url'] + '.git'
    source_file = file_info[func_hash]['local_file_path']
    project_dir = output_path + '/' + name
    func_dir = project_dir + '/' + metadata['cwe'] + '/' + file_info[func_hash]['file_name'] + '/' + testcase['commit_id'] + '/' + label
    # Want to find the function name so that we can match it with the ePDG later
    # in order to save space for LLM context. Graphs of even the entire file
    # can be larger than entire context window.
    #
    # Match just before first '(' and account for whitespace before '('
    func_name_match = re.search(r"(\w+)\s*\(", testcase['func'])

    if not func_name_match:
        print(f'{name}: Cannot find function name')
        print(testcase['func'])
        continue

    func_name = func_name_match.group(1)
    func_file = func_dir + '/' + func_name

    if not metadata['project_url'] or not file_info[func_hash]['local_file_path']:
        continue

    if not os.path.exists(project_dir):
        os.makedirs(project_dir)
        print('Cloning... ' + github_url)
        subprocess.run(['git', 'clone', '--quiet', github_url, project_dir + '/project_src'])

    if not os.path.exists(func_dir):
        try:
            # Some source_file paths are absent from 'file_contents/'
            os.makedirs(func_dir)
            shutil.copy(primevul_path + '/' + source_file, func_file)
            repo_dir = func_dir + '/project_src'
            os.makedirs(repo_dir)
            source = project_dir + '/project_src/.'
            subprocess.run(['rsync', '-a', '-r', source, repo_dir])
            if label == 'fixed':
                subprocess.run(['git', '-C', repo_dir, 'checkout', '--quiet', metadata['commit_id']])
            else:
                prev_commit = f"{metadata['commit_id']}~1"
                subprocess.run(['git', '-C', repo_dir, 'checkout', '--quiet', prev_commit])
        except Exception as e:
            print(f"Error: {e}")
            shutil.rmtree(func_dir)
            continue
        with open(func_dir + '/metadata.json', 'w') as f:
            json.dump(metadata, f, indent=4)
