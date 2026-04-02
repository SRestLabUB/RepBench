#!/usr/bin/env python3

import json
import os
import shutil
import subprocess

cwes = {'CWE-121', 'CWE-122', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416'}
files = ['primevul_test_paired', 'primevul_train_paired', 'primevul_valid_paired']
path = '../data/'

data = []
for file in files:
    with open(path + 'unfiltered/primevul/' + file + '.jsonl') as f:
        for line in f:
            line_json = json.loads(line)
            if line_json['cwe'] and len(line_json['cwe']) > 0:
                if line_json['cwe'][0] in cwes:
                   data.append(line_json)

file_info = []
with open (path + 'unfiltered/primevul/file_info.json', 'r') as f:
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
    metadata['function_start'] = file_info[func_hash]['start_line']
    metadata['function_end'] = file_info[func_hash]['end_line']

    github_url = metadata['project_url'] + '.git'
    source_file = file_info[func_hash]['local_file_path']
    project_dir = path + 'filtered/primevul/' + name
    func_dir = project_dir + '/' + metadata['cwe'] + '/vunerable_funcs/' + func_hash

    if not metadata['project_url'] or not file_info[func_hash]['local_file_path']:
        continue

    if not os.path.exists(project_dir):
        os.makedirs(project_dir)
        print('Cloning... ' + github_url)
        subprocess.run(['git', 'clone', '--quiet', '--depth', '1', github_url, project_dir + '/project_src'])

    if not os.path.exists(func_dir):
        try:
            # Some source_file paths are not actually in the 'file_contents/' for some reason
            os.makedirs(func_dir)
            shutil.copy(path + 'unfiltered/primevul/' + source_file, func_dir)
        except:
            shutil.rmtree(func_dir)
            continue
        with open(func_dir + '/metadata.json', 'w') as f:
            json.dump(metadata, f, indent=4)
