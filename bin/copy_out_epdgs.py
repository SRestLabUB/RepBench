#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import argparse
import re

parser = argparse.ArgumentParser(description='Generate ePDGs for testcases')

parser.add_argument('-i', '--input', required=True, help='Testcase input directory')
parser.add_argument('-o', '--output', required=True, help='Testcase input directory')
args = parser.parse_args()

for root, dirs, files in os.walk(args.input):
    if 'cse713' in root.split("/")[-1]:
        # Read metadata file to grab CWE
        metadata = {}
        with open(root + '/metadata.json', 'r') as f:
            metadata = json.load(f)

        cwe_num = metadata['cwe'].split("-")[-1]
        filename = metadata['project_file_path'].split("/")[-1]

        # Keep only ePDG that matches function within `files`
        for epdg in files:
            epdg_comparision_name = epdg
            suffix = "_function_only"
            if epdg_comparision_name.endswith(suffix):
                epdg_comparision_name = epdg_comparision_name[:-len(suffix)]
            if epdg_comparision_name in filename:
                matched_epdg = f"{root}/{epdg}"
                subprocess.run(f"rsync -aR {matched_epdg} {args.output}", shell=True)
                subprocess.run(f"mkdir {args.output}/{root}/egpd", shell=True)
                subprocess.run(f"mv {args.output}/{root}/{epdg} {args.output}/{root}/egpd", shell=True)
                print(f"Copied matched ePDG file {epdg}")
