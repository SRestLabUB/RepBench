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

        filename = metadata['project_file_path'].split("/")[-1]

        for directory in dirs:
            if 'epdg' in directory:
                matched_epdg = f"{root}/{directory}"
                subprocess.run(f" rsync -aR {matched_epdg} {args.output}", shell=True)
                print(f"Copied matched ePDG file {matched_epdg}")
