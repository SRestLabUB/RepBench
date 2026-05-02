#!/usr/bin/env python3
import json
import sys
import pandas as pd
import argparse

parser = argparse.ArgumentParser(description='Decompose an ePDG by function.')

parser.add_argument('-n', '--nodes', help='The nodes of the ePDG')
parser.add_argument('-l', '--links', help='The links of the ePDG')
parser.add_argument('-o', '--output', default='.', help='Output path')
parser.add_argument('-s', '--start', help='Start line of vulnerable code lines')
parser.add_argument('-e', '--end', help='End line of vulerable code lines')
args = parser.parse_args()

filtered_nodes = []
with open(args.nodes, 'r') as f:
    filtered_nodes = json.load(f)

filtered_links = []
with open(args.links, 'r') as f:
    filtered_links = json.load(f)

nodes = pd.DataFrame(filtered_nodes)
links = pd.DataFrame(filtered_links)
output = args.output

merged = pd.merge(nodes, links, left_on='id', right_on='source_id', how='inner')
merged.to_json('merged_epdg.jsonl', orient='records', lines=True)

groupby_col = 'filename'
# Just grab the binary
merged['filename'] = merged['filename'].apply(lambda file: file.rsplit('/')[-1])

if args.start and args.end:
    merged = merged[merged['line_number'].between(int(args.start), int(args.end))]

grouped = {name: group for name, group in merged.groupby(groupby_col)}
for df_name, df in grouped.items():
    try:
        binary = df_name.split(".")[-2]
        if args.start and args.end:
            df.to_json(f'{output}/{binary}_function_only.jsonl', orient='records', lines=True)
        else:
            df.to_json(f'{output}/{binary}.jsonl', orient='records', lines=True)
    except:
        continue
