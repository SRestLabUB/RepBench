#!/usr/bin/env python3
"""
Joern 4.0 HTTP API client for exporting AST, CFG, PDG
Uses Joern's built-in HTTP server for reliable script execution
"""

import subprocess
import requests
import json
import time
import os
import re
import argparse
from pathlib import Path

JULIET_BASE = 'juliet-test-suite-for-c-cplusplus-v1-3'
OUTPUT_BASE = 'juliet_representations_real'

CWE_DIR_MAP = {
    'CWE-121': 'CWE121_Stack_Based_Buffer_Overflow',
    'CWE-122': 'CWE122_Heap_Based_Buffer_Overflow',
    'CWE-190': 'CWE190_Integer_Overflow',
    'CWE-191': 'CWE191_Integer_Underflow',
    'CWE-415': 'CWE415_Double_Free',
    'CWE-416': 'CWE416_Use_After_Free',
}

JOERN_SERVER_URL = 'http://localhost:8080'


class JoernServer:
    """Manage Joern HTTP server process"""
    
    def __init__(self):
        self.process = None
        self.url = JOERN_SERVER_URL
    
    def start(self):
        """Start Joern server in background"""
        print("Starting Joern server...")
        self.process = subprocess.Popen(
            ['joern', '--server'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for server to be ready
        max_wait = 30
        for i in range(max_wait):
            try:
                response = requests.get(f'{self.url}/query-sync', timeout=1)
                print(f"✅ Joern server ready (took {i+1}s)")
                return True
            except:
                time.sleep(1)
        
        print(f"❌ Joern server not ready after {max_wait}s")
        return False
    
    def stop(self):
        """Stop Joern server"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            print("Joern server stopped")
    
    def query(self, query: str) -> dict:
        """Execute a query on Joern server"""
        try:
            response = requests.post(
                f'{self.url}/query-sync',
                json={'query': query},
                timeout=120
            )
            result = response.json()
            return {
                'success': result.get('success', False),
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', '')
            }
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e)}


def find_source_file(cwe_id: str, filename: str) -> str | None:
    """Find source file in Juliet directory structure"""
    cwe_dir = CWE_DIR_MAP.get(cwe_id, cwe_id.replace('-', ''))
    for subdir in ['s01', 's02', 's03', 's04', 's05', 's06', 's07']:
        path = os.path.join(JULIET_BASE, 'testcases', cwe_dir, subdir, filename)
        if os.path.exists(path):
            return path
    return None


def process_file(cwe_id: str, filename: str) -> bool:
    """Process a single file using Joern HTTP server"""
    print(f"\n{'='*70}")
    print(f"PROCESSING: {filename}")
    print(f"CWE: {cwe_id}")
    print(f"{'='*70}")
    
    # Find source file
    source_file = find_source_file(cwe_id, filename)
    if not source_file:
        print(f"❌ Source file not found: {filename}")
        return False
    
    print(f"✅ Source: {source_file}")
    
    # Setup output directory
    output_dir = os.path.join(OUTPUT_BASE, cwe_id.replace('-', '_'))
    for subdir in ['ast', 'cfg', 'pdg', 'serialized']:
        os.makedirs(os.path.join(output_dir, subdir), exist_ok=True)
    
    # Start Joern server
    server = JoernServer()
    if not server.start():
        return False
    
    try:
        # Step 1: Import code and generate CPG
        print("\n📊 Generating CPG...")
        result = server.query(f'importCode("{source_file}")')
        if 'Cpg[' in result['stdout']:
            print("✅ CPG generated")
        else:
            print(f"⚠️ CPG generation response: {result['stdout'][:200]}")
        
        # Run data flow analysis
        print("Running data flow analysis...")
        result = server.query('run.ossdataflow')
        print(f"  {result['stdout'][:200] if result['stdout'] else 'OK'}")
        
        # Step 2: Export AST using dotAst
        print("\n📤 Exporting AST...")
        result = server.query('cpg.method.dotAst.l')
        
        ast_dir = os.path.join(output_dir, 'ast')
        os.makedirs(ast_dir, exist_ok=True)
        ast_files = []
        
        if result['stdout']:
            # Parse output - it may contain multiple dot graphs
            lines = result['stdout'].strip()
            if 'digraph' in lines:
                # Write to file
                ast_file = os.path.join(ast_dir, f'{Path(filename).stem}.ast.dot')
                with open(ast_file, 'w') as f:
                    f.write(lines)
                ast_files.append(ast_file)
                print(f"✅ AST exported: {ast_file}")
            else:
                print(f"⚠️ No AST dot found")
        else:
            print(f"❌ AST export failed: {result.get('stderr', 'No output')[:200]}")
        
        # Step 3: Export CFG using dotCfg
        print("\n📤 Exporting CFG...")
        result = server.query('cpg.method.dotCfg.l')
        
        cfg_dir = os.path.join(output_dir, 'cfg')
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_files = []
        
        if result['stdout']:
            lines = result['stdout'].strip()
            if 'digraph' in lines:
                cfg_file = os.path.join(cfg_dir, f'{Path(filename).stem}.cfg.dot')
                with open(cfg_file, 'w') as f:
                    f.write(lines)
                cfg_files.append(cfg_file)
                print(f"✅ CFG exported: {cfg_file}")
            else:
                print(f"⚠️ No CFG dot found")
        else:
            print(f"❌ CFG export failed: {result.get('stderr', 'No output')[:200]}")
        
        # Step 4: Export PDG using dotPdg
        print("\n📤 Exporting PDG...")
        result = server.query('cpg.method.dotPdg.l')
        
        pdg_dir = os.path.join(output_dir, 'pdg')
        os.makedirs(pdg_dir, exist_ok=True)
        pdg_files = []
        
        if result['stdout']:
            lines = result['stdout'].strip()
            if 'digraph' in lines:
                pdg_file = os.path.join(pdg_dir, f'{Path(filename).stem}.pdg.dot')
                with open(pdg_file, 'w') as f:
                    f.write(lines)
                pdg_files.append(pdg_file)
                print(f"✅ PDG exported: {pdg_file}")
            else:
                print(f"⚠️ No PDG dot found")
        else:
            print(f"❌ PDG export failed: {result.get('stderr', 'No output')[:200]}")
        
        # Summary
        print(f"\n{'='*70}")
        print("PROCESSING COMPLETE")
        print(f"{'='*70}")
        print(f"Source:  {source_file}")
        print(f"Output:  {output_dir}")
        
        print(f"{'AST':8s}: {'✅' if ast_files else '❌'} {ast_dir}")
        print(f"{'CFG':8s}: {'✅' if cfg_files else '❌'} {cfg_dir}")
        print(f"{'PDG':8s}: {'✅' if pdg_files else '❌'} {pdg_dir}")
        
        print(f"{'='*70}")
        
        return len(ast_files) > 0 or len(cfg_files) > 0 or len(pdg_files) > 0
        
    finally:
        server.stop()


def main():
    parser = argparse.ArgumentParser(description='Joern 4.0 HTTP API pipeline')
    parser.add_argument('--cwe', default='CWE-190', choices=list(CWE_DIR_MAP.keys()))
    parser.add_argument('--file', default='CWE190_Integer_Overflow__char_rand_add_01.c')
    
    args = parser.parse_args()
    
    success = process_file(args.cwe, args.file)
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())