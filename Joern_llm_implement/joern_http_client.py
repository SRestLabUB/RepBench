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
import signal
import argparse
from pathlib import Path

from project_paths import PROJECT_ROOT


ROOT = PROJECT_ROOT
JULIET_BASE = os.environ.get(
    'CSE713_JULIET_BASE',
    str(ROOT / 'Joern_llm_implement' / 'juliet-test-suite-for-c-cplusplus-v1-3'),
)
OUTPUT_BASE = os.environ.get(
    'CSE713_REPRESENTATIONS_BASE',
    str(ROOT / 'Joern_llm_implement' / 'juliet_representations_real'),
)
JAVA_HOME_CANDIDATES = [
    Path('/usr/lib/jvm/java-17-openjdk-amd64'),
    Path('/usr/lib/jvm/java-21-openjdk-amd64'),
]

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
        env = os.environ.copy()
        configured_java_home = env.get('JOERN_JAVA_HOME')
        java_home = (
            Path(configured_java_home).expanduser().resolve()
            if configured_java_home
            else next((path for path in JAVA_HOME_CANDIDATES if path.exists()), None)
        )
        if java_home and java_home.exists():
            env['JAVA_HOME'] = str(java_home)
            env['PATH'] = os.pathsep.join(
                (str(java_home / 'bin'), env.get('PATH', ''))
            )
        process_options = {}
        if os.name == 'posix':
            process_options['start_new_session'] = True
        elif hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP'):
            process_options['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

        self.process = subprocess.Popen(
            ['joern', '--server'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            **process_options,
        )
        
        # Wait for server to be ready
        max_wait = 30
        for i in range(max_wait):
            if self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ''
                print(f"❌ Joern server exited early: {stderr[:500]}")
                return False
            try:
                response = requests.get(f'{self.url}/query-sync', timeout=1)
                print(f"✅ Joern server ready (took {i+1}s)")
                return True
            except:
                time.sleep(1)
        
        print(f"❌ Joern server not ready after {max_wait}s")
        return False
    
    def _signal_process(self, force=False):
        """Signal the Joern process tree where supported."""
        if os.name == 'posix':
            try:
                process_group = os.getpgid(self.process.pid)
                os.killpg(
                    process_group, signal.SIGKILL if force else signal.SIGTERM
                )
                return
            except ProcessLookupError:
                return
            except OSError:
                # Fall back when process-group operations are unavailable.
                pass
        try:
            self.process.kill() if force else self.process.terminate()
        except ProcessLookupError:
            pass

    def stop(self):
        """Stop Joern server."""
        if not self.process:
            return
        self._signal_process()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._signal_process(force=True)
            self.process.wait(timeout=5)
        finally:
            self.process = None
        print("Joern server stopped")
    
    def query(self, query: str, timeout: float = 120) -> dict:
        """Execute a query on Joern server"""
        try:
            response = requests.post(
                f'{self.url}/query-sync',
                json={'query': query},
                timeout=timeout
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
    root_path = os.path.join(JULIET_BASE, 'testcases', cwe_dir, filename)
    if os.path.exists(root_path):
        return root_path
    for subdir in ['s01', 's02', 's03', 's04', 's05', 's06', 's07']:
        path = os.path.join(JULIET_BASE, 'testcases', cwe_dir, subdir, filename)
        if os.path.exists(path):
            return path
    return None


def list_source_files(cwe_id: str, limit: int | None = None) -> list[Path]:
    """List Juliet C files for a CWE, handling both flat and sXX layouts."""
    cwe_dir = CWE_DIR_MAP.get(cwe_id, cwe_id.replace('-', ''))
    cwe_path = Path(JULIET_BASE) / 'testcases' / cwe_dir
    if not cwe_path.exists():
        return []

    files = []
    for source_file in sorted(cwe_path.rglob('*.c')):
        # Juliet helper files do not represent standalone test cases.
        if source_file.name.startswith('main'):
            continue
        files.append(source_file)
        if limit and len(files) >= limit:
            break
    return files


def process_file_with_server(cwe_id: str, filename: str, server: JoernServer) -> bool:
    """Process a single file using an existing Joern HTTP server."""
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

    exported_files = []
    for rep_type, query_name in [('ast', 'dotAst'), ('cfg', 'dotCfg'), ('pdg', 'dotPdg')]:
        print(f"\n📤 Exporting {rep_type.upper()}...")
        result = server.query(f'cpg.method.{query_name}.l')
        rep_dir = os.path.join(output_dir, rep_type)
        os.makedirs(rep_dir, exist_ok=True)

        if result['stdout']:
            lines = result['stdout'].strip()
            if 'digraph' in lines:
                rep_file = os.path.join(rep_dir, f'{Path(filename).stem}.{rep_type}.dot')
                with open(rep_file, 'w') as f:
                    f.write(lines)
                exported_files.append(rep_file)
                print(f"✅ {rep_type.upper()} exported: {rep_file}")
            else:
                print(f"⚠️ No {rep_type.upper()} dot found")
        else:
            print(f"❌ {rep_type.upper()} export failed: {result.get('stderr', 'No output')[:200]}")

    print(f"\n{'='*70}")
    print("PROCESSING COMPLETE")
    print(f"Source:  {source_file}")
    print(f"Output:  {output_dir}")
    print(f"Exported: {len(exported_files)} files")
    print(f"{'='*70}")

    return len(exported_files) > 0


def process_file(cwe_id: str, filename: str) -> bool:
    """Process a single file using Joern HTTP server."""
    server = JoernServer()
    if not server.start():
        return False
    try:
        return process_file_with_server(cwe_id, filename, server)
    finally:
        server.stop()


def process_cwe(cwe_id: str, limit: int | None = None) -> tuple[int, int]:
    """Process multiple files for a CWE while reusing one Joern server."""
    source_files = list_source_files(cwe_id, limit)
    if not source_files:
        print(f"No source files found for {cwe_id}")
        return 0, 0

    print(f"Found {len(source_files)} source files for {cwe_id}")
    server = JoernServer()
    if not server.start():
        return 0, len(source_files)

    success_count = 0
    try:
        for index, source_file in enumerate(source_files, 1):
            print(f"\n[{index}/{len(source_files)}] {source_file.name}")
            if process_file_with_server(cwe_id, source_file.name, server):
                success_count += 1
    finally:
        server.stop()

    print(f"\nBatch complete for {cwe_id}: {success_count}/{len(source_files)} succeeded")
    return success_count, len(source_files)


def main():
    parser = argparse.ArgumentParser(description='Joern 4.0 HTTP API pipeline')
    parser.add_argument('--cwe', default='CWE-190', choices=list(CWE_DIR_MAP.keys()))
    parser.add_argument('--file', default='CWE190_Integer_Overflow__char_rand_add_01.c')
    parser.add_argument('--batch', action='store_true', help='Process multiple source files for the CWE')
    parser.add_argument('--limit', type=int, help='Limit number of files in batch mode')
    
    args = parser.parse_args()
    
    if args.batch:
        success_count, total = process_cwe(args.cwe, args.limit)
        return 0 if total > 0 and success_count == total else 1

    success = process_file(args.cwe, args.file)
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
