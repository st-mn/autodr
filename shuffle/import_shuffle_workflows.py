# Shuffle Workflow Import Script
# Automatically imports AUTODR workflows into Shuffle

import requests
import json
import os
import sys
from pathlib import Path

SHUFFLE_URL = os.environ.get('SHUFFLE_URL', 'http://localhost:3001')
SHUFFLE_API_KEY = os.environ.get('SHUFFLE_API_KEY', '')

def import_workflow(workflow_file):
    """Import a workflow JSON file into Shuffle"""
    print(f"Importing workflow: {workflow_file}")
    
    with open(workflow_file, 'r') as f:
        workflow_data = json.load(f)
    
    headers = {
        'Authorization': f'Bearer {SHUFFLE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f'{SHUFFLE_URL}/api/v1/workflows',
            json=workflow_data,
            headers=headers,
            verify=False,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Successfully imported: {workflow_data['name']}")
            print(f"  Workflow ID: {result.get('id')}")
            return result.get('id')
        else:
            print(f"✗ Failed to import: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
    except Exception as e:
        print(f"✗ Error importing workflow: {e}")
        return None

def main():
    """Import all AUTODR workflows"""
    print("="*70)
    print("AUTODR Shuffle Workflow Importer")
    print("="*70)
    print()
    
    workflows_dir = Path('shuffle_workflows')
    
    if not workflows_dir.exists():
        print(f"✗ Workflows directory not found: {workflows_dir}")
        sys.exit(1)
    
    workflow_files = list(workflows_dir.glob('*.json'))
    
    if not workflow_files:
        print(f"✗ No workflow files found in {workflows_dir}")
        sys.exit(1)
    
    print(f"Found {len(workflow_files)} workflow(s) to import")
    print()
    
    imported = 0
    failed = 0
    
    for workflow_file in workflow_files:
        workflow_id = import_workflow(workflow_file)
        if workflow_id:
            imported += 1
        else:
            failed += 1
        print()
    
    print("="*70)
    print(f"Import Complete: {imported} successful, {failed} failed")
    print("="*70)

if __name__ == '__main__':
    main()
