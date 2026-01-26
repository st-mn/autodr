# autobook/runbooks/00_isolate_endpoint.py
"""
Isolate Endpoint Runbook
Cuts network access to compromised endpoint
"""

import requests
import argparse
import sys
import os

def execute(agent_id, agent_name, wazuh_url="https://localhost", wazuh_token=None):
    """Entry point for isolation"""
    return execute_isolation(agent_id, agent_name, wazuh_url, wazuh_token)

def execute_isolation(agent_id, agent_name, wazuh_url="https://localhost", wazuh_token=None):
    """Execute firewall-drop active response"""
    print(f"\n🔒 RUNBOOK: Isolate Endpoint")
    print(f"   Target: {agent_name} (ID: {agent_id})")
    print("="*70)

    if not wazuh_token:
        print("❌ Error: Wazuh API token is required")
        return False

    if not agent_id:
        print("❌ Error: Agent ID is required")
        return False

    print("  📡 Cutting network connection...")

    headers = {
        'Authorization': f'Bearer {wazuh_token}',
        'Content-Type': 'application/json'
    }

    active_response = {
        "command": "firewall-drop",
        "arguments": ["-", "null", "0", "0"]
    }

    try:
        response = requests.put(
            f"{wazuh_url}:55000/active-response?agents_list={agent_id}",
            headers=headers,
            json=active_response,
            verify=False
        )

        if response.status_code == 200:
            print(f"  ✅ Endpoint {agent_name} isolated successfully")
            return True
        else:
            print(f"  ❌ Failed to isolate endpoint: {response.status_code}")
            print(response.text)
            return False

    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def execute_release(agent_id, agent_name, wazuh_url="https://localhost", wazuh_token=None):
    """Restore network access to the endpoint"""
    print(f"\n🔓 RUNBOOK: Release Endpoint")
    print(f"   Target: {agent_name} (ID: {agent_id})")
    print("="*70)

    if not wazuh_token:
        print("❌ Error: Wazuh API token is required")
        return False

    print("  📡 Restoring network connection...")

    headers = {
        'Authorization': f'Bearer {wazuh_token}',
        'Content-Type': 'application/json'
    }

    # Note: Releasing often requires specific logic depending on how it was blocked
    # For this simulation, we trigger a hypothetical release rule or clear command
    active_response = {
        "command": "firewall-drop", 
        "arguments": ["-", "null", "0", "0"],
        "alert": {"rule": {"id": "100004"}} 
    }

    try:
        response = requests.put(
            f"{wazuh_url}:55000/active-response?agents_list={agent_id}",
            headers=headers,
            json=active_response,
            verify=False
        )

        if response.status_code == 200:
            print(f"  ✅ Endpoint {agent_name} released successfully")
            return True
        else:
            print(f"  ❌ Failed to release endpoint: {response.status_code}")
            print(response.text)
            return False

    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def run_stepwise():
    """Run isolation in stepwise mode - prompt for confirmation"""
    print("\n🔒 ISOLATE/RELEASE ENDPOINT - STEPWISE MODE")
    print("="*50)

    # Get agent details
    agent_id = input("Enter Agent ID: ").strip()
    agent_name = input("Enter Agent Name/Hostname: ").strip()

    if not agent_id or not agent_name:
        print("❌ Agent ID and name are required")
        return False

    action = input("Action (isolate/release): ").strip().lower()
    if action not in ['isolate', 'release']:
        print("❌ Invalid action")
        return False

    # Confirm action
    confirm = input(f"\n⚠️  This will {action.upper()} {agent_name} (ID: {agent_id})\nContinue? (yes/no): ").strip().lower()

    if confirm not in ['yes', 'y']:
        print("❌ Operation cancelled")
        return False

    # Get Wazuh credentials
    wazuh_token = input("Enter Wazuh API token: ").strip()

    if not wazuh_token:
        print("❌ Wazuh token is required")
        return False

    # Execute
    if action == 'isolate':
        return execute_isolation(agent_id, agent_name, wazuh_token=wazuh_token)
    else:
        return execute_release(agent_id, agent_name, wazuh_token=wazuh_token)

def run_full_auto():
    """Run isolation in full auto mode - use environment variables/defaults"""
    print("\n🔒 ISOLATE ENDPOINT - FULL AUTO MODE")
    print("="*50)

    # In full auto mode, you might get agent details from environment variables
    # or from command line arguments, or from Wazuh alerts
    agent_id = os.getenv('AGENT_ID')
    agent_name = os.getenv('AGENT_NAME')
    wazuh_token = os.getenv('WAZUH_TOKEN')

    if not agent_id or not agent_name:
        print("❌ AGENT_ID and AGENT_NAME environment variables required for full auto mode")
        print("   Set them with: export AGENT_ID=001 && export AGENT_NAME=compromised-host")
        return False

    if not wazuh_token:
        print("❌ WAZUH_TOKEN environment variable required")
        print("   Set it with: export WAZUH_TOKEN=your_token_here")
        return False

    print(f"   Target: {agent_name} (ID: {agent_id})")
    
    action = os.getenv('ACTION', 'isolate').lower()
    if action == 'release':
        print("   Auto-executing release...")
        return execute_release(agent_id, agent_name, wazuh_token=wazuh_token)
    else:
        print("   Auto-executing isolation...")
        return execute_isolation(agent_id, agent_name, wazuh_token=wazuh_token)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Isolate/Release Endpoint Runbook')
    parser.add_argument('--step', action='store_true', help='Run in stepwise mode (interactive)')
    parser.add_argument('--full', action='store_true', help='Run in full auto mode (non-interactive)')
    parser.add_argument('--release', action='store_true', help='Release the endpoint instead of isolating')

    args = parser.parse_args()

    if args.step:
        success = run_stepwise()
    elif args.full:
        if args.release:
            os.environ['ACTION'] = 'release'
        success = run_full_auto()
    else:
        print("❌ Specify --step or --full mode")
        parser.print_help()
        sys.exit(1)

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()