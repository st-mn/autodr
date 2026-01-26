# simulate_attack.py
"""
Wazuh Command Execution & Event Logging Simulation Script
This script demonstrates how to execute commands on Wazuh agents and log them as events
"""

import subprocess
import sys
import time
import argparse
import os
from datetime import datetime

# Configuration
AGENT_CONTAINER = "wazuh-agent-linux"
TARGET_AGENT_NAME = "Unknown"
WAZUH_MANAGER_IP = "localhost"
WAZUH_API_PORT = "55000"

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_header():
    print("{0}================================================================{1}".format(Colors.BLUE, Colors.NC))
    print("{0}  [INFO] Wazuh Command Execution & Event Logging Simulation{1}".format(Colors.BLUE, Colors.NC))
    print("{0}================================================================{1}".format(Colors.BLUE, Colors.NC))
    print()

def print_step(step_num, message):
    print("{0}[STEP {1}]{2} {3}".format(Colors.GREEN, step_num, Colors.NC, message))

def print_info(message):
    print("{0}[INFO]{1} {2}".format(Colors.BLUE, Colors.NC, message))

def print_warning(message):
    print("{0}[WARNING]{1} {2}".format(Colors.YELLOW, Colors.NC, message))

def print_error(message):
    print("{0}[ERROR]{1} {2}".format(Colors.RED, Colors.NC, message))

def print_success(message):
    print("{0}[SUCCESS]{1} {2}".format(Colors.GREEN, Colors.NC, message))

def run_command(cmd, shell=False, capture_output=True):
    """Run a command and return the result"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
        else:
            result = subprocess.run(cmd.split(), capture_output=capture_output, text=True)
        return result
    except Exception as e:
        return type('Result', (), {'returncode': 1, 'stdout': '', 'stderr': str(e)})()

def check_docker():
    """Check if Docker is running"""
    result = run_command("docker info")
    if result.returncode != 0:
        print_error("Docker is not running or not accessible")
        sys.exit(1)
    print_success("Docker is running")

def check_agent_container():
    """Check if Wazuh agent container is running"""
    global AGENT_CONTAINER
    result = run_command("docker ps --format '{{.Names}}'", shell=True)
    running_containers = [c.strip() for c in result.stdout.split('\n') if c.strip()]
    
    if AGENT_CONTAINER not in running_containers:
        print_warning("Wazuh agent container '{0}' is not running".format(AGENT_CONTAINER))
        # Try to find any running wazuh-agent container
        found = False
        for container in running_containers:
            if "wazuh-agent" in container:
                AGENT_CONTAINER = container
                print_info("Found alternative running agent container: {0}".format(AGENT_CONTAINER))
                found = True
                break
        
        if not found:
            print_error("No Wazuh agent containers found running")
            print_info("Available containers: {0}".format(", ".join(running_containers) if running_containers else "None"))
            sys.exit(1)
            
    print_success("Wazuh agent container '{0}' is ready".format(AGENT_CONTAINER))

def check_wazuh_manager():
    """Check Wazuh manager status"""
    result = run_command("sudo /var/ossec/bin/wazuh-control status", shell=True)
    status_output = result.stdout + result.stderr
    running_count = status_output.count("is running")

    if running_count < 8:
        print_warning("Wazuh manager has some services not running ({0}/12 services running)".format(running_count))
        running_services = [line for line in status_output.split('\n') if "is running" in line]
        for service in running_services[:5]:
            print("  " + service.strip())
    else:
        print_success("Wazuh manager is running ({0}/12 services)".format(running_count))

def execute_command_on_agent(command, description):
    """Execute command on agent and log to syslog"""
    print_step("1", "Executing command on Wazuh agent [{0}]: {1}".format(TARGET_AGENT_NAME, command))

    # Execute the command and capture output
    docker_cmd = "docker exec {0} sh -c \"{1}\"".format(AGENT_CONTAINER, command)
    result = run_command(docker_cmd, shell=True)
    output = result.stdout + result.stderr if result.stderr else result.stdout
    if result.returncode != 0 and not output:
        output = "Command failed"

    # Log to syslog with timestamp and marker
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = "{0} WAZUH_CMD_EXEC: {1} - Command: {2} - Output: {3}".format(
        timestamp, description, command, output.replace('\n', ' ').strip()
    )

    log_cmd = "docker exec {0} sh -c \"echo '{1}' >> /var/log/syslog\"".format(AGENT_CONTAINER, log_entry)
    run_command(log_cmd, shell=True)

    print_success("Command executed and logged to syslog")
    print("Output: {0}".format(output.strip()))

def check_wazuh_alerts(search_term, timeout=10):
    """Check for alerts in Wazuh"""
    print_step("2", "Checking for Wazuh alerts (timeout: {0}s)".format(timeout))

    start_time = time.time()
    found_alert = False

    while (time.time() - start_time) < timeout:
        # Use grep but exclude the grep command itself to avoid false positives from sudo logging
        result = run_command("sudo grep \"{0}\" /var/ossec/logs/alerts/alerts.log | grep -v \"grep\"".format(search_term), shell=True)
        if result.stdout.strip():
            found_alert = True
            break
        time.sleep(1)

    if found_alert:
        print_success("Alert found in Wazuh!")
        print("Recent alerts containing '{0}':".format(search_term))
        # Show the actual alert content, excluding the grep command
        tail_cmd = "sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 -B 5 \"{0}\" | grep -v \"grep\"".format(search_term)
        result = run_command(tail_cmd, shell=True)
        if result.stdout:
            print(result.stdout)
    else:
        print_warning("No alerts found within {0} seconds".format(timeout))
        print_info("The event may still be in archives or alerts might be disabled for syslog events")

def check_agent_status():
    """Check agent status"""
    print_step("3", "Checking Wazuh agent status")
    result = run_command("sudo /var/ossec/bin/agent_control -l", shell=True)
    lines = result.stdout.split('\n')
    for line in lines:
        if 'wazuh-agent-linux' in line or 'Active' in line or 'Never connected' in line:
            print(line)

def list_active_agents():
    """List active agents and return their names"""
    print_header()
    print_info("Listing active Wazuh agents...")
    result = run_command("sudo /var/ossec/bin/agent_control -l", shell=True)
    active_agents = []
    
    lines = result.stdout.split('\n')
    print("{0:<5} {1:<30} {2:<15} {3:<10}".format("ID", "Name", "IP", "Status"))
    print("-" * 65)
    
    for line in lines:
        if "Active" in line:
            # Example line: "   ID: 004, Name: wazuh-agent-linux-1767224455, IP: any, Active"
            parts = line.split(',')
            if len(parts) >= 4:
                agent_id = parts[0].split(':')[1].strip()
                agent_name = parts[1].split(':')[1].strip()
                agent_ip = parts[2].split(':')[1].strip()
                agent_status = parts[3].strip()
                
                print("{0:<5} {1:<30} {2:<15} {3:<10}".format(agent_id, agent_name, agent_ip, agent_status))
                active_agents.append({"id": agent_id, "name": agent_name})
    
    if not active_agents:
        print_warning("No active agents found!")
    
    print()
    return active_agents

def demonstrate_commands():
    """Demonstrate different command types"""
    print()
    print_info("Demonstrating different types of command execution...")
    print()

    # 1. Simple echo command
    execute_command_on_agent("echo 'Hello from Wazuh agent!'", "Simple echo test")
    check_wazuh_alerts("WAZUH_CMD_EXEC.*echo")

    print()
    time.sleep(2)

    # 2. System information
    execute_command_on_agent("uname -a", "System information check")
    check_wazuh_alerts("WAZUH_CMD_EXEC.*uname")

    print()
    time.sleep(2)

    # 3. Network connectivity test (ping)
    execute_command_on_agent("ping -c 1 8.8.8.8", "Network connectivity test")
    check_wazuh_alerts("WAZUH_CMD_EXEC.*ping")

    print()
    time.sleep(2)

    # 4. DNS lookup simulation (since nslookup might not be available)
    execute_command_on_agent("echo 'Simulating DNS lookup: c2malware.com -> 8.8.8.8'", "DNS lookup simulation")
    check_wazuh_alerts("WAZUH_CMD_EXEC.*DNS")

    print()
    time.sleep(2)

    # 5. File system check
    execute_command_on_agent("df -h / | tail -1", "Disk space check")
    check_wazuh_alerts("WAZUH_CMD_EXEC.*d")

def show_usage():
    """Show usage information"""
    print()
    print_info("Usage examples:")
    print("  python {0}                    # Run full simulation".format(sys.argv[0]))
    print("  python {0} --command 'ls -la' --desc 'List files'  # Execute custom command".format(sys.argv[0]))
    print("  python {0} --check-alerts 'WAZUH_CMD_EXEC'         # Check for specific alerts".format(sys.argv[0]))
    print("  python {0} --status                                   # Show agent status only".format(sys.argv[0]))
    print()

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description='Wazuh Command Execution & Event Logging Simulation')
    parser.add_argument('--command', help='Custom command to execute')
    parser.add_argument('--desc', '--description', help='Description of the command')
    parser.add_argument('--check-alerts', help='Search term for alerts to check')
    parser.add_argument('--status', action='store_true', help='Show agent status only')

    args = parser.parse_args()

    # Basic checks
    check_docker()
    check_wazuh_manager()
    
    # List active agents at the beginning as requested
    active_agents = list_active_agents()
    
    if not active_agents:
        print_error("No active agents found in Wazuh. Please ensure agents are running and connected.")
        sys.exit(1)
        
    # Select an active agent for simulation
    # Prefer linux agent for the default simulation commands
    target_agent = None
    for agent in active_agents:
        if "linux" in agent['name'].lower():
            target_agent = agent
            break
    
    if not target_agent:
        target_agent = active_agents[0]
        
    global TARGET_AGENT_NAME
    TARGET_AGENT_NAME = target_agent['name']
    print_info("Selected target agent: {0} (ID: {1})".format(TARGET_AGENT_NAME, target_agent['id']))
    
    # Update AGENT_CONTAINER based on selected agent name if it matches our naming convention
    global AGENT_CONTAINER
    if "wazuh-agent-linux" in target_agent['name']:
        AGENT_CONTAINER = "wazuh-agent-linux"
    elif "wazuh-agent-windows" in target_agent['name']:
        AGENT_CONTAINER = "wazuh-agent-windows"
    elif "wazuh-agent-macos" in target_agent['name']:
        AGENT_CONTAINER = "wazuh-agent-macos"
    
    check_agent_container()

    if args.status:
        check_agent_status()
        sys.exit(0)

    if args.check_alerts:
        check_wazuh_alerts(args.check_alerts, 5)
        sys.exit(0)

    if args.command:
        execute_command_on_agent(args.command, args.desc or "Custom command")
        check_wazuh_alerts("WAZUH_CMD_EXEC")
        check_agent_status()
        sys.exit(0)

    # Full demonstration
    demonstrate_commands()
    check_agent_status()

    print()
    print_success("Command Execution & Event Logging simulation completed!")
    print_info("All commands executed on the agent have been logged to Wazuh")
    print_info("Check the Wazuh dashboard at https://localhost:443 for visual alerts")

if __name__ == "__main__":
    main()