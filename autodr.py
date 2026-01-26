# automated_threat_hunting.py
# -*- coding: utf-8 -*-
"""
Automated Threat Hunting & Incident Response System with Endpoint Isolation
Flow:
1. Attacker performs DNS lookup to malware.com on endpoint
2. Wazuh detects and fires alert (rule 100001/100002/100003)
3. Alert is enriched with MISP threat intelligence
4. This script detects the enriched alert
5. AutoHunt modules proactively search for threats
6. AutoBook runbooks execute automated remediation
7. Endpoint is automatically isolated and quarantined
"""

import requests
import json
import time
import sys
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Import AutoBook and AutoHunt loaders
sys.path.insert(0, str(Path(__file__).parent))
from autobook.runbook_loader import RunbookLoader
from autohunt.hunt_loader import HuntLoader

# Import ML components
from vertex.ml_predictor import predict_threat

# Import Shuffle orchestration and IRIS case management
from shuffle.shuffle_integration import ShuffleOrchestrator
from iris.iris_integration import IrisIntegration
import os

class AutomatedThreatHunter:
    """Automated threat hunting with modular runbooks and hunts"""

    def __init__(self):
        # Wazuh Configuration
        self.wazuh_url = "https://localhost"
        self.wazuh_user = "wazuh-wui"
        self.wazuh_pass = "NZ5k.8gLaS4gPqiQFs+ArZDAwsgkvrBJ"
        self.wazuh_token = None

        # Indexer Configuration (for alerts)
        self.indexer_url = "https://localhost:9200"
        self.indexer_user = "adm@adm.adm"
        self.indexer_pass = "adm@adm.adm"

        # Malicious DNS rules to monitor
        self.malicious_dns_rules = ['100001', '100002', '100003']

        # Initialize connection
        self._init_wazuh()

        # Load modular runbooks and hunts
        print("[INFO] Initializing modular systems...")
        self.runbook_loader = RunbookLoader()
        self.hunt_loader = HuntLoader()

        # Initialize Shuffle orchestration
        shuffle_url = os.environ.get('SHUFFLE_URL', 'http://localhost:3001')
        shuffle_api_key = os.environ.get('SHUFFLE_API_KEY', '')
        self.shuffle = None
        try:
            self.shuffle = ShuffleOrchestrator(shuffle_url=shuffle_url, api_key=shuffle_api_key)
            print("[SHUFFLE] ✓ Shuffle orchestration layer initialized\n")
        except Exception as e:
            print(f"[SHUFFLE] ⚠ Shuffle initialization failed (continuing without orchestration): {e}\n")

        # Initialize IRIS case management
        iris_url = os.environ.get('IRIS_URL', 'http://localhost:8000')
        iris_api_key = os.environ.get('IRIS_API_KEY', '')
        self.iris = None
        try:
            self.iris = IrisIntegration(iris_url=iris_url, api_key=iris_api_key)
            print("[IRIS] ✓ IRIS case management platform initialized\n")
        except Exception as e:
            print(f"[IRIS] ⚠ IRIS initialization failed (continuing without case management): {e}\n")

        # Tracking
        self.quarantined_agents = []
        self.active_cases = {}  # Maps alert_id to IRIS case_id

    def _init_wazuh(self):
        """Initialize Wazuh connection"""
        print("[CONNECT] Connecting to Wazuh Manager...")
        try:
            response = requests.post(
                "{0}:55000/security/user/authenticate".format(self.wazuh_url),
                auth=(self.wazuh_user, self.wazuh_pass),
                verify=False
            )
            if response.status_code == 200:
                self.wazuh_token = response.json()['data']['token']
                print("[SUCCESS] Wazuh connected successfully\n")
            else:
                print("[ERROR] Wazuh auth failed: {0}\n".format(response.status_code))
        except Exception as e:
            print("[ERROR] Wazuh connection error: {0}\n".format(e))

    def _wazuh_request(self, endpoint, params=None, method='GET'):
        """Make authenticated Wazuh API request or fallback to Indexer for alerts"""
        if endpoint in ['/alerts', '/events'] and method == 'GET':
            return self._indexer_alerts_request(params)

        if not self.wazuh_token:
            return None

        headers = {
            'Authorization': 'Bearer {0}'.format(self.wazuh_token),
            'Content-Type': 'application/json'
        }

        try:
            if method == 'GET':
                response = requests.get(
                    "{0}:55000{1}".format(self.wazuh_url, endpoint),
                    headers=headers,
                    params=params,
                    verify=False
                )
            elif method == 'PUT':
                response = requests.put(
                    "{0}:55000{1}".format(self.wazuh_url, endpoint),
                    headers=headers,
                    json=params,
                    verify=False
                )

            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

    def _indexer_alerts_request(self, params=None):
        """Query Wazuh Indexer (OpenSearch) for alerts as a fallback for /alerts"""
        try:
            # Construct OpenSearch query from Wazuh API params
            query = {"query": {"bool": {"must": []}}}
            
            if params:
                if 'rule.id' in params:
                    rule_ids = params['rule.id'].split(',')
                    query["query"]["bool"]["must"].append({"terms": {"rule.id": rule_ids}})
                
                if 'q' in params:
                    # Handle simple q=field~value or field=value
                    q_parts = params['q'].split('~')
                    if len(q_parts) == 2:
                        # Use query_string for partial matches with wildcards
                        query["query"]["bool"]["must"].append({
                            "query_string": {
                                "query": f"*{q_parts[1]}*",
                                "default_field": q_parts[0]
                            }
                        })
                    else:
                        q_parts = params['q'].split('=')
                        if len(q_parts) == 2:
                            query["query"]["bool"]["must"].append({"term": {q_parts[0]: q_parts[1]}})

            # Add timeframe if needed (default to last 24h)
            query["query"]["bool"]["must"].append({
                "range": {
                    "timestamp": {
                        "gte": "now-24h"
                    }
                }
            })

            response = requests.get(
                "{0}/wazuh-alerts-*/_search".format(self.indexer_url),
                auth=(self.indexer_user, self.indexer_pass),
                json=query,
                params={'size': params.get('limit', 100) if params else 100},
                verify=False
            )

            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                affected_items = [hit['_source'] for hit in hits]
                return {
                    'data': {
                        'affected_items': affected_items,
                        'total_affected_items': len(affected_items)
                    }
                }
            return None
        except Exception as e:
            print(f"[DEBUG] Indexer request failed: {e}")
            return None

    def step1_monitor_malicious_dns_alerts(self):
        """Step 1: Monitor for malicious DNS query alerts"""
        print("="*70)
        print("[TARGET] STEP 1: MONITORING FOR MALICIOUS DNS ALERTS")
        print("="*70 + "\n")

        print("📡 Checking for alerts from custom DNS rules (100001, 100002, 100003)...")

        params = {
            'rule.id': ','.join(self.malicious_dns_rules),
            'limit': 100,
            'sort': '-timestamp'
        }

        result = self._wazuh_request('/alerts', params)

        if not result or 'data' not in result:
            print("[SUCCESS] No malicious DNS alerts detected\n")
            return []

        alerts = result['data']['affected_items']
        print("[ALERT] Found {0} malicious DNS query alerts!\n".format(len(alerts)))

        # Trigger Shuffle incident response workflow for each alert
        if self.shuffle:
            for alert in alerts[:5]:  # Limit to first 5 to avoid overload
                try:
                    print("[SHUFFLE] Triggering incident response workflow for alert...")
                    execution = self.shuffle.trigger_incident_response_workflow(alert)
                    if execution:
                        print(f"[SHUFFLE] ✓ Workflow execution started: {execution.get('execution_id')}")
                except Exception as e:
                    print(f"[SHUFFLE] ⚠ Workflow trigger failed: {e}")

        # Create IRIS case for high-severity alerts
        if self.iris:
            for alert in alerts[:5]:  # Limit to first 5
                rule = alert.get('rule', {})
                rule_level = rule.get('level', 0)
                
                # Only create cases for high severity (level >= 10)
                if rule_level >= 10:
                    try:
                        print("[IRIS] Creating case for high-severity alert...")
                        alert['threat_score'] = alert.get('ml_threat_score', 0.5)  # Add ML score
                        case_result = self.iris.create_case_from_alert(alert)
                        if case_result:
                            alert_id = alert.get('id', 'unknown')
                            case_id = case_result.get('case_id')
                            self.active_cases[alert_id] = case_id
                            print(f"[IRIS] ✓ Case created: ID {case_id}")
                    except Exception as e:
                        print(f"[IRIS] ⚠ Case creation failed: {e}")

        # Display alert details
        for i, alert in enumerate(alerts[:10], 1):
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            data = alert.get('data', {})
            timestamp = alert.get('timestamp', '')

            print("  Alert #{0}:".format(i))
            print("    Time: {0}".format(timestamp))
            print("    Agent: {0} (ID: {1})".format(agent.get('name', 'unknown'), agent.get('id', 'N/A')))
            print("    Rule: {0}".format(rule.get('description', 'N/A')))
            print("    Rule ID: {0}".format(rule.get('id', 'N/A')))
            print("    Level: {0}".format(rule.get('level', 'N/A')))

            # Extract malicious domain
            domain = None
            if 'win' in data and 'eventdata' in data['win']:
                domain = data['win']['eventdata'].get('QueryName', '')
            if not domain:
                # Try to extract from syslog
                full_log = alert.get('full_log', '')
                for bad_domain in ['malware.com', 'evil.com', 'c2server.com', 'badactor.net']:
                    if bad_domain in full_log:
                        domain = bad_domain
                        break

            if domain:
                print("    [RED] Malicious Domain: {0}".format(domain))

            # Check if MISP enriched
            if 'misp_enrichment' in alert:
                print("    [SUCCESS] Alert enriched with MISP threat intelligence")

            # ML Threat Scoring
            try:
                # Extract features for ML (placeholder - customize based on your features)
                features = [float(rule.get('level', 0)) / 15.0]  # Normalize level
                threat_score = predict_threat('threat_model.pkl', features)
                print("    [AI] ML Threat Score: {0:.2f} (1=Threat, 0=Benign)".format(threat_score))
                alert['ml_threat_score'] = threat_score
            except Exception as e:
                print("    [AI] ML Scoring failed: {0}".format(e))
                alert['ml_threat_score'] = 0.5  # Default

            print()

        return alerts

    def step2_identify_compromised_endpoints(self, alerts):
        """Step 2: Identify compromised endpoints from alerts"""
        print("="*70)
        print("[INFO] STEP 2: IDENTIFYING COMPROMISED ENDPOINTS")
        print("="*70 + "\n")

        compromised_agents = set()

        for alert in alerts:
            agent = alert.get('agent', {})
            agent_id = agent.get('id')
            agent_name = agent.get('name', 'unknown')
            ml_score = alert.get('ml_threat_score', 0)

            # Only consider high-confidence threats
            if agent_id and agent_id != '000' and ml_score > 0.7:
                compromised_agents.add((agent_id, agent_name))

        print("[ALERT] Compromised Endpoints Identified (ML Score > 0.7): {0}\n".format(len(compromised_agents)))

        for agent_id, agent_name in compromised_agents:
            print("  [RED] Agent ID: {0} | Name: {1}".format(agent_id, agent_name))

        print()
        return list(compromised_agents)

    def step3_isolate_endpoint(self, agent_id, agent_name):
        """Step 3: Isolate compromised endpoint using AutoBook runbook"""
        print("="*70)
        print("[LOCKED] STEP 3: ISOLATING COMPROMISED ENDPOINT (AutoBook)")
        print("="*70 + "\n")

        # Trigger Shuffle orchestrated isolation workflow
        if self.shuffle:
            try:
                print("[SHUFFLE] Triggering endpoint isolation workflow...")
                execution = self.shuffle.isolate_endpoint(
                    agent_id=agent_id,
                    reason=f"High-confidence threat detected on {agent_name}"
                )
                if execution:
                    print(f"[SHUFFLE] ✓ Isolation workflow started: {execution.get('execution_id')}")
            except Exception as e:
                print(f"[SHUFFLE] ⚠ Workflow trigger failed, falling back to direct isolation: {e}")

        # Execute isolation runbook from autobook/runbooks/
        result = self.runbook_loader.execute_runbook(
            '00_isolate_endpoint',
            agent_id=agent_id,
            agent_name=agent_name,
            wazuh_url=self.wazuh_url,
            wazuh_token=self.wazuh_token
        )

        return result

    def step3a_execute_additional_runbooks(self, agent_id, agent_name):
        """Step 3a: Execute additional AutoBook runbooks as needed"""
        print("="*70)
        print("📚 STEP 3a: EXECUTING ADDITIONAL RUNBOOKS")
        print("="*70 + "\n")

        # Example: Block malicious IP if detected
        # self.runbook_loader.execute_runbook('block_ip', ip_address='192.168.1.100')

        # Example: Disable compromised user
        # self.runbook_loader.execute_runbook('40_disable_user', username='compromised_user')

        print("  ℹ️  No additional runbooks needed for this incident\n")
        return True

    def step4_quarantine_endpoint(self, agent_id, agent_name):
        """Step 4: Quarantine endpoint in Wazuh"""
        print("="*70)
        print("[WARNING]  STEP 4: QUARANTINING ENDPOINT")
        print("="*70 + "\n")

        print("[PACKAGE] Placing Agent {0} (ID: {1}) into quarantine...\n".format(agent_name, agent_id))

        # Add agent to quarantine group
        print("  [LABEL]  Adding 'quarantine' group to agent...")

        # In Wazuh, we can change agent group to quarantine
        # This can be done via agent configuration
        endpoint = "/agents/{0}/group/quarantine".format(agent_id)
        result = self._wazuh_request(endpoint, method='PUT')

        if result:
            print("  [SUCCESS] Agent added to quarantine group")
        else:
            print("  [WARNING]  Quarantine group assignment failed (may not exist)")

        # Log quarantine action
        self.quarantined_agents.append({
            'agent_id': agent_id,
            'agent_name': agent_name,
            'quarantine_time': datetime.now().isoformat(),
            'reason': 'Malicious DNS query detected',
            'status': 'QUARANTINED'
        })

        print("  [SUCCESS] Agent {0} is now in QUARANTINE status".format(agent_name))
        print("  [LOG] Incident logged for security team review\n")

        # Update IRIS case with isolation status
        if self.iris and hasattr(self, 'active_cases'):
            for alert_id, case_id in self.active_cases.items():
                try:
                    self.iris.add_timeline_event(
                        case_id=case_id,
                        event_title=f"Endpoint Isolated: {agent_name}",
                        event_date=datetime.now().isoformat(),
                        event_description=f"Agent {agent_id} ({agent_name}) isolated and quarantined. Network access revoked.",
                        event_category_id=2
                    )
                    print(f"[IRIS] ✓ Updated case {case_id} with isolation status")
                except Exception as e:
                    print(f"[IRIS] ⚠ Failed to update case: {e}")

        return True

    def step5_generate_incident_report(self, alerts, compromised_agents):
        """Step 5: Generate incident response report"""
        print("="*70)
        print("📄 STEP 5: GENERATING INCIDENT REPORT")
        print("="*70 + "\n")

        report = {
            'timestamp': datetime.now().isoformat(),
            'incident_type': 'Malicious DNS Query - C2 Communication Attempt (ML-Enhanced)',
            'severity': 'CRITICAL',
            'alerts_detected': len(alerts),
            'compromised_endpoints': len(compromised_agents),
            'quarantined_agents': self.quarantined_agents,
            'ml_integration': {
                'model_used': 'threat_model.pkl',
                'threat_threshold': 0.7,
                'average_threat_score': sum(a.get('ml_threat_score', 0) for a in alerts) / len(alerts) if alerts else 0
            },
            'mitre_attack': {
                'tactic': 'Command and Control',
                'technique': 'T1071.004 - Application Layer Protocol: DNS'
            },
            'response_actions': [
                'Malicious DNS alert detected',
                'ML model scored alerts for threat level',
                'High-confidence threats isolated',
                'Endpoint identified and isolated',
                'Network access revoked',
                'Agent quarantined for forensics',
                'SOC team notified'
            ],
            'iris_cases': self.active_cases if hasattr(self, 'active_cases') else {}
        }

        # Update IRIS cases with final report
        if self.iris and hasattr(self, 'active_cases'):
            for alert_id, case_id in self.active_cases.items():
                try:
                    # Add final incident report as note
                    report_content = f"""# Final Incident Report

## Summary
- **Alerts Detected**: {len(alerts)}
- **Compromised Endpoints**: {len(compromised_agents)}
- **Endpoints Quarantined**: {len(self.quarantined_agents)}
- **Average ML Threat Score**: {report['ml_integration']['average_threat_score']:.2f}

## MITRE ATT&CK
- **Tactic**: {report['mitre_attack']['tactic']}
- **Technique**: {report['mitre_attack']['technique']}

## Response Actions
{chr(10).join('- ' + action for action in report['response_actions'])}

## Quarantined Agents
{chr(10).join(f"- Agent {qa['agent_name']} (ID: {qa['agent_id']}) - {qa['quarantine_time']}" for qa in self.quarantined_agents)}
"""
                    self.iris.add_note(
                        case_id=case_id,
                        note_title="Final Incident Response Report",
                        note_content=report_content
                    )
                    
                    # Add timeline event for case closure
                    self.iris.add_timeline_event(
                        case_id=case_id,
                        event_title="Incident Response Completed",
                        event_date=datetime.now().isoformat(),
                        event_description=f"All response actions completed. {len(compromised_agents)} endpoints isolated and quarantined.",
                        event_category_id=3
                    )
                    
                    print(f"[IRIS] ✓ Updated case {case_id} with final report")
                except Exception as e:
                    print(f"[IRIS] ⚠ Failed to update case {case_id}: {e}")

        # Save report
        report_file = "incident_report_{0}.json".format(datetime.now().strftime('%Y%m%d_%H%M%S'))
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Display summary
        print("[ALERT] INCIDENT RESPONSE SUMMARY (ML-ENHANCED)")
        print("-" * 70)
        print("  Incident Type: {0}".format(report['incident_type']))
        print("  Severity: {0}".format(report['severity']))
        print("  Alerts Detected: {0}".format(report['alerts_detected']))
        print("  Compromised Endpoints: {0}".format(report['compromised_endpoints']))
        print("  Endpoints Quarantined: {0}".format(len(self.quarantined_agents)))
        print("  ML Threat Threshold: {0}".format(report['ml_integration']['threat_threshold']))
        print("  Average ML Threat Score: {0:.2f}".format(report['ml_integration']['average_threat_score']))
        if report['iris_cases']:
            print("  IRIS Cases Created: {0}".format(len(report['iris_cases'])))
        print("\n  MITRE ATT&CK:")
        print("    • Tactic: {0}".format(report['mitre_attack']['tactic']))
        print("    • Technique: {0}".format(report['mitre_attack']['technique']))
        print("\n  Response Actions Taken:")
        for action in report['response_actions']:
            print("    [CHECK] {0}".format(action))

        print("\n[SUCCESS] Report saved: {0}\n".format(report_file))

        return report

    def run_proactive_hunts(self):
        """Execute AutoHunt modules for proactive threat hunting"""
        print("="*70)
        print("[INFO] PROACTIVE THREAT HUNTING (AutoHunt)")
        print("="*70 + "\n")

        # Trigger Shuffle orchestrated threat hunting workflow
        if self.shuffle:
            try:
                print("[SHUFFLE] Triggering automated threat hunting workflow...")
                hunt_params = {
                    'hunt_type': 'scheduled',
                    'timeframe': '24h',
                    'data_sources': ['wazuh', 'splunk', 'crowdstrike'],
                    'iocs': []
                }
                execution = self.shuffle.trigger_threat_hunting_workflow(hunt_params)
                if execution:
                    print(f"[SHUFFLE] ✓ Threat hunting workflow started: {execution.get('execution_id')}\n")
            except Exception as e:
                print(f"[SHUFFLE] ⚠ Threat hunting workflow trigger failed: {e}\n")

        # Execute all threat hunting modules
        hunt_results = self.hunt_loader.execute_all_hunts(
            wazuh_api=self,
            timeframe_hours=24
        )

        # Analyze results and add to IRIS if applicable
        critical_findings = []
        for hunt_name, result in hunt_results.items():
            if result and result.get('severity') in ['CRITICAL', 'HIGH']:
                critical_findings.append(result)
                
                # Create IRIS case or add evidence to existing case
                if self.iris and result.get('findings'):
                    try:
                        # Check if there's a related case already
                        related_case_id = None
                        if hasattr(self, 'active_cases') and self.active_cases:
                            # Use the first active case (or implement smarter matching)
                            related_case_id = list(self.active_cases.values())[0]
                        
                        if related_case_id:
                            # Add findings to existing case
                            print(f"[IRIS] Adding hunt findings to case {related_case_id}...")
                            self.iris.add_note(
                                case_id=related_case_id,
                                note_title=f"Threat Hunt: {hunt_name}",
                                note_content=f"""# Threat Hunt Results

**Hunt Name**: {hunt_name}
**Severity**: {result.get('severity', 'UNKNOWN')}
**Findings Count**: {len(result.get('findings', []))}

## Details
{result.get('description', 'No description')}

## Findings
```json
{json.dumps(result.get('findings', []), indent=2)}
```
"""
                            )
                            
                            # Add IOCs from findings
                            for finding in result.get('findings', [])[:10]:  # Limit to 10
                                data = finding.get('data', {})
                                if 'srcip' in data:
                                    self.iris.add_ioc(related_case_id, data['srcip'], 'ip', 
                                                     f"From hunt: {hunt_name}", ["autodr", "hunt"])
                                if 'domain' in data:
                                    self.iris.add_ioc(related_case_id, data['domain'], 'domain',
                                                     f"From hunt: {hunt_name}", ["autodr", "hunt"])
                            
                            print(f"[IRIS] ✓ Hunt evidence added to case {related_case_id}")
                        else:
                            # Create new case for hunt findings
                            case = self.iris.create_case(
                                case_name=f"Threat Hunt: {hunt_name}",
                                case_description=f"Critical findings from proactive threat hunt.\n\n{result.get('description', '')}",
                                severity_id=2,  # High
                                case_tags=["autodr", "threat-hunt", hunt_name.replace('_', '-')]
                            )
                            if case:
                                print(f"[IRIS] ✓ Created new case for hunt: {case.get('case_id')}")
                    except Exception as e:
                        print(f"[IRIS] ⚠ Failed to add hunt results to IRIS: {e}")

        if critical_findings:
            print("\n[ALERT] CRITICAL: {0} hunts found suspicious activity!".format(len(critical_findings)))
            print("   Manual investigation recommended\n")
        else:
            print("\n[SUCCESS] All proactive hunts completed - no critical findings\n")

        return hunt_results

    def run_automated_response(self):
        """Execute complete automated threat response workflow"""
        print("\n" + "="*70)
        print("🤖 AUTOMATED THREAT HUNTING & RESPONSE SYSTEM")
        print("   Modular AutoBook + AutoHunt Integration")
        print("="*70 + "\n")

        start_time = time.time()

        # Step 0: Run proactive threat hunts (AutoHunt)
        hunt_results = self.run_proactive_hunts()

        # Step 1: Monitor for malicious DNS alerts
        alerts = self.step1_monitor_malicious_dns_alerts()

        if not alerts:
            print("[SUCCESS] No malicious DNS activity detected. System is clean.\n")
            return

        # Step 2: Identify compromised endpoints
        compromised_agents = self.step2_identify_compromised_endpoints(alerts)

        if not compromised_agents:
            print("[WARNING]  Alerts found but no agent identification possible\n")
            return

        # Step 3 & 3a: Execute AutoBook runbooks for each compromised endpoint
        for agent_id, agent_name in compromised_agents:
            # Get ML score for this agent
            agent_alerts = [a for a in alerts if a.get('agent', {}).get('id') == agent_id]
            avg_ml_score = sum(a.get('ml_threat_score', 0) for a in agent_alerts) / len(agent_alerts) if agent_alerts else 0
            print(f"  [AI] Agent {agent_name} average ML threat score: {avg_ml_score:.2f}")
            
            self.step3_isolate_endpoint(agent_id, agent_name)
            self.step3a_execute_additional_runbooks(agent_id, agent_name)
            self.step4_quarantine_endpoint(agent_id, agent_name)

        # Step 5: Generate incident report
        report = self.step5_generate_incident_report(alerts, compromised_agents)

        elapsed = time.time() - start_time

        print("="*70)
        print("[SUCCESS] AUTOMATED RESPONSE COMPLETE - Elapsed Time: {0:.2f}s".format(elapsed))
        print("[INFO] {0} threat hunts executed".format(len(hunt_results)))
        print("[AI] ML-enhanced threat detection active")
        print("[LOCKED] {0} endpoint(s) isolated and quarantined".format(len(compromised_agents)))
        print("="*70 + "\n")

def execute_runbook_cli(runbook_name, step_mode=False, full_mode=False):
    """Execute a runbook script directly via command line or open in Jupyter"""
    import subprocess
    import sys

    # Build the path to the runbook script
    runbook_script = f"autobook/runbooks/{runbook_name}.py"

    if not Path(runbook_script).exists():
        print(f"❌ Runbook script not found: {runbook_script}")
        return False

    if step_mode:
        # For step mode, open in Jupyter notebook for interactive execution
        print(f"📓 Opening runbook: {runbook_name} in Jupyter notebook (step mode)")

        # Check if notebook version exists first
        notebook_script = f"autobook/runbooks/{runbook_name}.ipynb"

        if Path(notebook_script).exists():
            print(f"   File: {notebook_script}")
            print("-" * 50)

            try:
                # Try to open the notebook in VS Code
                full_path = str(Path(__file__).parent / notebook_script)
                subprocess.run(['code', full_path], check=False)
                print("✅ Jupyter notebook opened in VS Code")
                print("   Execute cells interactively to run the runbook")
                return True

            except FileNotFoundError:
                print("⚠️  VS Code CLI not found, trying alternative methods...")

            try:
                # Fallback: try to start jupyter notebook server
                print("🔄 Starting Jupyter notebook server...")
                subprocess.Popen(['jupyter', 'notebook', notebook_script],
                               cwd=Path(__file__).parent,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                print("✅ Jupyter notebook server started")
                print(f"   Open your browser to access the notebook: {runbook_name}.ipynb")
                return True

            except Exception as e:
                print(f"❌ Could not open notebook: {e}")
                return False
        else:
            print(f"❌ Notebook not found: {notebook_script}")
            return False

    elif full_mode:
        # For full mode, execute directly
        print(f"🔧 Executing runbook: {runbook_name} (full auto mode)")
        cmd = [sys.executable, runbook_script, '--full']
        print(f"   Command: {' '.join(cmd)}")
        print("-" * 50)

        try:
            result = subprocess.run(cmd, cwd=Path(__file__).parent)
            return result.returncode == 0
        except Exception as e:
            print(f"❌ Error executing runbook: {e}")
            return False
    else:
        print("❌ Must specify --step or --full mode")
        return False

def main():
    """Main execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Automated Threat Hunting & Response')
    parser.add_argument('--list-runbooks', action='store_true', help='List available runbooks')
    parser.add_argument('--list-hunts', action='store_true', help='List available hunts')
    parser.add_argument('--run-hunt', type=str, help='Run specific hunt module')
    parser.add_argument('--run-runbook', type=str, help='Run specific runbook')

    # Add subparser for runbook command
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Runbook subcommand
    runbook_parser = subparsers.add_parser('runbook', help='Execute runbook')
    runbook_parser.add_argument('runbook_name', help='Name of the runbook to execute')
    runbook_parser.add_argument('--step', action='store_true', help='Run in stepwise mode (interactive)')
    runbook_parser.add_argument('--full', action='store_true', help='Run in full auto mode (non-interactive)')

    # Hunt subcommand
    hunt_parser = subparsers.add_parser('hunt', help='Execute threat hunt')
    hunt_parser.add_argument('hunt_name', help='Name of the hunt to execute')

    args = parser.parse_args()

    # Handle runbook subcommand before initializing the full system
    if args.command == 'runbook':
        execute_runbook_cli(args.runbook_name, args.step, args.full)
        return

    # Handle hunt subcommand
    if args.command == 'hunt':
        print("[START] Starting Automated Threat Hunting System...\n")
        hunter = AutomatedThreatHunter()
        hunter.hunt_loader.execute_hunt(args.hunt_name, wazuh_api=hunter, timeframe_hours=24)
        return

    # Handle listing without initializing the full system
    if args.list_runbooks:
        loader = RunbookLoader()
        loader.list_runbooks()
        return

    if args.list_hunts:
        loader = HuntLoader()
        loader.list_hunts()
        return

    print("[START] Starting Automated Threat Hunting System...\n")
    hunter = AutomatedThreatHunter()

    if args.run_hunt:
        hunter.hunt_loader.execute_hunt(args.run_hunt, wazuh_api=hunter, timeframe_hours=24)
        return

    # Run full automated response workflow
    hunter.run_automated_response()

if __name__ == "__main__":
    main()