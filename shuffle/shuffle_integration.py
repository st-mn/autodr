"""
Shuffle SOAR Integration Module
Provides orchestration layer for automated threat hunting and incident response
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import warnings
warnings.filterwarnings('ignore')


class ShuffleOrchestrator:
    """
    Shuffle SOAR Integration for orchestrating security workflows
    Connects AUTODR with Shuffle for advanced automation and orchestration
    """

    def __init__(self, shuffle_url: str = "http://localhost:3001", api_key: str = None):
        """
        Initialize Shuffle orchestrator
        
        Args:
            shuffle_url: Shuffle instance URL (default: http://localhost:3001)
            api_key: Shuffle API key for authentication
        """
        self.shuffle_url = shuffle_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })
        
        print(f"[SHUFFLE] Initializing Shuffle orchestrator at {self.shuffle_url}")
        self._verify_connection()

    def _verify_connection(self):
        """Verify connection to Shuffle instance"""
        try:
            response = self.session.get(f'{self.shuffle_url}/api/v1/workflows', verify=False, timeout=5)
            if response.status_code in [200, 401]:  # 401 means server is up but needs auth
                print("[SHUFFLE] ✓ Successfully connected to Shuffle")
                return True
            else:
                print(f"[SHUFFLE] ⚠ Shuffle connection warning: Status {response.status_code}")
                return False
        except Exception as e:
            print(f"[SHUFFLE] ⚠ Could not connect to Shuffle (will retry): {e}")
            return False

    def create_workflow(self, name: str, description: str = "", actions: List[Dict] = None) -> Optional[str]:
        """
        Create a new Shuffle workflow
        
        Args:
            name: Workflow name
            description: Workflow description
            actions: List of workflow actions/nodes
            
        Returns:
            Workflow ID if successful, None otherwise
        """
        workflow_data = {
            "name": name,
            "description": description,
            "tags": ["autodr", "automated"],
            "actions": actions or [],
            "branches": [],
            "triggers": [],
            "workflow_variables": []
        }

        try:
            response = self.session.post(
                f'{self.shuffle_url}/api/v1/workflows',
                json=workflow_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                workflow_id = result.get('id')
                print(f"[SHUFFLE] ✓ Created workflow '{name}' (ID: {workflow_id})")
                return workflow_id
            else:
                print(f"[SHUFFLE] ✗ Failed to create workflow: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"[SHUFFLE] ✗ Error creating workflow: {e}")
            return None

    def execute_workflow(self, workflow_id: str, execution_argument: Dict = None) -> Optional[Dict]:
        """
        Execute a Shuffle workflow
        
        Args:
            workflow_id: Workflow ID to execute
            execution_argument: Execution parameters/data
            
        Returns:
            Execution result dictionary
        """
        try:
            url = f'{self.shuffle_url}/api/v1/workflows/{workflow_id}/execute'
            
            response = self.session.post(
                url,
                json=execution_argument or {},
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                execution_id = result.get('execution_id', result.get('id'))
                print(f"[SHUFFLE] ✓ Started workflow execution (ID: {execution_id})")
                return result
            else:
                print(f"[SHUFFLE] ✗ Failed to execute workflow: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"[SHUFFLE] ✗ Error executing workflow: {e}")
            return None

    def get_execution_status(self, execution_id: str) -> Optional[Dict]:
        """
        Get status of a workflow execution
        
        Args:
            execution_id: Execution ID to check
            
        Returns:
            Execution status dictionary
        """
        try:
            response = self.session.get(
                f'{self.shuffle_url}/api/v1/streams/results',
                json={'execution_id': execution_id},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
                
        except Exception as e:
            print(f"[SHUFFLE] ✗ Error getting execution status: {e}")
            return None

    def wait_for_execution(self, execution_id: str, timeout: int = 300, poll_interval: int = 5) -> Optional[Dict]:
        """
        Wait for workflow execution to complete
        
        Args:
            execution_id: Execution ID to wait for
            timeout: Maximum time to wait in seconds
            poll_interval: Time between status checks
            
        Returns:
            Final execution result
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            status = self.get_execution_status(execution_id)
            
            if status and status.get('status') in ['FINISHED', 'SUCCESS', 'ABORTED', 'FAILURE']:
                print(f"[SHUFFLE] Execution completed with status: {status.get('status')}")
                return status
            
            time.sleep(poll_interval)
        
        print(f"[SHUFFLE] ⚠ Execution timeout after {timeout}s")
        return None

    def trigger_incident_response_workflow(self, alert_data: Dict) -> Optional[Dict]:
        """
        Trigger incident response workflow based on alert
        
        Args:
            alert_data: Alert/incident data to process
            
        Returns:
            Workflow execution result
        """
        # Build execution data from alert
        execution_data = {
            "alert_id": alert_data.get('id', 'unknown'),
            "alert_rule": alert_data.get('rule', {}).get('id', 'unknown'),
            "alert_level": alert_data.get('rule', {}).get('level', 0),
            "alert_description": alert_data.get('rule', {}).get('description', ''),
            "agent_id": alert_data.get('agent', {}).get('id', 'unknown'),
            "agent_name": alert_data.get('agent', {}).get('name', 'unknown'),
            "timestamp": alert_data.get('timestamp', datetime.now().isoformat()),
            "mitre_tactics": alert_data.get('rule', {}).get('mitre', {}).get('tactic', []),
            "mitre_techniques": alert_data.get('rule', {}).get('mitre', {}).get('technique', []),
            "threat_score": alert_data.get('threat_score', 0.0),
            "full_alert": json.dumps(alert_data)
        }

        print(f"[SHUFFLE] Triggering incident response for alert: {execution_data['alert_id']}")
        
        # Get incident response workflow ID from config or environment
        workflow_id = self._get_incident_response_workflow_id()
        
        if workflow_id:
            return self.execute_workflow(workflow_id, execution_data)
        else:
            print("[SHUFFLE] ⚠ No incident response workflow configured")
            return None

    def trigger_threat_hunting_workflow(self, hunt_params: Dict) -> Optional[Dict]:
        """
        Trigger automated threat hunting workflow
        
        Args:
            hunt_params: Threat hunting parameters (IOCs, timeframe, etc.)
            
        Returns:
            Workflow execution result
        """
        execution_data = {
            "hunt_type": hunt_params.get('hunt_type', 'generic'),
            "iocs": hunt_params.get('iocs', []),
            "timeframe": hunt_params.get('timeframe', '24h'),
            "data_sources": hunt_params.get('data_sources', ['wazuh', 'splunk', 'crowdstrike']),
            "timestamp": datetime.now().isoformat()
        }

        print(f"[SHUFFLE] Triggering threat hunting workflow: {execution_data['hunt_type']}")
        
        workflow_id = self._get_threat_hunting_workflow_id()
        
        if workflow_id:
            return self.execute_workflow(workflow_id, execution_data)
        else:
            print("[SHUFFLE] ⚠ No threat hunting workflow configured")
            return None

    def enrich_alert_with_misp(self, alert_data: Dict) -> Optional[Dict]:
        """
        Trigger MISP enrichment workflow for alert
        
        Args:
            alert_data: Alert data to enrich
            
        Returns:
            Enrichment workflow execution result
        """
        execution_data = {
            "alert_id": alert_data.get('id'),
            "iocs": self._extract_iocs_from_alert(alert_data),
            "alert_data": json.dumps(alert_data),
            "timestamp": datetime.now().isoformat()
        }

        print(f"[SHUFFLE] Triggering MISP enrichment workflow")
        
        workflow_id = self._get_misp_enrichment_workflow_id()
        
        if workflow_id:
            return self.execute_workflow(workflow_id, execution_data)
        else:
            print("[SHUFFLE] ⚠ No MISP enrichment workflow configured")
            return None

    def isolate_endpoint(self, agent_id: str, reason: str = "") -> Optional[Dict]:
        """
        Trigger endpoint isolation workflow
        
        Args:
            agent_id: Wazuh agent ID to isolate
            reason: Reason for isolation
            
        Returns:
            Workflow execution result
        """
        execution_data = {
            "agent_id": agent_id,
            "action": "isolate",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "automated": True
        }

        print(f"[SHUFFLE] Triggering endpoint isolation for agent: {agent_id}")
        
        workflow_id = self._get_endpoint_isolation_workflow_id()
        
        if workflow_id:
            return self.execute_workflow(workflow_id, execution_data)
        else:
            print("[SHUFFLE] ⚠ No endpoint isolation workflow configured")
            return None

    def create_case_in_ticketing(self, incident_data: Dict, ticketing_system: str = "generic") -> Optional[Dict]:
        """
        Create incident ticket/case via workflow
        
        Args:
            incident_data: Incident information
            ticketing_system: Target ticketing system (jira, servicenow, etc.)
            
        Returns:
            Workflow execution result
        """
        execution_data = {
            "title": incident_data.get('title', 'Security Incident'),
            "description": incident_data.get('description', ''),
            "severity": incident_data.get('severity', 'medium'),
            "alert_data": json.dumps(incident_data.get('alert_data', {})),
            "ticketing_system": ticketing_system,
            "timestamp": datetime.now().isoformat()
        }

        print(f"[SHUFFLE] Creating case in {ticketing_system}")
        
        workflow_id = self._get_ticketing_workflow_id()
        
        if workflow_id:
            return self.execute_workflow(workflow_id, execution_data)
        else:
            print("[SHUFFLE] ⚠ No ticketing workflow configured")
            return None

    def _extract_iocs_from_alert(self, alert_data: Dict) -> List[str]:
        """Extract IOCs from alert data"""
        iocs = []
        
        # Extract IPs
        data = alert_data.get('data', {})
        if 'srcip' in data:
            iocs.append(data['srcip'])
        if 'dstip' in data:
            iocs.append(data['dstip'])
        
        # Extract domains/URLs
        if 'url' in data:
            iocs.append(data['url'])
        if 'domain' in data:
            iocs.append(data['domain'])
        
        # Extract hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            if hash_type in data:
                iocs.append(data[hash_type])
        
        return iocs

    def _get_incident_response_workflow_id(self) -> Optional[str]:
        """Get incident response workflow ID from config"""
        # This should be configured via environment variables or config file
        import os
        return os.environ.get('SHUFFLE_INCIDENT_RESPONSE_WORKFLOW_ID')

    def _get_threat_hunting_workflow_id(self) -> Optional[str]:
        """Get threat hunting workflow ID from config"""
        import os
        return os.environ.get('SHUFFLE_THREAT_HUNTING_WORKFLOW_ID')

    def _get_misp_enrichment_workflow_id(self) -> Optional[str]:
        """Get MISP enrichment workflow ID from config"""
        import os
        return os.environ.get('SHUFFLE_MISP_ENRICHMENT_WORKFLOW_ID')

    def _get_endpoint_isolation_workflow_id(self) -> Optional[str]:
        """Get endpoint isolation workflow ID from config"""
        import os
        return os.environ.get('SHUFFLE_ENDPOINT_ISOLATION_WORKFLOW_ID')

    def _get_ticketing_workflow_id(self) -> Optional[str]:
        """Get ticketing workflow ID from config"""
        import os
        return os.environ.get('SHUFFLE_TICKETING_WORKFLOW_ID')

    def list_workflows(self) -> List[Dict]:
        """
        List all available workflows in Shuffle
        
        Returns:
            List of workflow dictionaries
        """
        try:
            response = self.session.get(
                f'{self.shuffle_url}/api/v1/workflows',
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                workflows = response.json()
                print(f"[SHUFFLE] Found {len(workflows)} workflows")
                return workflows
            else:
                print(f"[SHUFFLE] ✗ Failed to list workflows: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"[SHUFFLE] ✗ Error listing workflows: {e}")
            return []

    def get_workflow_by_name(self, name: str) -> Optional[Dict]:
        """
        Find workflow by name
        
        Args:
            name: Workflow name to search for
            
        Returns:
            Workflow dictionary if found
        """
        workflows = self.list_workflows()
        for workflow in workflows:
            if workflow.get('name') == name:
                return workflow
        return None

    def create_webhook_trigger(self, workflow_id: str, name: str = "webhook") -> Optional[str]:
        """
        Create webhook trigger for workflow
        
        Args:
            workflow_id: Workflow ID to add trigger to
            name: Webhook name
            
        Returns:
            Webhook URL if successful
        """
        try:
            trigger_data = {
                "name": name,
                "type": "WEBHOOK",
                "status": "running",
                "workflow_id": workflow_id
            }
            
            response = self.session.post(
                f'{self.shuffle_url}/api/v1/workflows/{workflow_id}/triggers',
                json=trigger_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                webhook_url = f"{self.shuffle_url}/api/v1/hooks/{result.get('id')}"
                print(f"[SHUFFLE] ✓ Created webhook: {webhook_url}")
                return webhook_url
            else:
                print(f"[SHUFFLE] ✗ Failed to create webhook: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[SHUFFLE] ✗ Error creating webhook: {e}")
            return None


# Convenience function for quick initialization
def init_shuffle(shuffle_url: str = "http://localhost:3001", api_key: str = None) -> ShuffleOrchestrator:
    """
    Initialize Shuffle orchestrator with default settings
    
    Args:
        shuffle_url: Shuffle instance URL
        api_key: Shuffle API key
        
    Returns:
        ShuffleOrchestrator instance
    """
    return ShuffleOrchestrator(shuffle_url=shuffle_url, api_key=api_key)
