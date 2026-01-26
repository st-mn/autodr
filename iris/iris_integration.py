"""
DFIR-IRIS Integration Module
Provides case management and investigation platform integration for AUTODR
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import warnings
warnings.filterwarnings('ignore')


class IrisIntegration:
    """
    DFIR-IRIS Integration for collaborative incident response and case management
    Connects AUTODR with IRIS for evidence tracking, investigation workflows, and collaboration
    """

    def __init__(self, iris_url: str = "http://localhost:8000", api_key: str = None):
        """
        Initialize IRIS integration
        
        Args:
            iris_url: IRIS instance URL (default: http://localhost:8000)
            api_key: IRIS API key for authentication
        """
        self.iris_url = iris_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })
        
        print(f"[IRIS] Initializing IRIS integration at {self.iris_url}")
        self._verify_connection()

    def _verify_connection(self):
        """Verify connection to IRIS instance"""
        try:
            response = self.session.get(f'{self.iris_url}/api/ping', verify=False, timeout=5)
            if response.status_code in [200, 401]:
                print("[IRIS] ✓ Successfully connected to IRIS")
                return True
            else:
                print(f"[IRIS] ⚠ IRIS connection warning: Status {response.status_code}")
                return False
        except Exception as e:
            print(f"[IRIS] ⚠ Could not connect to IRIS (will retry): {e}")
            return False

    def create_case(self, case_name: str, case_description: str, 
                   customer_id: int = 1, classification_id: int = 1,
                   severity_id: int = 4, case_tags: List[str] = None) -> Optional[Dict]:
        """
        Create a new case in IRIS
        
        Args:
            case_name: Name of the case
            case_description: Detailed description
            customer_id: Customer/client ID (default: 1)
            classification_id: Case classification (1=malicious, 2=legitimate, etc.)
            severity_id: Severity level (1=critical, 2=high, 3=medium, 4=low)
            case_tags: List of tags for the case
            
        Returns:
            Case object if successful, None otherwise
        """
        case_data = {
            "case_name": case_name,
            "case_description": case_description,
            "case_customer": customer_id,
            "case_classification": classification_id,
            "soc_id": severity_id,
            "case_tags": ",".join(case_tags) if case_tags else ""
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/manage/cases/add',
                json=case_data,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    case = result.get('data')
                    case_id = case.get('case_id') if case else None
                    print(f"[IRIS] ✓ Created case '{case_name}' (ID: {case_id})")
                    return case
                else:
                    print(f"[IRIS] ✗ Failed to create case: {result.get('message')}")
                    return None
            else:
                print(f"[IRIS] ✗ Failed to create case: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error creating case: {e}")
            return None

    def add_ioc(self, case_id: int, ioc_value: str, ioc_type: str,
                ioc_description: str = "", ioc_tags: List[str] = None,
                tlp: str = "amber") -> Optional[Dict]:
        """
        Add an IOC (Indicator of Compromise) to a case
        
        Args:
            case_id: Case ID to add IOC to
            ioc_value: IOC value (IP, domain, hash, etc.)
            ioc_type: Type of IOC (ip, domain, md5, sha256, url, etc.)
            ioc_description: Description of the IOC
            ioc_tags: Tags for the IOC
            tlp: Traffic Light Protocol (red, amber, green, white)
            
        Returns:
            IOC object if successful
        """
        # Map common types to IRIS type IDs (adjust based on your IRIS instance)
        ioc_type_map = {
            'ip': 1,
            'domain': 2,
            'url': 3,
            'md5': 4,
            'sha1': 5,
            'sha256': 6,
            'email': 7,
            'filename': 8
        }
        
        ioc_type_id = ioc_type_map.get(ioc_type.lower(), 1)
        
        ioc_data = {
            "ioc_value": ioc_value,
            "ioc_type_id": ioc_type_id,
            "ioc_description": ioc_description,
            "ioc_tags": ",".join(ioc_tags) if ioc_tags else "",
            "ioc_tlp_id": self._get_tlp_id(tlp)
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/ioc/add?cid={case_id}',
                json=ioc_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Added IOC: {ioc_value} ({ioc_type})")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to add IOC: {result.get('message')}")
                    return None
            else:
                print(f"[IRIS] ⚠ Failed to add IOC: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error adding IOC: {e}")
            return None

    def add_asset(self, case_id: int, asset_name: str, asset_type: str,
                  asset_description: str = "", asset_ip: str = "",
                  asset_compromised: bool = False) -> Optional[Dict]:
        """
        Add an asset (endpoint, server, etc.) to a case
        
        Args:
            case_id: Case ID
            asset_name: Name of the asset
            asset_type: Type (workstation, server, firewall, etc.)
            asset_description: Description
            asset_ip: IP address
            asset_compromised: Whether asset is compromised
            
        Returns:
            Asset object if successful
        """
        # Map asset types to IRIS type IDs
        asset_type_map = {
            'workstation': 1,
            'server': 2,
            'firewall': 3,
            'router': 4,
            'switch': 5,
            'android-device': 6,
            'ios-device': 7,
            'other': 8
        }
        
        asset_type_id = asset_type_map.get(asset_type.lower(), 1)
        
        asset_data = {
            "asset_name": asset_name,
            "asset_type_id": asset_type_id,
            "asset_description": asset_description,
            "asset_ip": asset_ip,
            "asset_compromised": asset_compromised,
            "asset_tags": "autodr,automated"
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/assets/add?cid={case_id}',
                json=asset_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Added asset: {asset_name}")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to add asset: {result.get('message')}")
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error adding asset: {e}")
            return None

    def add_note(self, case_id: int, note_title: str, note_content: str,
                 note_group_id: int = 1) -> Optional[Dict]:
        """
        Add a note/observation to a case
        
        Args:
            case_id: Case ID
            note_title: Note title
            note_content: Note content (supports Markdown)
            note_group_id: Note group/category ID
            
        Returns:
            Note object if successful
        """
        note_data = {
            "note_title": note_title,
            "note_content": note_content,
            "group_id": note_group_id
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/notes/add?cid={case_id}',
                json=note_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Added note: {note_title}")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to add note: {result.get('message')}")
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error adding note: {e}")
            return None

    def add_evidence(self, case_id: int, filename: str, file_path: str,
                     file_description: str = "", file_hash: str = "") -> Optional[Dict]:
        """
        Add evidence/file to a case
        
        Args:
            case_id: Case ID
            filename: Name of the evidence file
            file_path: Path to file or URL
            file_description: Description
            file_hash: File hash (MD5/SHA256)
            
        Returns:
            Evidence object if successful
        """
        evidence_data = {
            "filename": filename,
            "file_description": file_description,
            "file_hash": file_hash,
            "file_size": 0,
            "file_path": file_path
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/evidences/add?cid={case_id}',
                json=evidence_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Added evidence: {filename}")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to add evidence: {result.get('message')}")
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error adding evidence: {e}")
            return None

    def create_task(self, case_id: int, task_title: str, task_description: str,
                    assignee_id: int = 1, status_id: int = 1) -> Optional[Dict]:
        """
        Create a task in a case
        
        Args:
            case_id: Case ID
            task_title: Task title
            task_description: Task description
            assignee_id: User ID to assign to
            status_id: Task status (1=todo, 2=in-progress, 3=done)
            
        Returns:
            Task object if successful
        """
        task_data = {
            "task_title": task_title,
            "task_description": task_description,
            "task_assignee_id": assignee_id,
            "task_status_id": status_id,
            "task_tags": "autodr"
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/tasks/add?cid={case_id}',
                json=task_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Created task: {task_title}")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to create task: {result.get('message')}")
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error creating task: {e}")
            return None

    def add_timeline_event(self, case_id: int, event_title: str, event_date: str,
                          event_description: str = "", event_category_id: int = 1) -> Optional[Dict]:
        """
        Add an event to the case timeline
        
        Args:
            case_id: Case ID
            event_title: Event title
            event_date: Event datetime (ISO format)
            event_description: Event description
            event_category_id: Event category ID
            
        Returns:
            Timeline event object if successful
        """
        event_data = {
            "event_title": event_title,
            "event_date": event_date,
            "event_content": event_description,
            "event_category_id": event_category_id,
            "event_tags": "autodr,automated"
        }

        try:
            response = self.session.post(
                f'{self.iris_url}/case/timeline/events/add?cid={case_id}',
                json=event_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"[IRIS] ✓ Added timeline event: {event_title}")
                    return result.get('data')
                else:
                    print(f"[IRIS] ⚠ Failed to add event: {result.get('message')}")
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error adding timeline event: {e}")
            return None

    def create_case_from_alert(self, alert_data: Dict) -> Optional[Dict]:
        """
        Create an IRIS case from AUTODR alert with all relevant information
        
        Args:
            alert_data: Alert dictionary from AUTODR
            
        Returns:
            Case object with all created elements
        """
        # Extract alert information
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        data = alert_data.get('data', {})
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        # Determine severity based on rule level
        rule_level = rule.get('level', 0)
        if rule_level >= 12:
            severity_id = 1  # Critical
        elif rule_level >= 10:
            severity_id = 2  # High
        elif rule_level >= 7:
            severity_id = 3  # Medium
        else:
            severity_id = 4  # Low
        
        # Create case
        case_name = f"AUTODR-{alert_data.get('id', 'unknown')}: {rule.get('description', 'Security Alert')}"
        case_description = f"""# Security Alert from AUTODR

## Alert Details
- **Alert ID**: {alert_data.get('id', 'N/A')}
- **Rule ID**: {rule.get('id', 'N/A')}
- **Rule Description**: {rule.get('description', 'N/A')}
- **Rule Level**: {rule_level}
- **Timestamp**: {timestamp}

## Agent Information
- **Agent ID**: {agent.get('id', 'N/A')}
- **Agent Name**: {agent.get('name', 'N/A')}
- **Agent IP**: {agent.get('ip', 'N/A')}

## MITRE ATT&CK
- **Tactics**: {', '.join(rule.get('mitre', {}).get('tactic', []))}
- **Techniques**: {', '.join(rule.get('mitre', {}).get('technique', []))}

## ML Threat Score
- **Score**: {alert_data.get('threat_score', 'N/A')}

## Additional Data
```json
{json.dumps(data, indent=2)}
```
"""
        
        case_tags = ["autodr", "automated", "security-alert"]
        if rule.get('mitre', {}).get('tactic'):
            case_tags.extend([t.lower().replace(' ', '-') for t in rule['mitre']['tactic']])
        
        case = self.create_case(
            case_name=case_name,
            case_description=case_description,
            severity_id=severity_id,
            case_tags=case_tags
        )
        
        if not case:
            return None
        
        case_id = case.get('case_id')
        
        # Add compromised asset
        if agent.get('id') and agent.get('id') != '000':
            self.add_asset(
                case_id=case_id,
                asset_name=agent.get('name', 'Unknown'),
                asset_type='workstation',
                asset_description=f"Agent ID: {agent.get('id')}",
                asset_ip=agent.get('ip', ''),
                asset_compromised=True if rule_level >= 10 else False
            )
        
        # Add IOCs from alert data
        iocs_added = []
        for key in ['srcip', 'dstip', 'domain', 'url', 'md5', 'sha1', 'sha256']:
            if key in data and data[key]:
                ioc_type = 'ip' if 'ip' in key else key
                ioc = self.add_ioc(
                    case_id=case_id,
                    ioc_value=data[key],
                    ioc_type=ioc_type,
                    ioc_description=f"Extracted from {key} field in alert",
                    ioc_tags=["autodr", "malicious"]
                )
                if ioc:
                    iocs_added.append(data[key])
        
        # Add timeline event for the alert
        self.add_timeline_event(
            case_id=case_id,
            event_title=rule.get('description', 'Security Alert'),
            event_date=timestamp,
            event_description=f"Alert detected by AUTODR. Rule: {rule.get('id')}, Level: {rule_level}",
            event_category_id=1
        )
        
        # Create investigation tasks
        self.create_task(
            case_id=case_id,
            task_title="Analyze Alert and Validate Threat",
            task_description="Review AUTODR alert details, validate ML threat score, and confirm if threat is genuine."
        )
        
        if rule_level >= 10:
            self.create_task(
                case_id=case_id,
                task_title="Containment Actions",
                task_description="Verify endpoint isolation status, confirm IOC blocking, and ensure threat is contained."
            )
        
        self.create_task(
            case_id=case_id,
            task_title="Root Cause Analysis",
            task_description="Investigate how the threat entered the environment and identify security gaps."
        )
        
        # Add initial note
        self.add_note(
            case_id=case_id,
            note_title="Automated Case Creation",
            note_content=f"""This case was automatically created by AUTODR in response to a security alert.

**Automated Actions Taken:**
- Alert detected and analyzed
- ML threat scoring completed (Score: {alert_data.get('threat_score', 'N/A')})
- {'Endpoint isolated and quarantined' if rule_level >= 10 else 'Alert logged for review'}

**Next Steps:**
1. Review alert details and validate threat
2. Analyze IOCs and check for related activity
3. Investigate affected assets
4. Complete containment if not already done
5. Perform eradication and recovery
6. Update case with findings
"""
        )
        
        print(f"[IRIS] ✓ Case created with {len(iocs_added)} IOCs and investigation tasks")
        
        return {
            'case': case,
            'case_id': case_id,
            'iocs_added': iocs_added,
            'automated': True
        }

    def update_case_status(self, case_id: int, status_id: int) -> bool:
        """
        Update case status
        
        Args:
            case_id: Case ID
            status_id: Status ID (1=open, 2=in progress, 3=closed, etc.)
            
        Returns:
            True if successful
        """
        try:
            response = self.session.post(
                f'{self.iris_url}/manage/cases/update/{case_id}',
                json={'case_status_id': status_id},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[IRIS] ✓ Updated case {case_id} status")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"[IRIS] ✗ Error updating case status: {e}")
            return False

    def get_case(self, case_id: int) -> Optional[Dict]:
        """
        Get case details
        
        Args:
            case_id: Case ID
            
        Returns:
            Case object if found
        """
        try:
            response = self.session.get(
                f'{self.iris_url}/manage/cases/{case_id}',
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    return result.get('data')
                else:
                    return None
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error getting case: {e}")
            return None

    def list_cases(self, page: int = 1, per_page: int = 10) -> List[Dict]:
        """
        List all cases
        
        Args:
            page: Page number
            per_page: Cases per page
            
        Returns:
            List of cases
        """
        try:
            response = self.session.get(
                f'{self.iris_url}/manage/cases/list?page={page}&per_page={per_page}',
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    return result.get('data', [])
                else:
                    return []
            else:
                return []
                
        except Exception as e:
            print(f"[IRIS] ✗ Error listing cases: {e}")
            return []

    def _get_tlp_id(self, tlp: str) -> int:
        """Get TLP ID from string"""
        tlp_map = {
            'red': 1,
            'amber': 2,
            'green': 3,
            'white': 4
        }
        return tlp_map.get(tlp.lower(), 2)

    def export_case(self, case_id: int) -> Optional[Dict]:
        """
        Export case data
        
        Args:
            case_id: Case ID to export
            
        Returns:
            Complete case data
        """
        try:
            response = self.session.get(
                f'{self.iris_url}/case/export?cid={case_id}',
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"[IRIS] ✓ Exported case {case_id}")
                return response.json()
            else:
                return None
                
        except Exception as e:
            print(f"[IRIS] ✗ Error exporting case: {e}")
            return None


# Convenience function for quick initialization
def init_iris(iris_url: str = "http://localhost:8000", api_key: str = None) -> IrisIntegration:
    """
    Initialize IRIS integration with default settings
    
    Args:
        iris_url: IRIS instance URL
        api_key: IRIS API key
        
    Returns:
        IrisIntegration instance
    """
    return IrisIntegration(iris_url=iris_url, api_key=api_key)
