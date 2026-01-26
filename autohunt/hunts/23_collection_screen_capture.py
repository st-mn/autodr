#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Collection: Screen Capture
Detects screen capture and screenshot activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ScreenCaptureHunter:
    """Hunt for screen capture activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_screenshot_tools(self) -> List[Dict]:
        """Detect screenshot tool usage"""
        findings = []
        
        screenshot_patterns = {
            'Windows Screenshot': r'screenshot|printscreen|screencap',
            'Linux Screenshot': r'scrot|gnome-screenshot|import\s+',
            'Mac Screenshot': r'screencapture|cmd.*shift.*3',
            'Third-party Tools': r'greenshot|sharex|snagit'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for tool_type, pattern in screenshot_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Screenshot Tool - {tool_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting screenshot tools: {e}")
        
        return findings
    
    def hunt_screen_recording(self) -> List[Dict]:
        """Detect screen recording activities"""
        findings = []
        
        recording_patterns = {
            'Video Recording': r'ffmpeg.*screen|recordmydesktop|simplescreenrecorder',
            'Built-in Recording': r'windows.*recorder|quicktime.*recording',
            'OBS Studio': r'obs.*record|obs.*stream',
            'Streaming': r'streaming.*active|screen.*stream'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for record_type, pattern in recording_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Screen Recording - {record_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting screen recording: {e}")
        
        return findings
    
    def hunt_clipboard_capture(self) -> List[Dict]:
        """Detect clipboard capture activities"""
        findings = []
        
        clipboard_patterns = {
            'Clipboard Access': r'clipboard|xclip|xsel|pbpaste',
            'Clipboard Monitor': r'clipboard.*monitor|monitor.*clipboard',
            'Clipboard Dump': r'clipboard.*dump|dump.*clipboard',
            'Clipboard Spy': r'clipboard.*spy|keylogger.*clipboard'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for clip_type, pattern in clipboard_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Clipboard Capture - {clip_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting clipboard capture: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_screenshot_tools())
        self.findings.extend(self.hunt_screen_recording())
        self.findings.extend(self.hunt_clipboard_capture())
        
        return {
            'tactic': 'Collection',
            'technique': 'Screen Capture',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ScreenCaptureHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
