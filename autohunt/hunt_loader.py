# autohunt/hunt_loader.py
"""
Automated Hunt Loader
Dynamically loads and executes threat hunting scripts
"""

import os
import importlib.util
from pathlib import Path
from datetime import datetime

class HuntLoader:
    """Load and execute threat hunts from autohunt/hunts/"""

    def __init__(self, hunts_dir='autohunt/hunts'):
        self.hunts_dir = Path(hunts_dir)
        self.hunts = {}
        self.hunt_results = []
        self.load_hunts()

    def load_hunts(self):
        """Discover and load all hunt scripts"""
        if not self.hunts_dir.exists():
            print(f"⚠️  Hunts directory not found: {self.hunts_dir}")
            return

        print(f"🔍 Loading threat hunts from {self.hunts_dir}...")

        for file_path in self.hunts_dir.glob('*.py'):
            if file_path.name.startswith('_'):
                continue

            hunt_name = file_path.stem

            try:
                # Load module
                spec = importlib.util.spec_from_file_location(hunt_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Store hunt
                self.hunts[hunt_name] = module
                print(f"  ✓ Loaded: {hunt_name}")

            except Exception as e:
                print(f"  ✗ Failed to load {hunt_name}: {e}")

        print(f"✅ {len(self.hunts)} hunt(s) loaded\n")

    def execute_hunt(self, hunt_name, **kwargs):
        """Execute a specific threat hunt"""
        if hunt_name not in self.hunts:
            print(f"❌ Hunt '{hunt_name}' not found")
            return None

        try:
            hunt = self.hunts[hunt_name]

            # Check if hunt has hunt function
            if hasattr(hunt, 'hunt'):
                print(f"🎯 Executing hunt: {hunt_name}")
                result = hunt.hunt(**kwargs)

                # Log result
                self.hunt_results.append({
                    'hunt_name': hunt_name,
                    'timestamp': datetime.now().isoformat(),
                    'result': result
                })

                return result
            else:
                print(f"❌ Hunt '{hunt_name}' missing hunt() function")
                return None

        except Exception as e:
            print(f"❌ Error executing hunt '{hunt_name}': {e}")
            return None

    def execute_all_hunts(self, **kwargs):
        """Execute all loaded hunts"""
        print("🚀 Executing all threat hunts...")
        print("="*70 + "\n")

        results = {}
        for hunt_name in self.hunts.keys():
            result = self.execute_hunt(hunt_name, **kwargs)
            results[hunt_name] = result
            print()

        return results

    def list_hunts(self):
        """List all available hunts"""
        print("🔍 Available Threat Hunts:")
        for name, module in self.hunts.items():
            description = getattr(module, '__doc__', 'No description').strip()
            print(f"  • {name}: {description.split(chr(10))[0]}")
        print()