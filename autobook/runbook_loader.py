"""
Automated Runbook Loader
Dynamically loads and executes incident response runbooks
"""

import os
import sys
import importlib.util
from pathlib import Path

class RunbookLoader:
    """Load and execute runbooks from autobook/runbooks/"""

    def __init__(self, runbooks_dir='autobook/runbooks'):
        self.runbooks_dir = Path(runbooks_dir)
        self.runbooks = {}
        self.load_runbooks()

    def load_runbooks(self):
        """Discover and load all runbook scripts"""
        if not self.runbooks_dir.exists():
            print(f"⚠️  Runbooks directory not found: {self.runbooks_dir}")
            return

        print(f"📚 Loading runbooks from {self.runbooks_dir}...")

        for file_path in self.runbooks_dir.glob('*.py'):
            if file_path.name.startswith('_'):
                continue

            runbook_name = file_path.stem

            try:
                # Load module
                spec = importlib.util.spec_from_file_location(runbook_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Store runbook
                self.runbooks[runbook_name] = module
                print(f"  ✓ Loaded: {runbook_name}")

            except Exception as e:
                print(f"  ✗ Failed to load {runbook_name}: {e}")

        print(f"✅ {len(self.runbooks)} runbook(s) loaded\n")

    def execute_runbook(self, runbook_name, **kwargs):
        """Execute a specific runbook"""
        if runbook_name not in self.runbooks:
            print(f"❌ Runbook '{runbook_name}' not found")
            return False

        try:
            runbook = self.runbooks[runbook_name]

            # Check if runbook has execute function
            if hasattr(runbook, 'execute'):
                print(f"📖 Executing runbook: {runbook_name}")
                result = runbook.execute(**kwargs)
                return result
            else:
                print(f"❌ Runbook '{runbook_name}' missing execute() function")
                return False

        except Exception as e:
            print(f"❌ Error executing runbook '{runbook_name}': {e}")
            return False

    def list_runbooks(self):
        """List all available runbooks"""
        print("📚 Available Runbooks:")
        for name, module in self.runbooks.items():
            description = getattr(module, '__doc__', 'No description').strip()
            print(f"  • {name}: {description.split(chr(10))[0]}")
        print()