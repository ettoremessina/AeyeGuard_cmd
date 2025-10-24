#!/usr/bin/env python3
"""
Quick setup verification script for AeyeGuard_cs.

This script checks if all dependencies are installed and
tests the connection to LM Studio.
"""

import sys
import subprocess

def check_python_version():
    """Check Python version."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} - Need 3.8+")
        return False

def check_dependencies():
    """Check if required packages are installed."""
    print("\nChecking dependencies...")
    required = ['langchain', 'langchain_community', 'requests', 'yaml']
    all_installed = True

    for package in required:
        try:
            if package == 'yaml':
                __import__('yaml')
                module_name = 'PyYAML'
            else:
                __import__(package)
                module_name = package

            print(f"  ✓ {module_name}")
        except ImportError:
            print(f"  ✗ {module_name} - Not installed")
            all_installed = False

    return all_installed

def check_lm_studio():
    """Check if LM Studio is accessible."""
    print("\nChecking LM Studio connection...")
    try:
        import requests
        response = requests.get('http://localhost:1234/v1/models', timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = data.get('data', [])
            if models:
                print(f"  ✓ LM Studio is running")
                print(f"  ✓ Loaded models: {[m.get('id') for m in models]}")
                return True
            else:
                print("  ⚠ LM Studio is running but no model loaded")
                print("    Please load a model in LM Studio")
                return False
        else:
            print(f"  ✗ LM Studio returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Cannot connect to LM Studio: {e}")
        print("    Make sure LM Studio is running on http://localhost:1234")
        return False

def install_dependencies():
    """Attempt to install dependencies."""
    print("\nAttempting to install dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', '../../requirements.txt'])
        print("  ✓ Dependencies installed successfully")
        return True
    except Exception as e:
        print(f"  ✗ Failed to install dependencies: {e}")
        return False

def main():
    """Run setup verification."""
    print("=" * 60)
    print("AeyeGuard_cs Setup Verification")
    print("=" * 60)

    all_good = True

    # Check Python version
    if not check_python_version():
        all_good = False
        print("\n⚠ Please upgrade to Python 3.8 or higher")

    # Check dependencies
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n⚠ Some dependencies are missing")
        response = input("Would you like to install them now? (y/n): ")
        if response.lower() == 'y':
            deps_ok = install_dependencies()
            if deps_ok:
                print("\nPlease run this script again to verify installation")
                return
        all_good = False

    # Check LM Studio
    if not check_lm_studio():
        all_good = False

    # Final status
    print("\n" + "=" * 60)
    if all_good:
        print("✓ Setup verification complete!")
        print("\nYou can now run:")
        print("  python AeyeGuard_cs.py ../examples/example_vulnerable.cs")
    else:
        print("⚠ Setup incomplete - Please address the issues above")
        print("\nFor help, see README.md")
    print("=" * 60)

if __name__ == '__main__':
    main()
