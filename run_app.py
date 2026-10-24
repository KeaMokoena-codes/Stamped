"""
Entry point wrapper for the Streamlit app.
Run this using: python -m streamlit run run_app.py
This ensures the Stamped root directory is correctly added to Python's sys.path
so internal module imports (like 'access', 'detect', 'seal') resolve correctly.
"""

import sys
from pathlib import Path

# Force the repository root into the Python path
repo_root = Path(__file__).resolve().parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# Import the actual Streamlit app and run it
from app.main import main

if __name__ == "__main__":
    main()