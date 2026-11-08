"""Conftest for analysis tests - adds parent dir to path."""

import sys
from pathlib import Path

# Add the services/analysis directory to sys.path so that `analysis` package
# and its submodules are importable
_analysis_dir = Path(__file__).resolve().parent.parent
if str(_analysis_dir) not in sys.path:
    sys.path.insert(0, str(_analysis_dir))