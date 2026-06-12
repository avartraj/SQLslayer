"""
tests/_bootstrap.py — make the SQLSlayer tool importable from the tests folder.

The tool (ssqli_agent/) uses top-level imports (config, agent.*, recon.*,
utils.*, scanner). The tests live in a sibling folder, so we add the tool's
directory to sys.path here. Import this module first in every test file.

Paths exposed:
    ROOT    — repository root (SQLI agent/)
    TOOL    — ssqli_agent/   (the SQLSlayer tool)
    TARGET  — vulnerable_target/   (the deliberately-vulnerable demo API)
"""
import sys
import os

HERE   = os.path.dirname(os.path.abspath(__file__))
ROOT   = os.path.dirname(HERE)
TOOL   = os.path.join(ROOT, "ssqli_agent")
TARGET = os.path.join(ROOT, "vulnerable_target")

for _p in (HERE, TOOL, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
