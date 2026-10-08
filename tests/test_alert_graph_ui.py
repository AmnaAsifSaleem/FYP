import shutil
import subprocess
from pathlib import Path
import pytest

def test_alert_identity_and_graph_direction():
    node=shutil.which('node')
    if not node:pytest.skip('Node is required for browser logic regressions')
    root=Path(__file__).resolve().parents[1]
    result=subprocess.run([node,str(root/'tests/ui/test_alert_graph_ui.js'),str(root)],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
