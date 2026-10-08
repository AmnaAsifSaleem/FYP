import sys,json,os
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import docker_backend

def test_wsl_command_uses_argument_list(monkeypatch):
 monkeypatch.setenv('CAVE_OT_DOCKER_BACKEND','wsl');monkeypatch.setenv('CAVE_OT_WSL_DISTRO','Ubuntu')
 args=docker_backend.command('compose','up','-d')
 if os.name=='nt':
  assert args[:4]==['wsl','-d','Ubuntu','--cd']
  assert args[4].startswith('/mnt/') and args[4].endswith('/docker')
  assert args[5:]==['--','docker','compose','up','-d']
 else:assert args==['docker','compose','up','-d']
def test_native_command(monkeypatch):
 monkeypatch.setenv('CAVE_OT_DOCKER_BACKEND','native')
 assert docker_backend.command('info')==['docker','info']
def test_invalid_distribution_rejected(monkeypatch):
 monkeypatch.setenv('CAVE_OT_WSL_DISTRO','Ubuntu; arbitrary command')
 with pytest.raises(ValueError):docker_backend.command('info')
def test_unknown_backend_rejected(monkeypatch):
 monkeypatch.setenv('CAVE_OT_DOCKER_BACKEND','unsupported')
 with pytest.raises(ValueError):docker_backend.command('info')
