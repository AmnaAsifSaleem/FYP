import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT/'Dashboard'):
    sys.path.insert(0, str(directory))
import app
import docker_backend


@pytest.fixture(autouse=True)
def state(monkeypatch):
    monkeypatch.setattr(app, '_scan_operation', {'state': 'IDLE', 'message': '', 'error': None})
    monkeypatch.setattr(app, '_scan_running', lambda: False)


class ImmediateThread:
    def __init__(self, target, args=(), **kwargs):
        self.target, self.args = target, args
    def start(self):
        self.target(*self.args)


def test_start_failure_is_reported_and_retry_available(monkeypatch):
    monkeypatch.setattr(app.threading, 'Thread', ImmediateThread)
    def fail():
        raise RuntimeError('Build failed: engine unavailable')
    monkeypatch.setattr(app, '_ensure_docker_desktop_and_start', fail)
    client = app.app.test_client()
    assert client.post('/api/scan/start').status_code == 202
    status = client.get('/api/scan/status').json
    assert status['state'] == 'FAILED' and not status['busy']
    assert 'Build failed' in status['error']
    assert client.post('/api/scan/start').status_code == 202


def test_successful_start_unlocks_control(monkeypatch):
    monkeypatch.setattr(app.threading, 'Thread', ImmediateThread)
    monkeypatch.setattr(app, '_ensure_docker_desktop_and_start', lambda: None)
    monkeypatch.setattr(app, '_scan_running', lambda: True)
    client = app.app.test_client()
    assert client.post('/api/scan/start').status_code == 202
    status = client.get('/api/scan/status').json
    assert status['state'] == 'RUNNING' and not status['busy'] and status['error'] is None


def test_duplicate_operation_rejected(monkeypatch):
    app._scan_operation['state'] = 'STARTING'
    assert app.app.test_client().post('/api/scan/start').status_code == 409
    assert app.app.test_client().post('/api/scan/stop').status_code == 409


def test_stop_failure_is_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(app.threading, 'Thread', ImmediateThread)
    monkeypatch.setattr(app.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1, stderr='shutdown failed', stdout=''))
    client = app.app.test_client()
    assert client.post('/api/scan/stop').status_code == 202
    assert 'shutdown failed' in client.get('/api/scan/status').json['error']


def test_stop_waits_for_completion_and_releases_owned_keeper(monkeypatch):
    release = MagicMock()
    monkeypatch.setattr(app.threading, 'Thread', ImmediateThread)
    monkeypatch.setattr(docker_backend, 'release_keeper', release)
    monkeypatch.setattr(app.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stderr='', stdout=''))
    client = app.app.test_client()
    assert client.post('/api/scan/stop').status_code == 202
    assert client.get('/api/scan/status').json['state'] == 'STOPPED'
    release.assert_called_once()


def test_ready_engine_does_not_start_a_second_daemon(monkeypatch):
    prepare = MagicMock()
    monkeypatch.setattr(app, '_docker_daemon_ready', lambda: True)
    monkeypatch.setattr(app, '_scan_running', lambda: True)
    monkeypatch.setattr(docker_backend, 'prepare', prepare)
    monkeypatch.setattr(app.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stderr='', stdout=''))
    app._ensure_docker_desktop_and_start()
    prepare.assert_not_called()


def test_build_error_propagates(monkeypatch):
    monkeypatch.setattr(app, '_docker_daemon_ready', lambda: True)
    monkeypatch.setattr(app.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1, stderr='invalid compose file', stdout=''))
    with pytest.raises(RuntimeError, match='invalid compose file'):
        app._ensure_docker_desktop_and_start()


def test_browser_control_transitions():
    import shutil, subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required for browser control regression')
    result = subprocess.run([node, str(ROOT/'tests/ui/test_scan_controls.js'),
                             str(ROOT/'Dashboard/templates/base.html')], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
