"""Read-only monitoring presentation; saved observations are not current status."""
import subprocess,time
from docker_backend import command
_cached=False
_expires=0.0
def scan_running():
    global _cached,_expires
    if time.monotonic()<_expires:return _cached
    try:
        result=subprocess.run(command('ps','--filter','name=caveot-engine','--filter','status=running','--format','{{.Names}}'),capture_output=True,text=True,timeout=5)
        _cached=result.returncode==0 and 'caveot-engine' in result.stdout.splitlines()
    except (OSError,subprocess.TimeoutExpired):_cached=False
    _expires=time.monotonic()+3
    return _cached
def asset_view(asset,running):
    result=dict(asset)
    result['last_observed_status']=result.get('status')
    if not running:
        result['status']='NOT_MONITORED'
        result['status_label']='Not monitored'
        result['status_reason']='Scanning is stopped. Last-seen information belongs to a saved scan.'
    elif not result.get('observed_recently',False):
        result['status']='INACTIVE'
        result['status_label']='Not recently seen'
        result['status_reason']='No recent observation in the current monitoring window.'
    else:
        result['status_label']='Active' if result.get('status')=='ACTIVE' else 'Not recently seen'
    return result
