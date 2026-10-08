"""Run the same Compose project through native Docker or installed WSL Docker."""
import json,os,re,subprocess
import hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
KEEPER_FILE=ROOT/'docker'/'shared'/'wsl-keeper.json'
KEEPER_TOKEN=hashlib.sha256(str(ROOT).encode()).hexdigest()[:24]

def keeper_alive():
    if os.name!='nt' or not KEEPER_FILE.exists():return False
    try:
        value=json.loads(KEEPER_FILE.read_text());pid=value['pid']
        if isinstance(pid,bool) or not isinstance(pid,int) or pid<1:return False
        script=f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' | Select-Object Name,CommandLine | ConvertTo-Json -Compress"
        result=subprocess.run(['powershell','-NoProfile','-Command',script],capture_output=True,text=True,timeout=10)
        process=json.loads(result.stdout)
        return process['Name'].lower()=='wsl.exe' and 'CAVE_OT_KEEPER_ID='+KEEPER_TOKEN in (process.get('CommandLine') or '')
    except (ValueError,KeyError,TypeError,subprocess.TimeoutExpired):return False

def ensure_keeper(distro):
    if keeper_alive():return
    process=subprocess.Popen(['wsl','-d',distro,'--exec','env','CAVE_OT_KEEPER_ID='+KEEPER_TOKEN,'sleep','infinity'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    KEEPER_FILE.parent.mkdir(parents=True,exist_ok=True)
    from snapshot_io import atomic_json
    atomic_json(KEEPER_FILE,{'pid':process.pid,'distro':distro,'project_token':KEEPER_TOKEN})

def release_keeper():
    if keeper_alive():
        pid=json.loads(KEEPER_FILE.read_text())['pid']
        subprocess.run(['taskkill','/PID',str(pid),'/F'],capture_output=True,timeout=10)
        KEEPER_FILE.unlink(missing_ok=True)
def settings():
    config={}
    path=ROOT/'docker'/'backend.json'
    if path.exists():config=json.loads(path.read_text(encoding='utf-8'))
    backend=os.environ.get('CAVE_OT_DOCKER_BACKEND',config.get('backend','native'))
    distro=os.environ.get('CAVE_OT_WSL_DISTRO',config.get('distro','Ubuntu'))
    if backend not in ('native','wsl'):raise ValueError('Unsupported container backend')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}',distro):raise ValueError('Invalid WSL distribution name')
    return backend,distro
def command(*args):
    backend,distro=settings()
    if backend=='wsl' and os.name=='nt':
        drive=ROOT.drive.rstrip(':').lower()
        if not re.fullmatch('[a-z]',drive):raise ValueError('WSL backend requires a local drive project path')
        directory='/mnt/'+drive+str(ROOT/'docker')[2:].replace('\\','/')
        return ['wsl','-d',distro,'--cd',directory,'--','docker',*args]
    return ['docker',*args]
def prepare():
    backend,distro=settings()
    if backend=='wsl' and os.name=='nt':
        ensure_keeper(distro)
        result=subprocess.run(['wsl','-d',distro,'-u','root','--','service','docker','start'],capture_output=True,text=True,timeout=30)
        if result.returncode:raise RuntimeError('Unable to start the installed container engine')
def main():
    import sys
    if not sys.argv[1:]:raise SystemExit('Usage: python docker_backend.py compose up -d --build')
    prepare()
    result=subprocess.run(command(*sys.argv[1:]),cwd=ROOT/'docker')
    if sys.argv[1:3]==['compose','down'] and result.returncode==0:release_keeper()
    raise SystemExit(result.returncode)
if __name__=='__main__':main()
