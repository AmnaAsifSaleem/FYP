"""Watch the atomic snapshot manifest; retry pending changes after debounce."""
import os,time,sys,subprocess
from pipeline_paths import RUNTIME_FOLDER
WATCH_DIR=RUNTIME_FOLDER
SYNC_SCRIPT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"Database","sync_db.py")
DEBOUNCE_SECONDS=5
def log(message,*args):print(message,flush=True)
def run_sync(wipe=False,reset=False):
    # Reset/wipe are explicit database maintenance, never triggered by watcher.
    try:result=subprocess.run([sys.executable,SYNC_SCRIPT],capture_output=True,text=True,timeout=120)
    except subprocess.TimeoutExpired:
        log('Sync timed out; pending cycle retained for retry');return False
    log(result.stdout if result.returncode==0 else result.stderr or result.stdout)
    return result.returncode==0
def watch_polling():
    path=os.path.join(WATCH_DIR,'snapshot.json');last=None;pending=None;due=0
    log(f'Watching complete monitoring cycles in {WATCH_DIR}')
    while True:
        try:
            stamp=os.stat(path).st_mtime_ns
            if stamp!=last and stamp!=pending:
                pending=stamp;due=time.monotonic()+DEBOUNCE_SECONDS
            if pending is not None and time.monotonic()>=due:
                if run_sync():last=pending;pending=None
                else:due=time.monotonic()+DEBOUNCE_SECONDS
        except FileNotFoundError:pass
        except KeyboardInterrupt:break
        except Exception as e:log(f'Watcher retry: {e}')
        time.sleep(1)
watch_watchdog=watch_polling
if __name__=='__main__':
    os.makedirs(WATCH_DIR,exist_ok=True)
    with open(os.path.join(WATCH_DIR,'watcher.lock'),'a+b') as lock:
        try:
            lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except (OSError,BlockingIOError):
            print('Another watcher is already active');sys.exit(0)
        watch_polling()
