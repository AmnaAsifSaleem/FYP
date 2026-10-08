"""Publish complete immutable monitoring cycles; partial writes never ingest."""
import hashlib
import json
import os
import pathlib
import tempfile
import uuid
from datetime import datetime,timezone

FILES=('assets.json','vulnerability_scan_results.json','risk_scored_results.json','suricata_context.json','anomaly_results.json','attack_paths.json')
def atomic_json(path,value):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.',suffix='.tmp')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(value,f,indent=2,allow_nan=False);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def publish_cycle(source,shared):
    source=pathlib.Path(source);shared=pathlib.Path(shared)
    cycle=uuid.uuid4().hex;dest=shared/'cycles'/cycle;dest.mkdir(parents=True)
    hashes={}
    for name in FILES:
        raw=(source/name).read_bytes();json.loads(raw.decode('utf-8-sig'))
        (dest/name).write_bytes(raw);hashes[name]=hashlib.sha256(raw).hexdigest()
    atomic_json(shared/'snapshot.json',{'cycle_id':cycle,'generated_at':datetime.now(timezone.utc).isoformat(),'files':hashes})
    return cycle

def load_cycle(shared):
    shared=pathlib.Path(shared)
    manifest=json.loads((shared/'snapshot.json').read_text(encoding='utf-8'))
    cycle=manifest.get('cycle_id','')
    if len(cycle)!=32 or any(c not in '0123456789abcdef' for c in cycle):raise ValueError('Invalid cycle identifier')
    payload={}
    if set(manifest.get('files',{}))!=set(FILES):raise ValueError('Incomplete monitoring cycle')
    for name in FILES:
        raw=(shared/'cycles'/cycle/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=manifest['files'][name]:raise ValueError(f'Snapshot checksum mismatch: {name}')
        payload[name]=json.loads(raw.decode('utf-8-sig'))
    return manifest,payload
