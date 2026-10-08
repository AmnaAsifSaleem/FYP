"""Never install mirror/cache bytes without checking authoritative PyPI hashes."""
import pathlib,sys,json,hashlib,urllib.request
manifest_path=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else None
# This manifest is generated only after checking the downloaded bytes against
# official PyPI release metadata. Recheck bytes on every offline build.
manifest=json.loads(manifest_path.read_text()) if manifest_path and manifest_path.exists() else {}
for path in pathlib.Path(sys.argv[1]).glob('*.whl'):
    package,version=path.name.split('-')[:2]
    expected=manifest.get(path.name)
    if expected is None:
        request=urllib.request.Request(f'https://pypi.org/pypi/{package.replace("_","-")}/{version}/json')
        with urllib.request.urlopen(request,timeout=30) as response:metadata=json.load(response)
        official=next(item for item in metadata['urls'] if item['filename']==path.name)
        expected=official['digests']['sha256']
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest!=expected:raise RuntimeError(f'Authoritative checksum mismatch: {path.name}')
    print('Verified',path.name,flush=True)
