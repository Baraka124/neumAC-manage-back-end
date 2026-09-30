"""Verify the matched archives before deployment; does not contact any service."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--frontend',type=Path,required=True);p.add_argument('--backend',type=Path,required=True);a=p.parse_args()
for directory in [a.frontend,a.backend]:
 for line in (directory/'CHECKSUMS.sha256').read_text().splitlines():
  digest,name=line.split('  ',1);file=directory/name
  assert file.is_file(),f'Missing {file}'
  assert hashlib.sha256(file.read_bytes()).hexdigest()==digest,f'Changed {file}'
 for file in directory.glob('*.js'):subprocess.run(['node','--check',str(file)],check=True,capture_output=True)
f=json.loads((a.frontend/'release.json').read_text());b=json.loads((a.backend/'release.json').read_text());assert f['id']==b['id'],'Frontend/backend release mismatch'
for ref in re.findall(r'(?:src|href)="([^"{}]+)"',(a.frontend/'index.html').read_text()):
 if ref.startswith(('https:','http:','//','#','data:')):continue
 ref=ref.split('?')[0]
 if Path(ref).suffix in ['.js','.css','.svg','.png']:assert (a.frontend/ref).is_file(),f'Missing frontend asset {ref}'
for file in a.backend.glob('*.js'):
 for ref in re.findall(r"require\(['\"](\./[^'\"]+)['\"]\)",file.read_text()):
  target=file.parent/ref
  assert target.is_file() or target.with_suffix('.js').is_file(),f'Missing backend module {ref}'
assert b['migration'] and (a.backend/b['migration']).is_file(),'Missing migration'
print(f"PASS: {f['id']}: checksums, all JavaScript syntax, release pairing, assets, modules and migration file. Live schema and account behavior require deployment testing.")
