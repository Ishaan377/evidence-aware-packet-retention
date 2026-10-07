"""Prepare and inventory the small, reproducible private GitHub project copy."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
from zipfile import ZipFile, ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]
INVENTORY=ROOT/'logs/github_upload_inventory.json'
ROOT_FILES=('README.md','TEAM_START_HERE.md','CONTRIBUTING.md','run_project.py','requirements.txt','config.json','.gitignore','.gitattributes','progress_check.md','professor_explanation.md','final_project_roadmap.md','Network_Traffic_Forensics_Synopsis_FINAL.docx')
LOG_FILES=('action_log.md','continuation_notes.md','unit_tests.txt','result_audit.txt','scapy_verification.json','document_update_checks.json')

def digest(data): return hashlib.sha256(data).hexdigest()
def blob_digest(data): return hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()
def selected():
    files={ROOT/name for name in ROOT_FILES}
    for folder in ('src','demo','tests','tools','.github','docs','examples'):
        for p in (ROOT/folder).rglob('*'):
            if not p.is_file() or '__pycache__' in p.parts or p.suffix=='.pyc': continue
            rel=p.relative_to(ROOT)
            if rel.parts[:2] in (('docs','archive'),('docs','qa')) and rel.as_posix()!='docs/qa/template_evidence.json': continue
            files.add(p)
    files.update(ROOT/'logs'/name for name in LOG_FILES if (ROOT/'logs'/name).is_file())
    return sorted(files)
def prepare():
    entries=[]
    for p in selected():
        data=p.read_bytes()
        try:
            data.decode('utf-8')
            kind='text' if b'\0' not in data else 'binary'
        except UnicodeDecodeError: kind='binary'
        entries.append({'path':p.relative_to(ROOT).as_posix(),'bytes':len(data),'sha256':digest(data),'git_blob_sha':blob_digest(data),'kind':kind})
    inventory={'repository_full_name':'Ishaan377/evidence-aware-packet-retention','visibility':'private','status':'PREPARED_NOT_UPLOADED','scope':'Core/demo/tests/config, final documents, research/source notes, teammate/GitHub setup, original synopsis reference, small measured example and selected action/verification logs. Runtime data/results, virtual environments, render history and full exports remain local.','files':entries}
    INVENTORY.write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf-8')
    destination=ROOT/'logs/github_clone_check'
    destination.mkdir(exist_ok=True)
    for row in entries:
        target=destination/row['path']
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/row['path'],target)
    archive_path=ROOT/'logs/github_project_bundle.zip'
    with ZipFile(archive_path,'w',ZIP_DEFLATED) as z:
        for row in entries: z.write(ROOT/row['path'],row['path'])
    print(json.dumps({'files':len(entries),'bytes':sum(r['bytes'] for r in entries),'binary_files':[r['path'] for r in entries if r['kind']=='binary'],'fresh_copy':str(destination),'bundle':str(archive_path)}))
def read_chunk(path,offset,size):
    inventory=json.loads(INVENTORY.read_text(encoding='utf-8'))
    row=next((r for r in inventory['files'] if r['path']==path),None)
    if row is None: raise ValueError('Path is not in the reviewed upload inventory.')
    data=(ROOT/path).read_bytes()
    if digest(data)!=row['sha256']: raise ValueError('File changed after inventory preparation: '+path)
    if offset<0 or size<1 or size>32768: raise ValueError('Invalid chunk range.')
    print(json.dumps({'path':path,'offset':offset,'base64':base64.b64encode(data[offset:offset+size]).decode('ascii'),'total_bytes':len(data)}))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    sub.add_parser('prepare')
    r=sub.add_parser('read')
    r.add_argument('path')
    r.add_argument('--offset',type=int,default=0)
    r.add_argument('--size',type=int,default=32768)
    a=parser.parse_args()
    if a.operation=='prepare': prepare()
    else: read_chunk(a.path,a.offset,a.size)