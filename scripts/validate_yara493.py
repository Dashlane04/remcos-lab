"""Read-only YARA validation in the disposable VM; never executes the specimen.

Records matches, explicit non-matches and errors. Decrypted settings remain in
memory. No RC4 keys or decrypted binary blobs are written into scan telemetry.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib,json,platform,shutil,socket,time
from pathlib import Path
import pefile
import yara

SAMPLE_SHA='0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5'
PLAIN_SHA='9eba7761aad8594f7df92cc39c957b3085fa8a6d0143c7108104495da1255f40'
NATIVE='Remcos_493Pro_Settings_RC4_x86'
CONFIG='Remcos_493_Case_DecodedConfig_IOCs'
RULE_NAMES=(NATIVE,CONFIG)
KSA=bytes.fromhex('33d28bc3f77424180fb6042a03049f03f081e6ff00008079084e81ce00ffffff468a0c9f8b04b789049f430fb6c18904b781fb00010000')
def now():return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def sha(data):return hashlib.sha256(data).hexdigest()
def rc4(key,source):
    s=list(range(256));j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&255;s[i],s[j]=s[j],s[i]
    i=j=0;out=bytearray()
    for v in source:
        i=(i+1)&255;j=(j+s[i])&255;s[i],s[j]=s[j],s[i]
        out.append(v^s[(s[i]+s[j])&255])
    return bytes(out)

def references(per_arch):
    found=[]
    for folder,machine in ((Path('C:/Windows/System32'),0x8664),(Path('C:/Windows/SysWOW64'),0x14c)):
        selected=[]
        for p in sorted(folder.glob('*.exe'),key=lambda p:p.name.casefold()):
            if not 4096<=p.stat().st_size<2*1024*1024:continue
            try:
                pe=pefile.PE(str(p),fast_load=True);m=pe.FILE_HEADER.Machine;pe.close()
            except (OSError,pefile.PEFormatError):continue
            if m!=machine:continue
            selected.append(p)
            if len(selected)==per_arch:break
        if len(selected)!=per_arch:raise RuntimeError(f'Insufficient {machine:x} OS references: {len(selected)}')
        found.extend((p,'os-reference-x86' if machine==0x14c else 'os-reference-x64') for p in selected)
    return found

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sample',type=Path,required=True)
    ap.add_argument('--rules',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--run-id',required=True)
    ap.add_argument('--references-per-arch',type=int,default=64)
    a=ap.parse_args()
    if a.output.exists():raise RuntimeError('Choose a new output directory; do not overwrite a scan run')
    raw=a.sample.read_bytes();assert sha(raw)==SAMPLE_SHA
    rules_sha=sha(a.rules.read_bytes())
    rules=yara.compile(filepath=str(a.rules),error_on_warning=True,includes=False)
    pe=pefile.PE(data=raw)
    resource=next(lang for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries if typ.id==10
        for name in typ.directory.entries if str(name.name)=='SETTINGS' for lang in name.directory.entries)
    r=resource.data.struct;blob=pe.get_data(r.OffsetToData,r.Size)
    assert rc4(b'Key',b'Plaintext').hex()=='bbf316e8d940af0ad3'
    k=blob[0];plain=rc4(blob[1:k+1],blob[k+1:]);assert sha(plain)==PLAIN_SHA
    assert KSA in raw
    a.output.mkdir(parents=True)
    renamed=a.output/'same-bytes-renamed.bin';shutil.copyfile(a.sample,renamed)
    refs=references(a.references_per_arch)
    inputs=[('original-native',raw,str(a.sample),'file',{NATIVE},'specimen'),
      ('renamed-same-bytes',renamed.read_bytes(),str(renamed),'file',{NATIVE},'same-specimen-copy'),
      ('decoded-settings',plain,'[decoded SETTINGS buffer; not written to disk]','decoded-buffer',{CONFIG},'specimen-derived-buffer')]
    for i,(p,group) in enumerate(refs,1):inputs.append((f'reference-{i:03d}',None,str(p),'file',set(),group))
    notes=b'Analyst IOC notes only\nremchukwugixiemu4.duckdns.org\nremchukwugix231fgh.duckdns.org\nakpleoeurs-QPYUMO\nlpaowtrts.dat\n'
    inputs.extend([
      ('invalid-pe-feature-text',b'MZ'+b'\x00'*62+b'4.9.3 Pro\x00'+KSA+'SETTINGS'.encode('utf-16le'),'[non-executable invalid-PE control]','synthetic-buffer',set(),'synthetic-control'),
      ('domains-only',b'remchukwugixiemu4.duckdns.org\nremchukwugix231fgh.duckdns.org','[domains-only control]','synthetic-buffer',set(),'synthetic-control'),
      ('benign-ioc-notes',notes,'[benign analyst IOC notes]','synthetic-buffer',{CONFIG},'synthetic-control')])
    rows=[];corpus=[];errors=[];mismatches=[];started=now()
    for input_id,data,display,kind,expected,group in inputs:
        stamp=now();begin=time.perf_counter();outcome='success';error=None
        try:
            if data is None:data=Path(display).read_bytes()
            digest=sha(data)
            try:
                pp=pefile.PE(data=data,fast_load=True);machine=pp.FILE_HEADER.Machine;pp.close()
            except pefile.PEFormatError:machine=None
            found={m.rule:m for m in rules.match(data=data,timeout=10)}
        except (OSError,yara.Error) as e:
            outcome='failure';error=type(e).__name__+': '+str(e);found={};digest=None;machine=None
            errors.append({'input_id':input_id,'error':error})
        elapsed=round((time.perf_counter()-begin)*1000,3)
        corpus.append({'input_id':input_id,'path':display,'group':group,'sha256':digest,'bytes':None if data is None else len(data),'pe_machine':machine,'expected_rules':sorted(expected),'outcome':outcome})
        for rule_name in RULE_NAMES:
            m=found.get(rule_name);actual=bool(m);expect=rule_name in expected
            passed=outcome=='success' and actual==expect
            if not passed:mismatches.append({'input_id':input_id,'rule':rule_name,'expected':expect,'actual':actual,'outcome':outcome})
            witnesses=[]
            if m:
                for sm in m.strings:
                    for si in sm.instances[:8]:
                        witnesses.append({'identifier':sm.identifier,'offset':si.offset,'offset_hex':hex(si.offset),'length':si.matched_length})
            rows.append({'@timestamp':stamp,'event':{'dataset':'lab.yara','kind':'event','action':'yara-rule-evaluation','outcome':outcome,'id':sha((a.run_id+'|'+input_id+'|'+rules_sha+'|'+rule_name).encode())},'host':{'name':socket.gethostname()},'labels':{'case_id':a.run_id,'stage':'file-and-buffer-validation','input_group':group,'scope':'lab-validation; not a production alert'},'input':{'id':input_id},'file':{'path':display,'sha256':digest,'size':None if data is None else len(data),'pe_machine':machine},'rule':{'name':rule_name,'matched':actual,'ruleset_sha256':rules_sha},'scan':{'kind':kind,'engine':'yara-python','engine_version':yara.__version__,'duration_ms':elapsed,'error':error,'sample_executed':False},'test':{'expected_match':expect,'passed':passed},'yara':{'strings':witnesses},'provenance':{'source_sample_sha256':SAMPLE_SHA if group in ('specimen','same-specimen-copy','specimen-derived-buffer') else None,'reference_set':'Local Windows OS files from previously exposed VM; not a vetted clean-room benchmark' if group.startswith('os-reference') else None}})
    assert sha(a.sample.read_bytes())==SAMPLE_SHA
    events_path=a.output/(a.run_id+'.ndjson')
    with events_path.open('x',encoding='utf-8',newline='\n') as f:
        for event in rows:f.write(json.dumps(event,ensure_ascii=False)+'\n')
    probe=yara.compile(source='rule DomainLiteralTrial { strings: $a="remchukwugixiemu4.duckdns.org" $b="remchukwugix231fgh.duckdns.org" condition: all of them }',error_on_warning=True)
    trial={'native_payload_matched':bool(probe.match(data=raw)),'decoded_buffer_matched':bool(probe.match(data=plain)),'benign_ioc_notes_matched':bool(probe.match(data=notes))}
    report={'run_id':a.run_id,'started_utc':started,'ended_utc':now(),'engine_version':yara.__version__,'python':platform.python_version(),'host':socket.gethostname(),'sample_sha256':SAMPLE_SHA,'sample_hash_unchanged':True,'sample_executed':False,'decoded_settings_sha256':sha(plain),'decoded_settings_bytes':len(plain),'rules_sha256':rules_sha,'rules_compiled_without_warnings':True,'inputs':len(inputs),'rule_evaluations':len(rows),'os_reference_paths':len(refs),'os_reference_unique_sha256':len({x['sha256'] for x in corpus if x['group'].startswith('os-reference')}),'native_rule_reference_eligible':sum(x['pe_machine']==0x14c and x['bytes']<2*1024*1024 for x in corpus if x['group'].startswith('os-reference')),'failed_scans':len(errors),'expectation_failures':mismatches,'input_manifest':corpus,'domain_literal_trial':trial,'events_file':events_path.name,'events_sha256':sha(events_path.read_bytes()),'positive_witnesses':[r for r in rows if r['rule']['matched']]}
    (a.output/'validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('input_manifest','positive_witnesses')},indent=2))
    if errors or mismatches:raise SystemExit(1)

if __name__=='__main__':main()
