"""Invocation framing, builder order, validation, and real dry metadata controls."""
import json, os, subprocess, sys
from pathlib import Path
from invocation import run_sources
work=Path(sys.argv[1])/'protocol'; work.mkdir()
host=os.environ['LMSSL_HOST']
schema=Path('schema/lmssl.dsl.json').resolve()
def source(name,body):
 path=work/(name+'.lms')
 path.write_text('p = _lmcode_ schema='+json.dumps(str(schema))+';\n'+body+'\nend _lmcode_\n', encoding='utf-8')
 return path
first,second=work/'first.txt',work/'second.txt'
a=source('a','file_write('+json.dumps(str(first))+',"a"); out.line("diagnostic");')
b=source('b','file_write('+json.dumps(str(second))+',file_read('+json.dumps(str(first))+')+"b");')
bad=source('bad','let x = int_list().at(9);')
r=run_sources([a,b],capture=work/'capture')
assert r.returncode==0 and json.loads(r.stdout)=={'ok':True,'result':[None,None],'parts':2},r
assert second.read_text(encoding='utf-8')=='ab' and 'diagnostic' in r.stderr,r
first.unlink();second.unlink()
r=run_sources([a,bad,b],capture=work/'failed-capture')
assert r.returncode==3 and json.loads(r.stdout)['part']==1 and first.exists() and not second.exists(),r
first.unlink()
files=[str((work/'capture'/f'{i}.lmcode').resolve()) for i in range(2)]
file_args=[word for file in files for word in ('--lmcode',file)]
def hostrun(args,env=None):
 return subprocess.run([host,*args],env=env,capture_output=True,text=True,timeout=30, encoding='utf-8', errors='replace')
def frame(r):
 lines=r.stdout.splitlines()
 assert len(lines)==3 and lines[0]=='LMCODE_RETURN_BEGIN' and lines[2]=='LMCODE_RETURN_END',r
 return json.loads(lines[1])
r=hostrun(['--dry-run','--lmcode',str((work/'failed-capture'/'1.lmcode').resolve())])
assert r.returncode==0 and frame(r)['dry'] is True and not r.stderr,r
r=hostrun([*file_args,'--lmcode',str(work/'missing.lmcode')])
assert r.returncode==3 and frame(r)['phase']=='load' and not first.exists(),r
manifest=work/'invocation.json'
metadata={'version':1,'mode':'builder','dry':True,'parts':[{'index':i,'file':p} for i,p in enumerate(files)]}
manifest.write_text(json.dumps(metadata), encoding='utf-8')
env=dict(os.environ,LMCODE_INVOCATION_FILE=str(manifest.resolve()))
r=hostrun(file_args,env)
assert r.returncode==0 and frame(r)['dry'] is True and not first.exists() and not second.exists(),r
metadata['dry']=False;manifest.write_text(json.dumps(metadata), encoding='utf-8')
r=hostrun(['--dry-run',*file_args],env)
assert r.returncode==2 and frame(r)['phase']=='cli' and not first.exists(),r
env['LMCODE_INVOCATION_FILE']=str(work/'absent.json')
r=hostrun(file_args,env)
assert r.returncode==2 and frame(r)['phase']=='cli' and not first.exists(),r
r=hostrun(['--lmcode-schema','--json'],env)
assert r.returncode==0 and r.stdout==schema.read_text(encoding='utf-8'),r
r=hostrun(file_args)
assert r.returncode==0 and frame(r)['parts']==2 and 'diagnostic' in r.stderr,r
print('PASS framing, builder order, stop-on-error, load-before-write, dry metadata and passive introspection')

# Per-part argv stays separate; source/data text includes non-ASCII Windows coverage.
arg_a=source('arg-a','file_write('+json.dumps(str(work/'arg-a.txt'))+', ssl.args().at(0) + " café λ");')
arg_b=source('arg-b','file_write('+json.dumps(str(work/'arg-b.txt'))+', ssl.args().at(0));')
for i,src in enumerate([arg_a,arg_b]):
 r=run_sources([src],capture=work/f'arg-{i}',capture_only=True)
 assert r.returncode==0,r
r=hostrun(['--lmcode',str(work/'arg-0'/'0.lmcode'),'first',
           '--lmcode',str(work/'arg-1'/'0.lmcode'),'second'])
assert r.returncode==0 and frame(r)['parts']==2,r
assert (work/'arg-a.txt').read_text(encoding='utf-8')=='first café λ'
assert (work/'arg-b.txt').read_text(encoding='utf-8')=='second'
first.unlink(); second.unlink()
app=source('app','out.fail("application control");')
r=run_sources([a,app,b],capture=work/'app-capture')
assert r.returncode==4 and json.loads(r.stdout)['phase']=='app' and json.loads(r.stdout)['part']==1 and first.exists() and not second.exists(),r
# Dry does not bind a socket: the same real invocation fails on an occupied port.
import socket
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0)); listener.listen()
 src=source('listen',f'let l = net.listen({listener.getsockname()[1]});')
 r=run_sources([src],capture=work/'listen-capture',capture_only=True)
 assert r.returncode==0,r
 file=str(work/'listen-capture'/'0.lmcode')
 r=hostrun(['--dry-run','--lmcode',file])
 assert r.returncode==0 and frame(r)['dry'] is True,r
 r=hostrun(['--lmcode',file])
 assert r.returncode==3 and frame(r)['phase']=='run',r
print('PASS per-part arguments and UTF-8 source/data, application exit 4 and dry socket negative control')
