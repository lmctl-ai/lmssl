"""Exercise public run_lmcode footers, including argument forwarding."""
from pathlib import Path
import subprocess, sys
from invocation import compiler_cmd
work=Path(sys.argv[1])
for source,args in [('crypto-basics',[]),('selfsigned-wildcard',[str(work/'source-wild')])]:
 r=subprocess.run(compiler_cmd()+['examples/'+source+'.lms',*args],capture_output=True,
                  text=True,encoding='utf-8',errors='replace',timeout=120)
 assert r.returncode==0,(source,r.stdout,r.stderr)
assert (work/'source-wild'/'cert.pem').is_file()
assert (work/'source-wild'/'key.pem').is_file()
print('PASS public source invocations and ARGV forwarding')
