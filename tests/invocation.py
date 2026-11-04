"""Test-only run_lmcode drivers; capture private inputs and preserve host exit status."""
import json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path


def compiler_cmd():
    compiler = os.environ.get('LMSCRIPT_BIN', 'lmscript')
    if sys.platform == 'win32' and Path(compiler + '.cmd').exists():
        return ['cmd.exe', '/c', compiler + '.cmd']
    return [compiler]


def run_sources(sources, *, dry=False, capture=None, example=False, capture_only=False, check=False, timeout=600):
    host = str(Path(os.environ.get('LMSSL_HOST', 'build/lmssl')).resolve())
    with tempfile.TemporaryDirectory(prefix='lmssl-invocation-') as directory:
        directory = Path(directory)
        status = directory / 'status'
        command = [os.environ['LMSSL_SHIM'], '--capture-host' if capture_only else '--host', host,
                   str(status), str(Path(capture).resolve()) if capture else '', '--lmcode']
        if example:
            text = Path(sources[0]).read_text(encoding='utf-8')
            # Only wrap this host's calls; optional lmplot calls keep their own binding.
            for name in re.findall(r'(\w+)\s*=\s*_lmcode_\s+cli="lmssl"', text):
                text = text.replace('run_lmcode(' + name + ')',
                    'run_lmcode(' + name + ', {command:' + json.dumps(command + ['$DSLFILE']) + '})')
        else:
            text = 'b = lmcode_build(' + json.dumps(command) + ');\n' if len(sources) > 1 else ''
            for i, source in enumerate(sources):
                chunk = Path(source).read_text(encoding='utf-8').split('end _lmcode_', 1)[0] + 'end _lmcode_\n'
                chunk = re.sub(r'\bp\s*=\s*_lmcode_', f'p{i} = _lmcode_', chunk, count=1)
                text += chunk
                if len(sources) > 1:
                    text += f'b.add(p{i}, ' + json.dumps((["--lmcode"] if i else []) + ["$DSLFILE"]) + ');\n'
            text += ('r = run_lmcode(b);\n' if len(sources) > 1 else
                     'r = run_lmcode(p0, {command:' + json.dumps(command + ['$DSLFILE']) + '});\n')
            text += 'println(json_stringify(r));\n'
        driver = directory / 'driver.lms'
        driver.write_text(text, encoding='utf-8')
        result = subprocess.run(compiler_cmd() + (['--check'] if check else ['--dry-run'] if dry else []) +
                                ['--base-dir', str(Path.cwd()), str(driver)],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        # Never mask a compiler/driver failure with a successful host status.
        if status.exists() and (result.returncode == 0 or int(status.read_text(encoding='utf-8')) != 0):
            result.returncode = int(status.read_text(encoding='utf-8'))
        elif not check and not dry and not status.exists() and result.returncode == 0:
            result.returncode = 125
            result.stderr += "test driver did not execute the selected host\n"
        return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--example', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--capture')
    parser.add_argument('--capture-only', action='store_true')
    parser.add_argument('sources', nargs='+')
    args = parser.parse_args()
    result = run_sources(args.sources, dry=args.dry_run, capture=args.capture, example=args.example, capture_only=args.capture_only, check=args.check,
                         timeout=3600 if args.example else 600)
    print(result.stdout, end=''); print(result.stderr, end='', file=sys.stderr)
    sys.exit(result.returncode)
