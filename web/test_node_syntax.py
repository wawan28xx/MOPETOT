import re
import subprocess

html = open('templates/results.html', encoding='utf-8').read()
match = re.search(r'<script>(.*?)</script>', html, re.DOTALL)
if match:
    js_code = match.group(1).replace('{{ scan.id }}', '29').replace('{{ logs|length if logs else 0 }}', '0')
    with open('temp_script.js', 'w', encoding='utf-8') as f:
        f.write(js_code)
    
    res = subprocess.run(['node', '--check', 'temp_script.js'], capture_output=True, text=True)
    print("Node check exit code:", res.returncode)
    if res.returncode == 0:
        print("[SUCCESS] JavaScript syntax 100% VALID!")
    else:
        print("Node stderr:\n", res.stderr)
