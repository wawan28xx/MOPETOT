import re
import subprocess

html = open('templates/results.html', encoding='utf-8').read()
# Ambil SEMUA inline <script> (tanpa atribut src), lalu check yang terbesar (script utama app)
blocks = re.findall(r'<script>(.*?)</script>', html, re.DOTALL)
if blocks:
    js_code = max(blocks, key=len).replace('{{ scan.id }}', '29').replace('{{ logs|length if logs else 0 }}', '0')
    with open('temp_script.js', 'w', encoding='utf-8') as f:
        f.write(js_code)

    res = subprocess.run(['node', '--check', 'temp_script.js'], capture_output=True, text=True)
    print("Node check exit code:", res.returncode)
    if res.returncode == 0:
        print("[SUCCESS] JavaScript syntax 100% VALID!")
    else:
        print("Node stderr:\n", res.stderr)
else:
    print("[ERROR] Tidak ada inline <script> ditemukan!")
