"""apkid_wrapper.py — jalankan APKiD di interpreter dengan yara-python-dex.

Dipakai mobile_audit.py via `py -3.13 apkid_wrapper.py <target>`.
Output: JSON satu baris ke stdout, atau {"error": "..."} bila gagal.
"""
import json
import sys
from pathlib import Path

RULES_DIR = Path(r"C:\platform-tools\APKiD-3.0.0\apkid\rules")


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: apkid_wrapper.py <target>"}))
        return 1
    target = sys.argv[1]
    try:
        from apkid.rules import RulesManager
        from apkid.apkid import Scanner, Options

        opts = Options(timeout=60, json=True, typing="magic", entry_max_scan_size=0)
        opts.rules_manager = RulesManager(str(RULES_DIR))
        scanner = Scanner(opts.rules_manager.load(), opts)
        results = scanner.scan_file(target)
        files = []
        for fname, matches in sorted(results.items()):
            grouped = {}
            for m in matches:
                for tag in m.tags:
                    grouped.setdefault(tag, []).append(m.rule)
            if grouped:
                files.append({"filename": fname, "matches": {k: sorted(set(v)) for k, v in grouped.items()}})
        print(json.dumps({"apkid_version": "3.1.0", "files": files}))
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())