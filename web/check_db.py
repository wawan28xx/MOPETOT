import sqlite3
conn = sqlite3.connect("mobile_audit.db")
rows = conn.execute("SELECT id, filename, file_size, status FROM scans ORDER BY id").fetchall()
for r in rows:
    print(f"Scan {r[0]}: {r[1]} ({r[2]//1024//1024}MB) - {r[3]}")
conn.close()
