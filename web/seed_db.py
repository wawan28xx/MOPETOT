import asyncio
import sys
sys.path.insert(0, '.')

from database.db import *

async def seed_db():
    db = await get_db()
    try:
        # Create sample scan
        cursor = await db.execute("""
            INSERT INTO scans (filename, file_path, file_size, file_type, platform, package_name, version, status, progress)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("TestApp.apk", "/upload/test.apk", 50000000, "apk", "android", "com.example.test", "1.0.0", "completed", 100))
        scan_id = cursor.lastrowid
        
        # Create sample secrets
        await db.execute("""
            INSERT INTO secrets (scan_id, rule_id, category, severity, file_path, line_number, match, context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "HARDCODED_PASSWORD", "Credentials", "high", 
              "MainActivity.java", 42, 
              "P@ssw0rd123",
              'String password = "P@ssw0rd123";\nString username = "admin";\nconnectDB(username, password);'))
        
        await db.execute("""
            INSERT INTO secrets (scan_id, rule_id, category, severity, file_path, line_number, match, context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "AWS_KEY", "API Keys", "critical",
              "Config.java", 100,
              "AKIAIOSFODNN7EXAMPLE",
              'final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n// This is a test key\nAWSClient client = new AWSClient(AWS_KEY);'))
        
        # Create sample findings
        await db.execute("""
            INSERT INTO findings (scan_id, category, severity, title, description, file_path, line_number)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "Code Injection", "high", "Potential SQL Injection", "Database code could be vulnerable", 
              "DatabaseHelper.java", 80))
        
        # Create sample endpoints
        await db.execute("""
            INSERT INTO endpoints (scan_id, url, host, port, scheme, path, env)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "https://api.example.com/v1/user", "api.example.com", 443, "https", "/v1/user", "prod"))
        
        await db.execute("""
            INSERT INTO endpoints (scan_id, url, host, port, scheme, path, env)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "http://staging.example.com/debug", "staging.example.com", 8080, "http", "/debug", "staging"))
        
        # Create sample manifest
        await db.execute("""
            INSERT INTO manifest_info (scan_id, package_name, version_name, version_code, min_sdk, target_sdk, permissions, components, deep_links)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, "com.example.test", "1.0.0", "1", "21", "34", 
              '["android.permission.CAMERA","android.permission.READ_CONTACTS","android.permission.ACCESS_FINE_LOCATION"]',
              '{"activities":["MainActivity","SettingsActivity"],"services":["SyncService"],"receivers":["BootReceiver"]}',
              '["scheme://app/path","myapp://screen/123"]'))
        
        await db.commit()
        print(f"[OK] Created sample scan ID: {scan_id}")
        return scan_id
    finally:
        await db.close()

asyncio.run(seed_db())
