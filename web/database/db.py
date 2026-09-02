import aiosqlite
import os
import json
from datetime import datetime
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).with_name("mobile_audit.db")
DB_PATH = str(Path(os.environ.get(
    "MOPETOT_DB_PATH",
    os.environ.get("DATABASE_PATH", str(DEFAULT_DB_PATH)),
)).expanduser())

async def get_db():
    Path(DB_PATH).expanduser().parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    await db.execute("PRAGMA busy_timeout = 5000")
    return db

async def init_db():
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                file_type TEXT,
                platform TEXT,
                package_name TEXT,
                version TEXT,
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                phase TEXT,
                error TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                fast_mode INTEGER DEFAULT 0,
                queued_at TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                file_path TEXT,
                line_number INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT,
                host TEXT,
                port INTEGER,
                scheme TEXT,
                path TEXT,
                env TEXT,
                method TEXT,
                depth TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_id TEXT,
                category TEXT,
                severity TEXT,
                file_path TEXT,
                line_number INTEGER,
                match TEXT,
                context TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS manifest_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                package_name TEXT,
                version_name TEXT,
                version_code TEXT,
                min_sdk TEXT,
                target_sdk TEXT,
                permissions TEXT,
                components TEXT,
                deep_links TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                level TEXT,
                message TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS verification_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                row_id TEXT NOT NULL,
                module TEXT,
                target TEXT,
                button_text TEXT,
                result_html TEXT,
                modal_json TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_verification_cache_scan_row
            ON verification_cache(scan_id, row_id);

            CREATE TABLE IF NOT EXISTS poc_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_poc_cache_scan
            ON poc_cache(scan_id);

            CREATE INDEX IF NOT EXISTS idx_scans_status_created
            ON scans(status, created_at, id);
        """)
        await db.commit()
        try:
            await db.execute("ALTER TABLE scans ADD COLUMN fast_mode INTEGER DEFAULT 0")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scans ADD COLUMN queued_at TEXT")
            await db.commit()
        except Exception:
            pass
    finally:
        await db.close()

async def insert_scan(db, filename, file_path, file_size, file_type, platform, fast_mode=0):
    cursor = await db.execute(
        "INSERT INTO scans (filename, file_path, file_size, file_type, platform, status, fast_mode) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
        (filename, file_path, file_size, file_type, platform, 1 if fast_mode else 0)
    )
    await db.commit()
    return cursor.lastrowid


async def request_scan(db, scan_id):
    cursor = await db.execute(
        """
        UPDATE scans
        SET status='queued', phase='queued', error=NULL, queued_at=?
        WHERE id=? AND status='pending'
        """,
        (datetime.now().isoformat(), scan_id),
    )
    await db.commit()
    return cursor.rowcount == 1


async def claim_next_queued_scan(db):
    await db.execute("BEGIN IMMEDIATE")
    try:
        cursor = await db.execute(
            "SELECT 1 FROM scans WHERE status='running' LIMIT 1"
        )
        if await cursor.fetchone():
            await db.commit()
            return None

        cursor = await db.execute(
            """
            SELECT *
            FROM scans
            WHERE status='queued'
            ORDER BY COALESCE(queued_at, created_at), id
            LIMIT 1
            """
        )
        scan = await cursor.fetchone()
        if not scan:
            await db.commit()
            return None

        cursor = await db.execute(
            """
            UPDATE scans
            SET status='running', progress=0, phase='init', error=NULL,
                started_at=?, completed_at=NULL
            WHERE id=? AND status='queued'
            """,
            (datetime.now().isoformat(), scan["id"]),
        )
        if cursor.rowcount != 1:
            await db.rollback()
            return None

        await db.commit()
        cursor = await db.execute("SELECT * FROM scans WHERE id=?", (scan["id"],))
        return await cursor.fetchone()
    except Exception:
        await db.rollback()
        raise


async def fail_interrupted_scans(db, reason="Scan interrupted: server restart"):
    cursor = await db.execute(
        """
        UPDATE scans
        SET status='failed', phase='failed', error=?, completed_at=?
        WHERE status='running'
        """,
        (reason, datetime.now().isoformat()),
    )
    await db.commit()
    return cursor.rowcount

async def update_scan_status(db, scan_id, status, progress=None, phase=None, error=None):
    if progress is not None:
        await db.execute("UPDATE scans SET status=?, progress=?, phase=? WHERE id=?", (status, progress, phase, scan_id))
    elif status == "failed":
        await db.execute(
            "UPDATE scans SET status=?, phase=?, error=?, completed_at=? WHERE id=?",
            (status, phase or "failed", error, datetime.now().isoformat(), scan_id),
        )
    else:
        await db.execute("UPDATE scans SET status=?, phase=?, error=? WHERE id=?", (status, phase, error, scan_id))
    await db.commit()

async def complete_scan(db, scan_id, package_name=None, version=None):
    await db.execute(
        "UPDATE scans SET status='completed', progress=100, completed_at=?, package_name=?, version=? WHERE id=?",
        (datetime.now().isoformat(), package_name, version, scan_id)
    )
    await db.commit()

async def insert_finding(db, scan_id, category, severity, title, description, evidence=None, file_path=None, line_number=None):
    await db.execute(
        "INSERT INTO findings (scan_id, category, severity, title, description, evidence, file_path, line_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, category, severity, title, description, evidence, file_path, line_number)
    )
    await db.commit()

async def insert_endpoint(db, scan_id, url, host=None, port=None, scheme=None, path=None, env=None, method=None, depth=None):
    await db.execute(
        "INSERT INTO endpoints (scan_id, url, host, port, scheme, path, env, method, depth) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, url, host, port, scheme, path, env, method, depth)
    )
    await db.commit()

async def insert_secret(db, scan_id, rule_id, category, severity, file_path, line_number, match, context=None):
    await db.execute(
        "INSERT INTO secrets (scan_id, rule_id, category, severity, file_path, line_number, match, context) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, rule_id, category, severity, file_path, line_number, match, context)
    )
    await db.commit()

async def insert_manifest(db, scan_id, package_name, version_name, version_code, min_sdk, target_sdk, permissions, components, deep_links):
    await db.execute(
        "INSERT INTO manifest_info (scan_id, package_name, version_name, version_code, min_sdk, target_sdk, permissions, components, deep_links) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, package_name, version_name, version_code, min_sdk, target_sdk, permissions, components, deep_links)
    )
    await db.commit()

async def insert_log(db, scan_id, level, message):
    await db.execute(
        "INSERT INTO scan_logs (scan_id, level, message) VALUES (?, ?, ?)",
        (scan_id, level, message)
    )
    await db.commit()

async def get_scan(db, scan_id):
    cursor = await db.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    return await cursor.fetchone()

async def get_scans(db, limit=50, offset=0):
    cursor = await db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
    return await cursor.fetchall()

async def query_scans(db, search=None, platform=None, status=None, limit=10, offset=0):
    conditions = []
    params = []

    if search:
        conditions.append("(filename LIKE ? OR package_name LIKE ?)")
        search_pattern = f"%{search}%"
        params.extend([search_pattern, search_pattern])

    if platform and platform.lower() != "all":
        conditions.append("LOWER(platform) = ?")
        params.append(platform.lower())

    if status and status.lower() != "all":
        conditions.append("LOWER(status) = ?")
        params.append(status.lower())

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # Count total matching
    count_sql = f"SELECT COUNT(*) as total FROM scans {where_clause}"
    cursor = await db.execute(count_sql, tuple(params))
    count_row = await cursor.fetchone()
    total = count_row["total"] if count_row else 0

    # Fetch rows
    fetch_sql = f"SELECT * FROM scans {where_clause} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    fetch_params = params + [limit, offset]
    cursor = await db.execute(fetch_sql, tuple(fetch_params))
    rows = await cursor.fetchall()

    return rows, total

async def get_findings(db, scan_id, severity=None):
    if severity:
        cursor = await db.execute("SELECT * FROM findings WHERE scan_id=? AND severity=? ORDER BY severity, category", (scan_id, severity))
    else:
        cursor = await db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY severity, category", (scan_id,))
    return await cursor.fetchall()

async def get_endpoints(db, scan_id):
    cursor = await db.execute("SELECT * FROM endpoints WHERE scan_id=? ORDER BY host, path", (scan_id,))
    return await cursor.fetchall()

async def get_secrets(db, scan_id, severity=None):
    if severity:
        cursor = await db.execute("SELECT * FROM secrets WHERE scan_id=? AND severity=? ORDER BY severity, category", (scan_id, severity))
    else:
        cursor = await db.execute("SELECT * FROM secrets WHERE scan_id=? ORDER BY severity, category", (scan_id,))
    return await cursor.fetchall()

async def get_manifest(db, scan_id):
    cursor = await db.execute("SELECT * FROM manifest_info WHERE scan_id=?", (scan_id,))
    return await cursor.fetchone()

async def get_logs(db, scan_id, after=0, limit=500):
    if after:
        cursor = await db.execute(
            "SELECT * FROM scan_logs WHERE scan_id=? AND id>? ORDER BY id LIMIT ?", (scan_id, after, limit))
    else:
        cursor = await db.execute("SELECT * FROM scan_logs WHERE scan_id=? ORDER BY id LIMIT ?", (scan_id, limit))
    return await cursor.fetchall()

async def get_stats(db):
    cursor = await db.execute("""
        SELECT
            COUNT(*) as total_scans,
            SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) as running,
            SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed
        FROM scans
    """)
    row = await cursor.fetchone()
    if row:
        return {
            "total_scans": row["total_scans"] or 0,
            "completed": row["completed"] or 0,
            "running": row["running"] or 0,
            "failed": row["failed"] or 0,
        }
    return {"total_scans": 0, "completed": 0, "running": 0, "failed": 0}

async def search_findings(db, query):
    cursor = await db.execute(
        "SELECT f.*, s.filename FROM findings f JOIN scans s ON f.scan_id=s.id WHERE f.title LIKE ? OR f.description LIKE ? ORDER BY f.severity LIMIT 100",
        (f"%{query}%", f"%{query}%")
    )
    return await cursor.fetchall()

async def delete_scan(db, scan_id):
    await db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    await db.commit()


async def upsert_verification_cache(
    db,
    scan_id,
    row_id,
    module,
    target,
    button_text,
    result_html,
    modal_json,
):
    await db.execute(
        """
        INSERT INTO verification_cache (scan_id, row_id, module, target, button_text, result_html, modal_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(scan_id, row_id)
        DO UPDATE SET
            module=excluded.module,
            target=excluded.target,
            button_text=excluded.button_text,
            result_html=excluded.result_html,
            modal_json=excluded.modal_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (scan_id, row_id, module, target, button_text, result_html, modal_json),
    )
    await db.commit()


async def get_verification_cache(db, scan_id):
    cursor = await db.execute(
        """
        SELECT row_id, module, target, button_text, result_html, modal_json, updated_at
        FROM verification_cache
        WHERE scan_id=?
        ORDER BY updated_at DESC, id DESC
        """,
        (scan_id,),
    )
    return await cursor.fetchall()


async def upsert_poc_cache(db, scan_id, payload_json):
    await db.execute(
        """
        INSERT INTO poc_cache (scan_id, payload_json, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(scan_id)
        DO UPDATE SET
            payload_json=excluded.payload_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (scan_id, payload_json),
    )
    await db.commit()


async def get_poc_cache(db, scan_id):
    cursor = await db.execute(
        """
        SELECT payload_json, updated_at
        FROM poc_cache
        WHERE scan_id=?
        LIMIT 1
        """,
        (scan_id,),
    )
    return await cursor.fetchone()
