import asyncio
import os
import shutil
import sys
import time
import unittest
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock


WEB_DIR = Path(__file__).resolve().parent
SESSION_ROOT = WEB_DIR / ".test-runtime" / uuid.uuid4().hex
IMPORT_ROOT = SESSION_ROOT / "import"

sys.path.insert(0, str(WEB_DIR))
os.environ["MOPETOT_DB_PATH"] = str(IMPORT_ROOT / "mobile_audit.db")
os.environ["MOPETOT_UPLOAD_DIR"] = str(IMPORT_ROOT / "uploads")
os.environ["MOPETOT_RESULTS_DIR"] = str(IMPORT_ROOT / "results")
os.environ.pop("MOPETOT_MAX_UPLOAD_BYTES", None)

from fastapi.testclient import TestClient

import app as application
from database import db as database
from maintenance.retention import run_retention


IMPORTED_UPLOAD_DIR = application.UPLOAD_DIR
IMPORTED_RESULTS_DIR = application.RESULTS_DIR
IMPORTED_DB_PATH = database.DB_PATH
IMPORTED_MAX_UPLOAD_BYTES = application.MAX_UPLOAD_BYTES


def run(coro):
    return asyncio.run(coro)


async def fetch_scans():
    db = await database.get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans ORDER BY id")
        return [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()


class ProductionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.root = SESSION_ROOT / uuid.uuid4().hex
        self.uploads = self.root / "uploads"
        self.results = self.root / "results"
        self.database_path = self.root / "database" / "mobile_audit.db"
        self.uploads.mkdir(parents=True)
        self.results.mkdir(parents=True)

        self.patchers = [
            mock.patch.object(database, "DB_PATH", str(self.database_path)),
            mock.patch.object(application, "UPLOAD_DIR", self.uploads),
            mock.patch.object(application, "RESULTS_DIR", self.results),
            mock.patch.object(application, "MAX_UPLOAD_BYTES", 1024),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(SESSION_ROOT, ignore_errors=True)

    def test_paths_and_upload_limit_are_configurable_from_environment(self):
        self.assertEqual(IMPORTED_UPLOAD_DIR, IMPORT_ROOT / "uploads")
        self.assertEqual(IMPORTED_RESULTS_DIR, IMPORT_ROOT / "results")
        self.assertEqual(IMPORTED_DB_PATH, str(IMPORT_ROOT / "mobile_audit.db"))
        self.assertEqual(IMPORTED_MAX_UPLOAD_BYTES, 500 * 1024 * 1024)

    def test_upload_streaming_limit_and_safe_basename(self):
        with TestClient(application.app) as client:
            response = client.post(
                "/upload",
                files={
                    "file": (
                        "../../unsafe.apk",
                        b"abcd",
                        "application/octet-stream",
                    )
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["filename"], "unsafe.apk")

            scans = run(fetch_scans())
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["status"], "pending")
            self.assertEqual(scans[0]["file_size"], 4)
            stored_path = Path(scans[0]["file_path"])
            self.assertEqual(stored_path.parent, self.uploads)
            self.assertEqual(stored_path.read_bytes(), b"abcd")

            with mock.patch.object(application, "MAX_UPLOAD_BYTES", 3):
                response = client.post(
                    "/upload",
                    files={
                        "file": (
                            "large.apk",
                            b"1234",
                            "application/octet-stream",
                        )
                    },
                )
            self.assertEqual(response.status_code, 413)
            self.assertEqual(len(list(self.uploads.iterdir())), 1)
            self.assertEqual(len(run(fetch_scans())), 1)

            response = client.delete(f"/api/scan/{scans[0]['id']}")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(list(self.uploads.iterdir()), [])
            self.assertEqual(run(fetch_scans()), [])

    def test_healthz_checks_database_and_directories(self):
        with TestClient(application.app) as client:
            response = client.get("/healthz")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json()["checks"],
                {"database": "ok", "uploads": "ok", "results": "ok"},
            )

            original = application.check_directory_writable

            def fail_results(directory):
                if directory == self.results:
                    raise OSError("read-only")
                return original(directory)

            with mock.patch.object(
                application, "check_directory_writable", fail_results
            ):
                response = client.get("/healthz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["checks"]["results"], "error")

    def test_persistent_queue_is_serial_and_resumes_requested_scans(self):
        async def prepare():
            await database.init_db()
            db = await database.get_db()
            try:
                ids = []
                names = (
                    "pending.apk",
                    "queued-1.apk",
                    "queued-2.apk",
                    "running.apk",
                )
                for name in names:
                    ids.append(
                        await database.insert_scan(
                            db,
                            name,
                            str(self.uploads / name),
                            1,
                            "apk",
                            "android",
                        )
                    )
                await database.request_scan(db, ids[1])
                await database.request_scan(db, ids[2])
                await db.execute(
                    "UPDATE scans SET status='running', phase='decompile' WHERE id=?",
                    (ids[3],),
                )
                await db.commit()
                return ids
            finally:
                await db.close()

        ids = run(prepare())
        active = 0
        max_active = 0
        order = []

        async def fake_run_scan(
            scan_id, file_path, file_type, platform, fast_mode=False
        ):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            order.append(scan_id)
            await asyncio.sleep(0.03)
            db = await database.get_db()
            try:
                if scan_id == ids[1]:
                    await database.update_scan_status(
                        db, scan_id, "failed", error="expected test failure"
                    )
                else:
                    await database.complete_scan(db, scan_id)
            finally:
                await db.close()
                active -= 1

        with mock.patch.object(application, "run_scan", fake_run_scan):
            with TestClient(application.app) as client:
                response = client.post(f"/api/scan/{ids[0]}/start")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["queue_status"], "queued")

                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    scans = {row["id"]: row for row in run(fetch_scans())}
                    if all(
                        scans[scan_id]["status"] in ("completed", "failed")
                        for scan_id in ids[:3]
                    ):
                        break
                    time.sleep(0.03)
                else:
                    self.fail("queued scans did not complete")

                self.assertEqual(scans[ids[3]]["status"], "failed")
                self.assertEqual(
                    scans[ids[3]]["error"],
                    "Scan interrupted: server restart",
                )
                self.assertEqual(
                    scans[ids[1]]["error"], "expected test failure"
                )
                self.assertEqual(scans[ids[2]]["status"], "completed")
                self.assertEqual(scans[ids[0]]["status"], "completed")

        self.assertEqual(order, [ids[1], ids[2], ids[0]])
        self.assertEqual(max_active, 1)

    def test_retention_dry_run_filters_and_is_idempotent(self):
        async def prepare():
            await database.init_db()
            db = await database.get_db()
            try:
                scan_ids = {}
                scans = (
                    ("old-completed.apk", "completed", 60),
                    ("old-failed.apk", "failed", 45),
                    ("old-pending.apk", "pending", 90),
                    ("recent-completed.apk", "completed", 2),
                )
                for name, status, age in scans:
                    upload_path = self.uploads / name
                    upload_path.write_bytes(name.encode())
                    scan_id = await database.insert_scan(
                        db,
                        name,
                        str(upload_path),
                        upload_path.stat().st_size,
                        "apk",
                        "android",
                    )
                    stamp = (
                        datetime.now() - timedelta(days=age)
                    ).isoformat()
                    await db.execute(
                        """
                        UPDATE scans
                        SET status=?, created_at=?, completed_at=?
                        WHERE id=?
                        """,
                        (
                            status,
                            stamp,
                            stamp
                            if status in ("completed", "failed")
                            else None,
                            scan_id,
                        ),
                    )
                    result_dir = self.results / str(scan_id)
                    result_dir.mkdir()
                    (result_dir / "report.md").write_text(name)
                    scan_ids[name] = scan_id
                await database.insert_log(
                    db,
                    scan_ids["old-completed.apk"],
                    "info",
                    "old log",
                )
                await db.commit()
                return scan_ids
            finally:
                await db.close()

        scan_ids = run(prepare())
        dry_run = run(
            run_retention(
                days=30,
                dry_run=True,
                upload_dir=self.uploads,
                results_dir=self.results,
            )
        )
        self.assertEqual(
            dry_run["scan_ids"],
            [
                scan_ids["old-completed.apk"],
                scan_ids["old-failed.apk"],
            ],
        )
        self.assertEqual(dry_run["deleted"], 0)
        self.assertTrue((self.uploads / "old-completed.apk").exists())

        result = run(
            run_retention(
                days=30,
                upload_dir=self.uploads,
                results_dir=self.results,
            )
        )
        self.assertEqual(result["deleted"], 2)
        self.assertFalse(result["errors"])

        async def remaining():
            db = await database.get_db()
            try:
                cursor = await db.execute("SELECT id FROM scans ORDER BY id")
                remaining_ids = [
                    row["id"] for row in await cursor.fetchall()
                ]
                cursor = await db.execute(
                    "SELECT COUNT(*) AS total FROM scan_logs WHERE scan_id=?",
                    (scan_ids["old-completed.apk"],),
                )
                return remaining_ids, (await cursor.fetchone())["total"]
            finally:
                await db.close()

        remaining_ids, old_logs = run(remaining())
        self.assertEqual(
            remaining_ids,
            [
                scan_ids["old-pending.apk"],
                scan_ids["recent-completed.apk"],
            ],
        )
        self.assertEqual(old_logs, 0)
        self.assertTrue((self.uploads / "old-pending.apk").exists())
        self.assertTrue(
            (self.results / str(scan_ids["old-pending.apk"])).exists()
        )

        second = run(
            run_retention(
                days=30,
                upload_dir=self.uploads,
                results_dir=self.results,
            )
        )
        self.assertEqual(second["eligible"], 0)
        self.assertEqual(second["deleted"], 0)


if __name__ == "__main__":
    unittest.main()
