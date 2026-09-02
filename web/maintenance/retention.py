import argparse
import asyncio
import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

try:
    from database import db as database
except ModuleNotFoundError:
    from ..database import db as database


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_UPLOAD_DIR = BASE_DIR / "uploads"
DEFAULT_RESULTS_DIR = BASE_DIR / "results"


def configured_path(primary, fallback, default):
    return Path(os.environ.get(primary, os.environ.get(fallback, default))).expanduser()


def _inside(candidate, root):
    candidate_abs = Path(os.path.abspath(candidate))
    root_abs = Path(os.path.abspath(root))
    try:
        candidate_abs.relative_to(root_abs)
        return True
    except ValueError:
        return False


def _remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


async def run_retention(
    days=30,
    dry_run=False,
    upload_dir=None,
    results_dir=None,
):
    if days < 0:
        raise ValueError("days must be zero or greater")

    upload_root = Path(upload_dir or configured_path(
        "MOPETOT_UPLOAD_DIR", "UPLOAD_DIR", DEFAULT_UPLOAD_DIR
    )).expanduser()
    results_root = Path(results_dir or configured_path(
        "MOPETOT_RESULTS_DIR", "RESULTS_DIR", DEFAULT_RESULTS_DIR
    )).expanduser()
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()

    db = await database.get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, file_path, status
            FROM scans
            WHERE status IN ('completed', 'failed')
              AND datetime(COALESCE(completed_at, created_at)) < datetime(?)
            ORDER BY id
            """,
            (cutoff,),
        )
        candidates = await cursor.fetchall()

        summary = {
            "dry_run": dry_run,
            "days": days,
            "eligible": len(candidates),
            "deleted": 0,
            "scan_ids": [row["id"] for row in candidates],
            "skipped_artifacts": [],
            "errors": [],
        }
        if dry_run:
            return summary

        for row in candidates:
            scan_id = row["id"]
            upload_path = Path(row["file_path"]) if row["file_path"] else None
            result_path = results_root / str(scan_id)
            try:
                if upload_path and _inside(upload_path, upload_root):
                    if upload_path.exists() or upload_path.is_symlink():
                        _remove_path(upload_path)
                elif upload_path:
                    summary["skipped_artifacts"].append(str(upload_path))

                if _inside(result_path, results_root):
                    if result_path.exists() or result_path.is_symlink():
                        _remove_path(result_path)

                await db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
                await db.commit()
                summary["deleted"] += 1
            except Exception as exc:
                await db.rollback()
                summary["errors"].append({"scan_id": scan_id, "error": str(exc)})

        return summary
    finally:
        await db.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove expired completed and failed scans."
    )
    try:
        default_days = int(os.environ.get("MOPETOT_RETENTION_DAYS", "30"))
    except ValueError:
        default_days = 30
    parser.add_argument("--days", type=int, default=default_days)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--db-path")
    parser.add_argument("--upload-dir")
    parser.add_argument("--results-dir")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.db_path:
        database.DB_PATH = args.db_path
    summary = asyncio.run(
        run_retention(
            days=args.days,
            dry_run=args.dry_run,
            upload_dir=args.upload_dir,
            results_dir=args.results_dir,
        )
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
