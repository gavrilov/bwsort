"""SQLite state: which items were already sorted, so re-runs only touch new ones.

Holds only the same metadata as SafeItem (id, type, redacted name, domains,
folder ids). No secrets. Lives in data/bwsort.db (gitignored).

Item lifecycle (column `status`):
    new      seen in the vault, not classified yet            -> classify
    planned  category chosen, not moved yet                   -> apply
    failed   move attempted and failed                        -> apply (retry)
    moved    bwsort put it into its target folder             -> skipped on re-runs
    manual   you placed it yourself (moved it after bwsort,   -> skipped, your choice wins
             or a new item already sitting in a bwsort folder)
    skipped  organization item                                -> never touched
    gone     no longer in the vault (deleted)                 -> ignored; back to `new` if restored
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .sanitize import SafeItem

SCHEMA_VERSION = 2

STATUSES = ("new", "planned", "failed", "moved", "manual", "skipped", "gone")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,            -- bw userId
    server_url   TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    command      TEXT NOT NULL,
    model        TEXT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    summary      TEXT                          -- JSON
);

CREATE TABLE IF NOT EXISTS folders (
    account_id        TEXT NOT NULL REFERENCES accounts(account_id),
    folder_id         TEXT NOT NULL,
    name              TEXT NOT NULL,
    created_by_bwsort INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT,
    PRIMARY KEY (account_id, folder_id)
);

CREATE TABLE IF NOT EXISTS categories (
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    name         TEXT NOT NULL,                -- = folder name, English
    description  TEXT NOT NULL DEFAULT '',
    examples     TEXT NOT NULL DEFAULT '[]',   -- JSON list (v2)
    position     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, name)
);

CREATE TABLE IF NOT EXISTS items (
    account_id         TEXT NOT NULL REFERENCES accounts(account_id),
    item_id            TEXT NOT NULL,
    type               TEXT NOT NULL,
    name               TEXT NOT NULL,
    domains            TEXT NOT NULL,          -- JSON list
    in_organization    INTEGER NOT NULL,
    current_folder_id  TEXT,
    original_folder_id TEXT,                   -- folder when first seen (for rollback)
    status             TEXT NOT NULL CHECK (status IN ('new','planned','failed','moved','manual','skipped','gone')),
    category           TEXT,
    suggested_category TEXT,                   -- model's pick when confidence was too low (v2)
    confidence         REAL,
    category_source    TEXT,                   -- llm | rule | cache | user
    target_folder_id   TEXT,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    classified_at      TEXT,
    moved_at           TEXT,
    last_error         TEXT,
    PRIMARY KEY (account_id, item_id)
);
CREATE INDEX IF NOT EXISTS items_status ON items(account_id, status);

CREATE TABLE IF NOT EXISTS moves (             -- journal for rollback
    move_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(run_id),
    account_id     TEXT NOT NULL,
    item_id        TEXT NOT NULL,
    from_folder_id TEXT,
    to_folder_id   TEXT,
    at             TEXT NOT NULL
);

"""

# Applied in order to databases created by an older version.
_MIGRATIONS = {
    2: [
        "ALTER TABLE categories ADD COLUMN examples TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE items ADD COLUMN suggested_category TEXT",
        "DROP TABLE IF EXISTS domain_cache",
    ],
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(f"{path} was created by a newer bwsort (schema {version})")
    with conn:
        if version == 0:
            conn.executescript(_SCHEMA)
        else:
            for target in range(version + 1, SCHEMA_VERSION + 1):
                for stmt in _MIGRATIONS.get(target, []):
                    conn.execute(stmt)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return conn


# --- accounts & runs ------------------------------------------------------


def ensure_account(conn: sqlite3.Connection, account_id: str, server_url: str) -> None:
    ts = now()
    with conn:
        conn.execute(
            """INSERT INTO accounts(account_id, server_url, first_seen, last_seen) VALUES (?,?,?,?)
               ON CONFLICT(account_id) DO UPDATE SET server_url=excluded.server_url, last_seen=excluded.last_seen""",
            (account_id, server_url, ts, ts),
        )


def start_run(conn: sqlite3.Connection, account_id: str, command: str, model: str | None = None) -> int:
    with conn:
        cur = conn.execute(
            "INSERT INTO runs(account_id, command, model, started_at) VALUES (?,?,?,?)",
            (account_id, command, model, now()),
        )
    return int(cur.lastrowid)


def finish_run(conn: sqlite3.Connection, run_id: int, summary: dict) -> None:
    with conn:
        conn.execute(
            "UPDATE runs SET finished_at=?, summary=? WHERE run_id=?",
            (now(), json.dumps(summary, ensure_ascii=False), run_id),
        )


# --- snapshot sync --------------------------------------------------------


@dataclass
class SyncReport:
    total: int = 0
    new: int = 0              # first time seen -> will be classified
    restored: int = 0         # was gone, came back -> will be classified
    already_moved: int = 0    # sorted earlier, still in place -> skipped
    became_manual: int = 0    # sorted earlier, you moved it since -> skipped
    new_but_manual: int = 0   # new item already in a bwsort folder -> skipped
    skipped_org: int = 0
    gone: int = 0
    pending: dict[str, int] = field(default_factory=dict)


def bwsort_folder_ids(conn: sqlite3.Connection, account_id: str) -> set[str]:
    rows = conn.execute(
        "SELECT folder_id FROM folders WHERE account_id=? AND created_by_bwsort=1", (account_id,)
    )
    return {r[0] for r in rows}


def sync_snapshot(
    conn: sqlite3.Connection,
    account_id: str,
    items: Iterable[SafeItem],
    folders: list[dict],
) -> SyncReport:
    """Merge a fresh vault snapshot into the DB in one transaction."""
    ts = now()
    rep = SyncReport()
    with conn:
        # folders: upsert names, drop ones that no longer exist (keep bwsort flag)
        live_folder_ids = {f["id"] for f in folders}
        for f in folders:
            conn.execute(
                """INSERT INTO folders(account_id, folder_id, name) VALUES (?,?,?)
                   ON CONFLICT(account_id, folder_id) DO UPDATE SET name=excluded.name""",
                (account_id, f["id"], f["name"]),
            )
        for (fid,) in conn.execute("SELECT folder_id FROM folders WHERE account_id=?", (account_id,)).fetchall():
            if fid not in live_folder_ids:
                conn.execute("DELETE FROM folders WHERE account_id=? AND folder_id=?", (account_id, fid))

        ours = bwsort_folder_ids(conn, account_id)
        existing = {
            r["item_id"]: r
            for r in conn.execute(
                "SELECT item_id, status, target_folder_id FROM items WHERE account_id=?", (account_id,)
            )
        }
        seen: set[str] = set()

        for it in items:
            rep.total += 1
            seen.add(it.id)
            meta = (it.type, it.name, json.dumps(it.domains, ensure_ascii=False), int(it.in_organization), it.folder_id, ts)
            row = existing.get(it.id)

            if row is None:
                if it.in_organization:
                    status = "skipped"
                    rep.skipped_org += 1
                elif it.folder_id and it.folder_id in ours:
                    status = "manual"
                    rep.new_but_manual += 1
                else:
                    status = "new"
                    rep.new += 1
                conn.execute(
                    """INSERT INTO items(account_id, item_id, type, name, domains, in_organization,
                                         current_folder_id, last_seen, original_folder_id, status, first_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (account_id, it.id, *meta, it.folder_id, status, ts),
                )
                continue

            status = row["status"]
            if status == "gone":
                status = "new"
                rep.restored += 1
            elif status == "moved":
                if it.folder_id != row["target_folder_id"]:
                    status = "manual"
                    rep.became_manual += 1
                else:
                    rep.already_moved += 1
            elif status == "skipped":
                rep.skipped_org += 1

            conn.execute(
                """UPDATE items SET type=?, name=?, domains=?, in_organization=?, current_folder_id=?,
                                    last_seen=?, status=?
                   WHERE account_id=? AND item_id=?""",
                (*meta, status, account_id, it.id),
            )

        for item_id, row in existing.items():
            if item_id not in seen and row["status"] != "gone":
                conn.execute(
                    "UPDATE items SET status='gone', last_seen=? WHERE account_id=? AND item_id=?",
                    (ts, account_id, item_id),
                )
                rep.gone += 1

    rep.pending = status_counts(conn, account_id)
    return rep


# --- queries used by later stages -----------------------------------------


def status_counts(conn: sqlite3.Connection, account_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT status, COUNT(*) FROM items WHERE account_id=? GROUP BY status", (account_id,)
    )
    counts = {s: 0 for s in STATUSES}
    counts.update({r[0]: r[1] for r in rows})
    return counts


def items_with_status(conn: sqlite3.Connection, account_id: str, *statuses: str) -> list[sqlite3.Row]:
    marks = ",".join("?" * len(statuses))
    return conn.execute(
        f"""SELECT i.*, f.name AS current_folder_name
            FROM items i LEFT JOIN folders f
              ON f.account_id = i.account_id AND f.folder_id = i.current_folder_id
            WHERE i.account_id=? AND i.status IN ({marks})
            ORDER BY i.name COLLATE NOCASE""",
        (account_id, *statuses),
    ).fetchall()


def set_category(
    conn: sqlite3.Connection,
    account_id: str,
    item_id: str,
    category: str,
    confidence: float | None,
    source: str,
    suggested: str | None = None,
) -> None:
    """Assign a category (status -> planned). Never touches moved/manual/skipped/gone items."""
    with conn:
        conn.execute(
            """UPDATE items SET category=?, suggested_category=?, confidence=?, category_source=?,
                                classified_at=?, status='planned'
               WHERE account_id=? AND item_id=? AND status IN ('new','planned','failed')""",
            (category, suggested, confidence, source, now(), account_id, item_id),
        )


def reset_planned(conn: sqlite3.Connection, account_id: str, keep_user_edits: bool = True) -> int:
    """Send planned items back to `new` so they get classified again."""
    sql = "UPDATE items SET status='new', category=NULL, suggested_category=NULL, confidence=NULL, category_source=NULL WHERE account_id=? AND status='planned'"
    if keep_user_edits:
        sql += " AND COALESCE(category_source,'') != 'user'"
    with conn:
        return conn.execute(sql, (account_id,)).rowcount


def register_bwsort_folder(conn: sqlite3.Connection, account_id: str, folder_id: str, name: str) -> None:
    with conn:
        conn.execute(
            """INSERT INTO folders(account_id, folder_id, name, created_by_bwsort, created_at) VALUES (?,?,?,1,?)
               ON CONFLICT(account_id, folder_id) DO UPDATE SET name=excluded.name, created_by_bwsort=1""",
            (account_id, folder_id, name, now()),
        )


def mark_moved(
    conn: sqlite3.Connection, run_id: int, account_id: str, item_id: str, from_folder: str | None, to_folder: str
) -> None:
    ts = now()
    with conn:
        conn.execute(
            """UPDATE items SET status='moved', target_folder_id=?, current_folder_id=?, moved_at=?, last_error=NULL
               WHERE account_id=? AND item_id=?""",
            (to_folder, to_folder, ts, account_id, item_id),
        )
        conn.execute(
            "INSERT INTO moves(run_id, account_id, item_id, from_folder_id, to_folder_id, at) VALUES (?,?,?,?,?,?)",
            (run_id, account_id, item_id, from_folder, to_folder, ts),
        )


def mark_failed(conn: sqlite3.Connection, account_id: str, item_id: str, error: str) -> None:
    with conn:
        conn.execute(
            "UPDATE items SET status='failed', last_error=? WHERE account_id=? AND item_id=?",
            (error[:500], account_id, item_id),
        )
