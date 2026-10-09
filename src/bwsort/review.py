"""Stage 4 helpers: look at the classification and correct it via CSV."""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from . import db

CSV_COLUMNS = [
    "item_id", "name", "type", "domains", "old_folder",
    "category", "suggested_category", "confidence", "source",
]


def summary(conn: sqlite3.Connection, account_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT category,
                  COUNT(*)                                             AS items,
                  SUM(category_source = 'rule')                        AS by_rule,
                  SUM(category_source = 'user')                        AS by_user,
                  SUM(confidence >= 0.85)                              AS high,
                  SUM(confidence >= 0.5 AND confidence < 0.85)         AS medium,
                  SUM(suggested_category IS NOT NULL)                  AS low_moved_to_unsorted,
                  SUM(category_source = 'fallback')                    AS unanswered
           FROM items
           WHERE account_id=? AND status IN ('planned','failed')
           GROUP BY category ORDER BY items DESC""",
        (account_id,),
    ).fetchall()


def planned_items(conn: sqlite3.Connection, account_id: str, category: str | None = None) -> list[sqlite3.Row]:
    rows = db.items_with_status(conn, account_id, "planned", "failed")
    if category:
        rows = [r for r in rows if (r["category"] or "").lower() == category.lower()]
    return sorted(rows, key=lambda r: ((r["category"] or ""), r["name"].lower()))


def export_csv(conn: sqlite3.Connection, account_id: str, path: Path) -> int:
    rows = planned_items(conn, account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig so Excel opens it correctly
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for r in rows:
            w.writerow([
                r["item_id"], r["name"], r["type"], " ".join(json.loads(r["domains"])),
                r["current_folder_name"] or "", r["category"] or "", r["suggested_category"] or "",
                "" if r["confidence"] is None else f"{r['confidence']:.1f}", r["category_source"] or "",
            ])
    return len(rows)


def import_csv(
    conn: sqlite3.Connection, account_id: str, path: Path, valid_names: list[str]
) -> tuple[int, list[str]]:
    """Apply edited `category` cells. Returns (changed, errors). Unknown names are reported, not applied."""
    by_lower = {n.lower(): n for n in valid_names}
    current = {r["item_id"]: r["category"] for r in db.items_with_status(conn, account_id, "planned", "failed")}
    changed, errors = 0, []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for line_no, row in enumerate(csv.DictReader(fh), start=2):
            item_id = (row.get("item_id") or "").strip()
            wanted = (row.get("category") or "").strip()
            if item_id not in current:
                if item_id:
                    errors.append(f"line {line_no}: item {item_id[:8]}... is not waiting to be moved, skipped")
                continue
            name = by_lower.get(wanted.lower())
            if not name:
                errors.append(f"line {line_no}: unknown category {wanted!r}")
                continue
            if name != current[item_id]:
                db.set_category(conn, account_id, item_id, name, 1.0, "user")
                changed += 1
    return changed, errors
