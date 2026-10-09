"""Stages 5-6: move items into their folders (and back), with per-item verification.

The only module that handles full decrypted items. For each item:
  1. `bw get item`            -> full item, in memory only
  2. change `folderId` only
  3. `bw edit item` via stdin -> the CLI returns the saved item
  4. compare the saved item with the original, field by field;
     a real difference -> ContentMismatch, the whole run stops.
Only field PATHS and a value-free KIND of difference are ever reported
(e.g. "login.totp: was set, now empty"), never values, lengths or fragments.

Differences that cannot change what the item does are accepted and reported as notes:
  - null vs "" vs [] vs {} (the CLI may store an empty field as null);
  - login.totp differing only in spaces or letter case (base32 TOTP keys ignore both).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import db
from .bw import BwClient, BwError

# Fields expected to change on a folder move:
# - folderId: the point of the edit;
# - revisionDate: set by the server on every save;
# - key: the item's own encryption key, itself encrypted (an EncString). Current Bitwarden
#   clients re-key an item when saving it, so this ciphertext changes while the decrypted
#   content stays the same. Every decrypted field is still compared.
VOLATILE = {"folderId", "revisionDate", "key"}
# Nested objects compared key by key, so a mismatch names the exact field.
NESTED = {"login", "card", "identity", "secureNote", "sshKey"}
MAX_ERRORS_IN_A_ROW = 5


@dataclass(frozen=True)
class Difference:
    path: str
    kind: str
    harmless: bool

    def __str__(self) -> str:
        return f"{self.path} ({self.kind})"


class ContentMismatch(RuntimeError):
    def __init__(self, item_id: str, diffs: list[Difference]):
        super().__init__(f"item {item_id}: content changed after edit: {', '.join(map(str, diffs))}")
        self.item_id = item_id
        self.diffs = diffs

    @property
    def paths(self) -> list[str]:
        return [d.path for d in self.diffs]


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _comparable(key: str, value: Any) -> Any:
    if key == "attachments" and isinstance(value, list):
        # download URLs are signed and expire, so compare identity only
        return sorted(
            (str(a.get("id")), str(a.get("fileName")), str(a.get("size"))) for a in value if isinstance(a, dict)
        )
    return value


def _flatten(item: dict[str, Any]) -> dict[str, Any]:
    """Path -> comparable value, without the volatile fields."""
    out: dict[str, Any] = {}
    for key, value in item.items():
        if key in VOLATILE:
            continue
        if key in NESTED and isinstance(value, dict):
            for sub, sub_value in value.items():
                out[f"{key}.{sub}"] = sub_value
        else:
            out[key] = _comparable(key, value)
    return out


def fingerprint(item: dict[str, Any]) -> dict[str, str]:
    """Path -> digest for every field except the volatile ones. Values are not kept."""
    return {path: _digest(value) for path, value in _flatten(item).items()}


def changed_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    fb, fa = fingerprint(before), fingerprint(after)
    return sorted(p for p in fb.keys() | fa.keys() if fb.get(p) != fa.get(p))


_MISSING = object()


def _is_empty(v: Any) -> bool:
    return v is _MISSING or v is None or v == "" or v == [] or v == {}


def _squash(s: str) -> str:
    return "".join(s.split())


def classify_difference(path: str, before: Any, after: Any) -> Difference:
    """Name the kind of a difference without revealing either value."""
    if _is_empty(before) and _is_empty(after):
        return Difference(path, "empty value stored differently", True)
    if _is_empty(before):
        return Difference(path, "was empty, now set", False)
    if _is_empty(after):
        return Difference(path, "was set, now empty", False)
    if isinstance(before, str) and isinstance(after, str):
        if path == "login.totp":
            if _squash(before).upper() == _squash(after).upper():
                return Difference(path, "spaces or letter case only, same TOTP key", True)
            if before.lower().startswith("otpauth://") != after.lower().startswith("otpauth://"):
                return Difference(path, "otpauth:// link vs plain key", False)
        if _squash(before) == _squash(after):
            return Difference(path, "whitespace only", False)
        if before.lower() == after.lower():
            return Difference(path, "letter case only", False)
        return Difference(path, "different value", False)
    if type(before) is not type(after):
        return Difference(path, f"type {type(before).__name__} -> {type(after).__name__}", False)
    if isinstance(before, list):
        return Difference(path, f"list changed ({len(before)} -> {len(after)} entries)", False)
    return Difference(path, "different value", False)


def differences(before: dict[str, Any], after: dict[str, Any]) -> list[Difference]:
    fb, fa = _flatten(before), _flatten(after)
    out = []
    for path in sorted(fb.keys() | fa.keys()):
        b, a = fb.get(path, _MISSING), fa.get(path, _MISSING)
        if b is _MISSING or a is _MISSING or _digest(b) != _digest(a):
            out.append(classify_difference(path, b, a))
    return out


def move_item(
    bw: BwClient, item_id: str, target_folder_id: str | None
) -> tuple[str | None, bool, list[Difference]]:
    """Move one item. Returns (previous folder id, True if an edit was made, harmless differences)."""
    before = bw.get_item_raw(item_id)
    updated: dict[str, Any] = {}
    after: dict[str, Any] = {}
    try:
        if before.get("id") != item_id:
            raise BwError("bw returned a different item")
        if before.get("organizationId"):
            raise BwError("organization item, refusing to edit")
        if before.get("deletedDate"):
            raise BwError("item is in the trash")
        source = before.get("folderId")
        if source == target_folder_id:
            return source, False, []
        updated = dict(before)
        updated["folderId"] = target_folder_id
        after = bw.edit_item_raw(item_id, updated)
        diffs = differences(before, after)
        problems = [d for d in diffs if not d.harmless]
        if after.get("folderId") != target_folder_id:
            problems.append(Difference("folderId", "move not applied", False))
        if problems:
            raise ContentMismatch(item_id, problems)
        return source, True, [d for d in diffs if d.harmless]
    finally:
        before.clear()
        updated.clear()
        after.clear()


@dataclass
class ApplyReport:
    moved: int = 0
    already_in_place: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stopped: str | None = None


def apply_plan(
    conn: sqlite3.Connection,
    bw: BwClient,
    account_id: str,
    run_id: int,
    rows: list[sqlite3.Row],
    folder_map: dict[str, str],
    on_item: Callable[[], None] | None = None,
) -> ApplyReport:
    """Move planned rows. Each item is committed to the DB right after its edit."""
    rep = ApplyReport()
    errors_in_a_row = 0
    for r in rows:
        item_id = r["item_id"]
        target = folder_map.get(r["category"])
        try:
            if not target:
                raise BwError(f"no folder for category {r['category']!r}")
            source, edited, harmless = move_item(bw, item_id, target)
            db.mark_moved(conn, run_id, account_id, item_id, source, target, journal=edited)
            rep.notes += [f"{r['name']}: {d}" for d in harmless]
            if edited:
                rep.moved += 1
            else:
                rep.already_in_place += 1
            errors_in_a_row = 0
        except ContentMismatch as exc:
            db.mark_failed(conn, account_id, item_id, str(exc))
            rep.failed += 1
            rep.stopped = f"{r['name']}: {exc}"
            break
        except (BwError, ValueError) as exc:  # ValueError: bad JSON from bw
            db.mark_failed(conn, account_id, item_id, str(exc))
            rep.failed += 1
            rep.errors.append(f"{r['name']}: {exc}")
            errors_in_a_row += 1
            if errors_in_a_row >= MAX_ERRORS_IN_A_ROW:
                rep.stopped = f"{errors_in_a_row} errors in a row, last: {exc}"
                break
        finally:
            if on_item:
                on_item()
    return rep


@dataclass
class RollbackReport:
    restored: int = 0
    skipped: int = 0
    failed: int = 0
    notes: list[str] = field(default_factory=list)
    stopped: str | None = None


def rollback_run(
    conn: sqlite3.Connection,
    bw: BwClient,
    account_id: str,
    source_run: int,
    new_run: int,
    live_folder_ids: set[str],
    on_item: Callable[[], None] | None = None,
) -> RollbackReport:
    """Undo the moves of one run, newest first. Items you moved since then are left alone."""
    rep = RollbackReport()
    moves = conn.execute(
        """SELECT m.item_id, m.from_folder_id, m.to_folder_id, i.name, i.status, i.current_folder_id
           FROM moves m JOIN items i ON i.account_id = m.account_id AND i.item_id = m.item_id
           WHERE m.account_id=? AND m.run_id=? ORDER BY m.move_id DESC""",
        (account_id, source_run),
    ).fetchall()
    for m in moves:
        try:
            if m["status"] != "moved" or m["current_folder_id"] != m["to_folder_id"]:
                rep.skipped += 1
                rep.notes.append(f"{m['name']}: changed since that run, left as is")
                continue
            dest = m["from_folder_id"]
            if dest and dest not in live_folder_ids:
                rep.notes.append(f"{m['name']}: old folder no longer exists, moved to 'No folder'")
                dest = None
            _, _, harmless = move_item(bw, m["item_id"], dest)
            rep.notes += [f"{m['name']}: {d}" for d in harmless]
            db.mark_rolled_back(conn, new_run, account_id, m["item_id"], m["to_folder_id"], dest)
            rep.restored += 1
        except ContentMismatch as exc:
            db.mark_failed(conn, account_id, m["item_id"], str(exc))
            rep.failed += 1
            rep.stopped = str(exc)
            break
        except (BwError, ValueError) as exc:
            rep.failed += 1
            rep.notes.append(f"{m['name']}: {exc}")
        finally:
            if on_item:
                on_item()
    return rep


def empty_old_folders(conn: sqlite3.Connection, account_id: str, live_folders: list[dict], items) -> list[dict]:
    """Folders not created/adopted by bwsort that hold no items at all (any type, any owner)."""
    ours = set(db.bwsort_folder_map(conn, account_id).values())
    used = {i.folder_id for i in items if i.folder_id}
    return [f for f in live_folders if f["id"] not in ours and f["id"] not in used]
