import base64
import copy
import json
import subprocess
from unittest import mock

from bwsort import apply as mover
from bwsort import db
from bwsort.bw import BwClient, BwError
from bwsort.sanitize import SafeItem

ACC = "user-1"
SECRET = "hunter2-SUPER-secret"


def full_item(id_, folder=None, **extra):
    item = {
        "object": "item", "id": id_, "organizationId": None, "folderId": folder, "type": 1,
        "name": f"Item {id_}", "notes": "note", "favorite": False, "reprompt": 0,
        "login": {
            "username": "me", "password": SECRET, "totp": None,
            "uris": [{"match": None, "uri": "https://x.com"}],
            "fido2Credentials": [{"credentialId": "c1", "keyValue": "k"}],
        },
        "attachments": [{"id": "a1", "fileName": "f.txt", "size": "10", "url": "https://blob/sig=1"}],
        "passwordHistory": [], "revisionDate": "2026-01-01", "creationDate": "2025-01-01", "deletedDate": None,
    }
    item.update(extra)
    return item


class FakeBw:
    """In-memory vault. `break_edit` simulates a CLI that drops a field on edit."""

    def __init__(self, items, break_edit=None, fail_ids=()):
        self.items = {i["id"]: i for i in items}
        self.break_edit = break_edit
        self.fail_ids = set(fail_ids)
        self.edits = []

    def get_item_raw(self, item_id):
        if item_id in self.fail_ids:
            raise BwError("Not found.")
        return copy.deepcopy(self.items[item_id])

    def edit_item_raw(self, item_id, item):
        self.edits.append(item_id)
        saved = copy.deepcopy(item)
        saved["revisionDate"] = "2026-10-09"
        saved["attachments"][0]["url"] = "https://blob/sig=2"  # signed URLs change; must not count
        if self.break_edit:
            self.break_edit(saved)
        self.items[item_id] = saved
        return copy.deepcopy(saved)


def setup(tmp_path, ids, folder="old"):
    conn = db.connect(tmp_path / "t.db")
    db.ensure_account(conn, ACC, "x")
    safe = [SafeItem(id=i, type="login", name=f"Item {i}", domains=["x.com"], folder_id=folder, in_organization=False) for i in ids]
    db.sync_snapshot(conn, ACC, safe, [{"id": "old", "name": "Old"}, {"id": "fin", "name": "Finance"}])
    db.register_bwsort_folder(conn, ACC, "fin", "Finance")
    for i in ids:
        db.set_category(conn, ACC, i, "Finance", 0.9, "llm")
    return conn


def rows(conn):
    return db.items_with_status(conn, ACC, "planned", "failed")


def status(conn, item_id):
    return conn.execute("SELECT status FROM items WHERE item_id=?", (item_id,)).fetchone()[0]


def test_moves_and_verifies(tmp_path):
    conn = setup(tmp_path, ["1", "2"])
    bw = FakeBw([full_item("1", "old"), full_item("2", "fin")])
    run = db.start_run(conn, ACC, "apply")
    rep = mover.apply_plan(conn, bw, ACC, run, rows(conn), {"Finance": "fin"})
    assert (rep.moved, rep.already_in_place, rep.failed, rep.stopped) == (1, 1, 0, None)
    assert bw.items["1"]["folderId"] == "fin" and bw.items["1"]["login"]["password"] == SECRET
    assert bw.edits == ["1"]  # item 2 was already there: no edit
    assert status(conn, "1") == status(conn, "2") == "moved"
    journal = conn.execute("SELECT item_id, from_folder_id, to_folder_id FROM moves").fetchall()
    assert [tuple(j) for j in journal] == [("1", "old", "fin")]


def test_lost_passkey_stops_the_run(tmp_path):
    conn = setup(tmp_path, ["1", "2", "3"])
    bw = FakeBw([full_item(i, "old") for i in "123"], break_edit=lambda it: it["login"].pop("fido2Credentials"))
    rep = mover.apply_plan(conn, bw, ACC, db.start_run(conn, ACC, "apply"), rows(conn), {"Finance": "fin"})
    assert rep.stopped and "login.fido2Credentials" in rep.stopped
    assert SECRET not in rep.stopped and "keyValue" not in rep.stopped
    assert len(bw.edits) == 1 and rep.failed == 1  # nothing else was touched
    assert db.status_counts(conn, ACC)["failed"] == 1 and db.status_counts(conn, ACC)["planned"] == 2


def test_rekeyed_item_is_not_a_mismatch(tmp_path):
    conn = setup(tmp_path, ["1"])
    item = full_item("1", "old", key="2.old-cipher-key")
    bw = FakeBw([item], break_edit=lambda it: it.update(key="2.new-cipher-key"))
    rep = mover.apply_plan(conn, bw, ACC, db.start_run(conn, ACC, "apply"), rows(conn), {"Finance": "fin"})
    assert (rep.moved, rep.failed, rep.stopped) == (1, 0, None)


def test_changed_password_is_detected():
    before = full_item("1")
    after = copy.deepcopy(before)
    after["login"]["password"] = "other"
    after["folderId"] = "x"
    assert mover.changed_paths(before, after) == ["login.password"]


def test_org_items_and_errors_do_not_stop_until_limit(tmp_path):
    ids = [str(i) for i in range(7)]
    conn = setup(tmp_path, ids)
    items = [full_item(i, "old") for i in ids]
    items[0]["organizationId"] = "org"
    bw = FakeBw(items, fail_ids={"1", "2", "3", "4"})
    rep = mover.apply_plan(conn, bw, ACC, db.start_run(conn, ACC, "apply"), rows(conn), {"Finance": "fin"})
    assert rep.stopped and "5 errors in a row" in rep.stopped
    assert rep.failed == 5 and rep.moved == 0 and bw.edits == []


def test_missing_folder_fails_item(tmp_path):
    conn = setup(tmp_path, ["1"])
    rep = mover.apply_plan(conn, FakeBw([full_item("1", "old")]), ACC, 1, rows(conn), {})
    assert rep.failed == 1 and "no folder" in rep.errors[0]


def test_rollback(tmp_path):
    conn = setup(tmp_path, ["1", "2", "3"])
    bw = FakeBw([full_item("1", "old"), full_item("2", None), full_item("3", "old")])
    run = db.start_run(conn, ACC, "apply")
    mover.apply_plan(conn, bw, ACC, run, rows(conn), {"Finance": "fin"})
    assert db.last_run_with_moves(conn, ACC) == run

    # you moved item 3 yourself afterwards -> rollback must leave it alone
    conn.execute("UPDATE items SET status='manual', current_folder_id='mine' WHERE item_id='3'")
    conn.commit()
    new_run = db.start_run(conn, ACC, f"rollback {run}")
    rep = mover.rollback_run(conn, bw, ACC, run, new_run, live_folder_ids={"fin"})  # "old" was deleted
    assert (rep.restored, rep.skipped, rep.failed) == (2, 1, 0)
    assert bw.items["1"]["folderId"] is None   # old folder gone -> No folder
    assert bw.items["2"]["folderId"] is None
    assert status(conn, "1") == "planned" and status(conn, "3") == "manual"


def test_empty_old_folders(tmp_path):
    conn = setup(tmp_path, ["1"])
    folders = [{"id": "old", "name": "Old"}, {"id": "fin", "name": "Finance"}, {"id": "x", "name": "Busy"}]
    items = [SafeItem(id="9", type="login", name="n", domains=[], folder_id="x", in_organization=True)]
    assert [f["name"] for f in mover.empty_old_folders(conn, ACC, folders, items)] == ["Old"]


def test_edit_sends_secrets_via_stdin_not_argv():
    client = BwClient(session="sess", bin_path="bw")
    item = full_item("1")
    saved = json.dumps(item)
    with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, saved, "")) as run:
        client.edit_item_raw("1", item)
    args, kwargs = run.call_args
    assert SECRET not in " ".join(args[0])
    assert SECRET in base64.b64decode(kwargs["input"]).decode()
    assert "sess" not in " ".join(args[0]) and kwargs["env"]["BW_SESSION"] == "sess"


def test_bw_errors_never_include_stdout():
    client = BwClient(session="sess", bin_path="bw")
    with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, SECRET, "Not found.")):
        try:
            client.get_item_raw("1")
        except BwError as exc:
            assert SECRET not in str(exc) and "Not found." in str(exc)
        else:
            raise AssertionError("expected BwError")


def _run_one(tmp_path, before_login, after_change):
    conn = setup(tmp_path, ["1"])
    item = full_item("1", "old")
    item["login"].update(before_login)
    bw = FakeBw([item], break_edit=after_change)
    return mover.apply_plan(conn, bw, ACC, db.start_run(conn, ACC, "apply"), rows(conn), {"Finance": "fin"})


def test_empty_totp_stored_as_null_is_harmless(tmp_path):
    rep = _run_one(tmp_path, {"totp": ""}, lambda it: it["login"].update(totp=None))
    assert (rep.moved, rep.stopped) == (1, None)
    assert rep.notes == ["Item 1: login.totp (empty value stored differently)"]


def test_totp_spaces_and_case_are_harmless(tmp_path):
    rep = _run_one(tmp_path, {"totp": "jbsw y3dp ehpk 3pxp"}, lambda it: it["login"].update(totp="JBSWY3DPEHPK3PXP"))
    assert (rep.moved, rep.stopped) == (1, None) and "same TOTP key" in rep.notes[0]


def test_different_totp_stops_without_leaking(tmp_path):
    rep = _run_one(tmp_path, {"totp": "JBSWY3DPEHPK3PXP"}, lambda it: it["login"].update(totp="AAAABBBBCCCCDDDD"))
    assert rep.stopped and "login.totp (different value)" in rep.stopped and "Item 1" in rep.stopped
    assert "JBSW" not in rep.stopped and "AAAA" not in rep.stopped


def test_totp_lost_or_uri_rewritten_stops(tmp_path):
    rep = _run_one(tmp_path, {"totp": "JBSWY3DPEHPK3PXP"}, lambda it: it["login"].update(totp=None))
    assert "was set, now empty" in rep.stopped


def test_password_whitespace_is_not_harmless():
    d = mover.classify_difference("login.password", "secret ", "secret")
    assert d.kind == "whitespace only" and not d.harmless
    d = mover.classify_difference("login.totp", "otpauth://totp/x?secret=JBSW", "JBSW")
    assert d.kind == "otpauth:// link vs plain key" and not d.harmless
