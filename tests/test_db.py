from bwsort import db
from bwsort.sanitize import SafeItem

ACC = "user-1"


def item(id_, folder=None, org=False, name=None):
    return SafeItem(
        id=id_, type="login", name=name or id_, domains=[f"{id_}.com"], folder_id=folder, in_organization=org
    )


def status_of(conn, item_id):
    return conn.execute("SELECT status FROM items WHERE account_id=? AND item_id=?", (ACC, item_id)).fetchone()[0]


def test_lifecycle(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.ensure_account(conn, ACC, "https://vault.bitwarden.com")
    folders = [{"id": "old", "name": "Old stuff"}]

    # first run: everything personal is new, including items already in folders
    rep = db.sync_snapshot(conn, ACC, [item("a", "old"), item("b"), item("c", org=True)], folders)
    assert (rep.new, rep.skipped_org) == (2, 1)
    assert status_of(conn, "a") == "new"
    assert status_of(conn, "c") == "skipped"

    # classify + move "a" into a bwsort folder
    db.set_category(conn, ACC, "a", "Finance", 0.9, "llm")
    assert status_of(conn, "a") == "planned"
    db.register_bwsort_folder(conn, ACC, "fin", "Finance")
    run = db.start_run(conn, ACC, "apply")
    db.mark_moved(conn, run, ACC, "a", "old", "fin")
    folders.append({"id": "fin", "name": "Finance"})

    # second run: a stays sorted, b is still new (not re-counted), d is new,
    # e is new but you already put it into a bwsort folder
    rep = db.sync_snapshot(
        conn, ACC, [item("a", "fin"), item("b"), item("c", org=True), item("d"), item("e", "fin")], folders
    )
    assert rep.already_moved == 1
    assert rep.new == 1 and rep.new_but_manual == 1
    assert status_of(conn, "a") == "moved"
    assert status_of(conn, "d") == "new"
    assert status_of(conn, "e") == "manual"
    assert rep.pending["new"] == 2  # b and d

    # third run: you moved "a" elsewhere, "b" was deleted
    rep = db.sync_snapshot(conn, ACC, [item("a", "old"), item("c", org=True), item("d"), item("e", "fin")], folders)
    assert rep.became_manual == 1 and rep.gone == 1
    assert status_of(conn, "a") == "manual"
    assert status_of(conn, "b") == "gone"

    # set_category never touches items bwsort must leave alone
    db.set_category(conn, ACC, "a", "Shopping", 0.5, "llm")
    assert status_of(conn, "a") == "manual"

    # fourth run: "b" restored from trash -> new again
    rep = db.sync_snapshot(conn, ACC, [item("a", "old"), item("b"), item("d"), item("e", "fin")], folders)
    assert rep.restored == 1
    assert status_of(conn, "b") == "new"

    # rollback journal recorded the original folder
    mv = conn.execute("SELECT from_folder_id, to_folder_id FROM moves WHERE item_id='a'").fetchone()
    assert tuple(mv) == ("old", "fin")


def test_accounts_are_isolated(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    for acc in ("u1", "u2"):
        db.ensure_account(conn, acc, "https://vault.bitwarden.com")
    db.sync_snapshot(conn, "u1", [item("a")], [])
    db.sync_snapshot(conn, "u2", [item("a"), item("b")], [])
    assert db.status_counts(conn, "u1")["new"] == 1
    assert db.status_counts(conn, "u2")["new"] == 2


def test_failed_items_stay_pending(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.ensure_account(conn, ACC, "x")
    db.sync_snapshot(conn, ACC, [item("a")], [])
    db.set_category(conn, ACC, "a", "Finance", 0.9, "llm")
    db.mark_failed(conn, ACC, "a", "bw edit failed")
    assert [r["item_id"] for r in db.items_with_status(conn, ACC, "planned", "failed")] == ["a"]
    db.sync_snapshot(conn, ACC, [item("a")], [])
    assert status_of(conn, "a") == "failed"
