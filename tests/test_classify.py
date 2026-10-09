import csv
import json
import sqlite3

import pytest

from bwsort import categories as cat
from bwsort import classify as clf
from bwsort import db
from bwsort import review as rv
from bwsort.llm import LlmError
from bwsort.sanitize import SafeItem

ACC = "user-1"
CATS = [
    cat.Category("Banking", "Banks", ["chase.com"]),
    cat.Category("Shopping", "Stores", ["amazon.com"]),
    cat.Category("Payment Cards", fixed=True),
    cat.Category("Unsorted", fixed=True),
]


class FakeLLM:
    """Answers from a dict item_name -> (category, confidence); names not in it are skipped."""

    def __init__(self, answers, fail_calls=()):
        self.answers = answers
        self.fail_calls = set(fail_calls)
        self.calls = []

    def chat_json(self, messages, schema, **kw):
        self.calls.append((messages, schema))
        if len(self.calls) in self.fail_calls:
            raise LlmError("boom")
        items = json.loads(messages[1]["content"])
        results = []
        for it in items:
            assert set(it) <= {"id", "type", "name", "domains", "old_folder"}
            if it["name"] in self.answers:
                category, conf = self.answers[it["name"]]
                results.append({"id": it["id"], "category": category, "confidence": conf})
        results.append({"id": "invented-id", "category": "Banking", "confidence": "high"})
        return {"results": results}, 0.1


def make_db(tmp_path, items):
    conn = db.connect(tmp_path / "t.db")
    db.ensure_account(conn, ACC, "x")
    db.sync_snapshot(conn, ACC, items, [{"id": "old", "name": "Old"}])
    cat.store(conn, ACC, CATS)
    return conn


def it(id_, name, domains=(), type_="login", folder=None):
    return SafeItem(id=id_, type=type_, name=name, domains=list(domains), folder_id=folder, in_organization=False)


def row(conn, item_id):
    return conn.execute("SELECT * FROM items WHERE item_id=?", (item_id,)).fetchone()


def test_classify_paths(tmp_path):
    conn = make_db(tmp_path, [
        it("1", "Chase", ["chase.com"], folder="old"),
        it("2", "Amazon", ["amazon.com"]),
        it("3", "Weird thing"),
        it("4", "Visa", type_="card"),
        it("5", "Maybe shop", ["shop.example"]),
    ])
    llm = FakeLLM({"Chase": ("Banking", "high"), "Amazon": ("Shopping", "medium"), "Maybe shop": ("Shopping", "low")})
    rep = clf.classify(conn, ACC, llm, cat.load_stored(conn, ACC), batch_size=10)

    assert row(conn, "1")["category"] == "Banking" and row(conn, "1")["status"] == "planned"
    assert row(conn, "2")["category"] == "Shopping"
    assert row(conn, "4")["category"] == "Payment Cards" and row(conn, "4")["category_source"] == "rule"
    assert row(conn, "5")["category"] == "Unsorted" and row(conn, "5")["suggested_category"] == "Shopping"
    assert row(conn, "3")["category"] == "Unsorted" and row(conn, "3")["category_source"] == "fallback"
    assert (rep.by_rule, rep.by_llm, rep.low_confidence, rep.fallback) == (1, 3, 1, 1)
    assert len(llm.calls) == 2  # one batch + one retry for the skipped item

    # schema pins ids and categories; old folder is passed as a hint; cards never reach the LLM
    schema = llm.calls[0][1]["properties"]["results"]["items"]["properties"]
    assert set(schema["id"]["enum"]) == {"1", "2", "3", "5"}
    assert schema["category"]["enum"] == ["Banking", "Shopping", "Payment Cards", "Unsorted"]
    sent = json.loads(llm.calls[0][0][1]["content"])
    assert {"id": "1", "type": "login", "name": "Chase", "domains": ["chase.com"], "old_folder": "Old"} in sent
    assert "Visa" not in llm.calls[0][0][1]["content"]


def test_failed_request_leaves_items_new(tmp_path):
    conn = make_db(tmp_path, [it("1", "Chase", ["chase.com"]), it("2", "Amazon", ["amazon.com"])])
    llm = FakeLLM({"Chase": ("Banking", "high"), "Amazon": ("Shopping", "high")}, fail_calls={1})
    rep = clf.classify(conn, ACC, llm, cat.load_stored(conn, ACC), batch_size=1)
    statuses = {r["item_id"]: r["status"] for r in conn.execute("SELECT item_id, status FROM items")}
    assert statuses == {"1": "planned", "2": "new"} or statuses == {"1": "new", "2": "planned"}
    assert len(rep.errors) == 1
    # a second run picks up only what's left
    clf.classify(conn, ACC, FakeLLM({"Chase": ("Banking", "high"), "Amazon": ("Shopping", "high")}), cat.load_stored(conn, ACC))
    assert db.status_counts(conn, ACC)["planned"] == 2


def test_aborts_after_repeated_failures(tmp_path):
    conn = make_db(tmp_path, [it(str(i), f"n{i}") for i in range(5)])
    with pytest.raises(LlmError):
        clf.classify(conn, ACC, FakeLLM({}, fail_calls={1, 2, 3}), cat.load_stored(conn, ACC), batch_size=1)
    assert db.status_counts(conn, ACC)["new"] == 5


def test_limit_and_domain_ordering(tmp_path):
    conn = make_db(tmp_path, [it("1", "b", ["zeta.com"]), it("2", "a", ["alpha.com"]), it("3", "c")])
    pending = clf.load_pending(conn, ACC)
    assert [p.item_id for p in pending] == ["2", "1", "3"]
    llm = FakeLLM({"a": ("Shopping", "high")})
    clf.classify(conn, ACC, llm, cat.load_stored(conn, ACC), limit=1)
    assert db.status_counts(conn, ACC)["planned"] == 1


def test_csv_roundtrip_and_reclassify(tmp_path):
    conn = make_db(tmp_path, [it("1", "Chase", ["chase.com"]), it("2", "Amazon", ["amazon.com"])])
    clf.classify(conn, ACC, FakeLLM({"Chase": ("Shopping", "high"), "Amazon": ("Shopping", "high")}), cat.load_stored(conn, ACC))
    path = tmp_path / "plan.csv"
    assert rv.export_csv(conn, ACC, path) == 2
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    for r in rows:
        if r["name"] == "Chase":
            r["category"] = "banking"
    rows.append({**rows[0], "item_id": "2", "category": "Nope"})
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=rv.CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    changed, errors = rv.import_csv(conn, ACC, path, [c.name for c in CATS])
    assert changed == 1 and len(errors) == 1
    assert row(conn, "1")["category"] == "Banking" and row(conn, "1")["category_source"] == "user"

    # --reclassify keeps your edit and resets the rest
    assert db.reset_planned(conn, ACC) == 1
    assert row(conn, "1")["status"] == "planned" and row(conn, "2")["status"] == "new"


def test_migration_from_v1(tmp_path):
    path = tmp_path / "old.db"
    v1 = db._SCHEMA.replace("    examples     TEXT NOT NULL DEFAULT '[]',   -- JSON list (v2)\n", "")
    v1 = v1.replace("    suggested_category TEXT,                   -- model's pick when confidence was too low (v2)\n", "")
    v1 += "CREATE TABLE domain_cache (account_id TEXT, domain TEXT, category TEXT);"
    raw = sqlite3.connect(path)
    raw.executescript(v1)
    raw.execute("PRAGMA user_version = 1")
    raw.execute("INSERT INTO accounts VALUES ('u','x','t','t')")
    raw.execute("INSERT INTO categories(account_id, name) VALUES ('u','Banking')")
    raw.commit()
    raw.close()

    conn = db.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert [c.examples for c in cat.load_stored(conn, "u")] == [[]]
    assert "suggested_category" in {r[1] for r in conn.execute("PRAGMA table_info(items)")}
    assert not conn.execute("SELECT name FROM sqlite_master WHERE name='domain_cache'").fetchone()
