import pytest

from bwsort import categories as cat
from bwsort import db
from bwsort.sanitize import SafeItem

ACC = "user-1"


def item(id_, type_="login", domains=(), name=None, folder=None):
    return SafeItem(
        id=id_, type=type_, name=name or id_, domains=list(domains), folder_id=folder, in_organization=False
    )


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.ensure_account(c, ACC, "x")
    items = [
        item("1", domains=["chase.com"], name="Chase checking", folder="f1"),
        item("2", domains=["chase.com"], name="Chase business"),
        item("3", domains=["amazon.com"], name="Amazon"),
        item("4", type_="secure_note", name="Home wifi"),
        item("5", type_="card", name="Visa"),
    ]
    db.sync_snapshot(c, ACC, items, [{"id": "f1", "name": "Banks"}])
    return c


def test_overview(conn):
    ov = cat.build_overview(conn, ACC)
    assert ov.total == 5
    assert ov.domains[0] == ("chase.com", 2, ["Chase checking", "Chase business"])
    assert ov.nameless == ["Home wifi"]          # cards are excluded, handled by type
    assert ov.old_folders == [("Banks", 1)]
    text = cat.overview_text(ov)
    assert "chase.com x2" in text and "Visa" not in text


def test_normalize_drops_bad_entries(conn):
    ov = cat.build_overview(conn, ACC)
    raw = {"categories": [
        {"name": "Banking", "description": "Banks", "examples": ["chase.com", "madeup.com"]},
        {"name": "banking", "description": "dup", "examples": []},
        {"name": "Misc", "description": "", "examples": []},
        {"name": "Payment Cards", "description": "", "examples": []},
        {"name": "Shopping/Retail", "description": "Stores", "examples": ["AMAZON.COM"]},
        {"name": "Banque épargne", "description": "", "examples": []},
    ]}
    out = cat.normalize_llm_categories(raw, ov)
    assert [c.name for c in out] == ["Banking", "Shopping Retail"]
    assert out[0].examples == ["chase.com"]       # invented example dropped
    assert out[1].examples == ["amazon.com"]


def test_with_fixed_only_for_present_types(conn):
    ov = cat.build_overview(conn, ACC)
    final = cat.with_fixed([cat.Category("Banking")], ov.type_counts)
    assert [c.name for c in final] == ["Banking", "Payment Cards", "Unsorted"]


def test_yaml_roundtrip_and_store(conn, tmp_path):
    path = tmp_path / "categories.yaml"
    cat.save_yaml(path, ACC, [cat.Category("Banking", "Banks", ["chase.com"]), cat.Category("Unsorted", fixed=True)])
    assert path.read_text(encoding="utf-8").startswith("# bwsort categories")
    loaded = cat.load_yaml(path)
    assert [c.name for c in loaded] == ["Banking", "Unsorted"]
    cat.store(conn, ACC, loaded)
    assert [c.name for c in cat.load_stored(conn, ACC)] == ["Banking", "Unsorted"]


def test_yaml_validation(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("categories:\n  - Banking\n  - banking\n", encoding="utf-8")
    with pytest.raises(cat.CategoryError):
        cat.load_yaml(path)
    path.write_text("categories:\n  - Work/Clients\n", encoding="utf-8")
    with pytest.raises(cat.CategoryError):
        cat.load_yaml(path)
    path.write_text("categories:\n  - Banking\n", encoding="utf-8")
    assert [c.name for c in cat.load_yaml(path)] == ["Banking", "Unsorted"]  # Unsorted re-added


def test_folder_plan_reuses_same_name():
    plan = cat.folder_plan([cat.Category("Banking"), cat.Category("Travel")], [{"id": "f9", "name": "banking "}])
    assert [(c.name, fid) for c, fid in plan] == [("Banking", "f9"), ("Travel", None)]


def test_num_ctx_grows_with_prompt():
    assert cat.estimate_num_ctx("x" * 100) == 8192
    assert cat.estimate_num_ctx("x" * 60000) == 32768
