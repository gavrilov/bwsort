"""Stage 2: propose, edit and store the folder taxonomy.

The LLM sees an aggregated overview (domains with counts and a couple of
redacted item names, old folder names, type counts). Never secrets.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


UNSORTED = "Unsorted"
# Item types that are sorted by rule, not by the LLM.
TYPE_CATEGORIES = {"card": "Payment Cards", "identity": "Identities", "ssh_key": "SSH Keys"}
RESERVED = {UNSORTED, *TYPE_CATEGORIES.values()}
BANNED = {"other", "others", "misc", "miscellaneous", "general", "uncategorized", "unsorted"}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &+.,'()\-]{0,29}$")
MIN_LLM_CATEGORIES = 6
MAX_LLM_CATEGORIES = 24
MAX_DOMAINS_IN_PROMPT = 450
MAX_NAMELESS_IN_PROMPT = 200

YAML_HEADER = """\
# bwsort categories (= Bitwarden folder names), account {account}
#
# Edit freely: rename, merge, delete or add entries. Rules:
#   - English, one level (no "/"), up to 30 characters, letters/digits/space & + . , ' ( ) -
#   - names must be unique (case-insensitive)
#   - "{unsorted}" is always kept: low-confidence items land there for manual sorting
#   - fixed categories for cards, identities and SSH keys are filled by item type, not by the LLM
# "examples" and "description" help the classifier; keep descriptions short and concrete.
#
# When done:  uv run bwsort categories --import
"""


class CategoryError(ValueError):
    pass


@dataclass
class Category:
    name: str
    description: str = ""
    examples: list[str] = field(default_factory=list)
    fixed: bool = False


# --- overview for the LLM -------------------------------------------------


@dataclass
class Overview:
    total: int
    type_counts: dict[str, int]
    domains: list[tuple[str, int, list[str]]]  # (domain, count, sample names)
    nameless: list[str]                         # names of items without any domain
    old_folders: list[tuple[str, int]]
    truncated: bool


def build_overview(conn: sqlite3.Connection, account_id: str) -> Overview:
    rows = conn.execute(
        """SELECT i.type, i.name, i.domains, f.name AS folder
           FROM items i LEFT JOIN folders f
             ON f.account_id = i.account_id AND f.folder_id = i.current_folder_id
           WHERE i.account_id=? AND i.status NOT IN ('gone','skipped')""",
        (account_id,),
    ).fetchall()

    types = Counter()
    dom_count: Counter[str] = Counter()
    dom_names: dict[str, list[str]] = defaultdict(list)
    nameless: list[str] = []
    folders: Counter[str] = Counter()
    for r in rows:
        types[r["type"]] += 1
        if r["folder"]:
            folders[r["folder"]] += 1
        if r["type"] in TYPE_CATEGORIES:
            continue
        domains = json.loads(r["domains"])
        if not domains:
            nameless.append(r["name"])
            continue
        main = domains[0]
        dom_count[main] += 1
        if len(dom_names[main]) < 2 and r["name"] and r["name"].lower() != main.lower():
            dom_names[main].append(r["name"][:40])

    top = dom_count.most_common()
    truncated = len(top) > MAX_DOMAINS_IN_PROMPT or len(nameless) > MAX_NAMELESS_IN_PROMPT
    return Overview(
        total=len(rows),
        type_counts=dict(types),
        domains=[(d, n, dom_names[d]) for d, n in top[:MAX_DOMAINS_IN_PROMPT]],
        nameless=sorted(set(nameless), key=str.lower)[:MAX_NAMELESS_IN_PROMPT],
        old_folders=folders.most_common(),
        truncated=truncated,
    )


def overview_text(ov: Overview) -> str:
    lines = [f"Total items: {ov.total}", "Item types: " + ", ".join(f"{k}={v}" for k, v in ov.type_counts.items())]
    if ov.old_folders:
        lines.append("\nUser's previous folders (name: items):")
        lines += [f"- {name}: {n}" for name, n in ov.old_folders]
    lines.append("\nDomains (domain xcount: sample item names):")
    for d, n, names in ov.domains:
        sample = f": {'; '.join(names)}" if names else ""
        lines.append(f"- {d} x{n}{sample}")
    if ov.nameless:
        lines.append("\nItems without a website (names only):")
        lines += [f"- {name}" for name in ov.nameless]
    return "\n".join(lines)


SYSTEM_PROMPT = f"""You design a folder structure for one person's password manager (Bitwarden).
You get an overview of their vault: websites with item counts and sample item names, items without a website, and their previous folders.
Propose a FLAT list of folders (categories) that a person would find intuitive when looking for a login.

Rules:
- Between 12 and 20 categories, organised by life area or purpose (e.g. banking, shopping, work, travel, government), not by technology.
- Categories must be mutually exclusive and together cover almost every item.
- Each category should plausibly hold at least 5 items of THIS vault; do not create categories for 1-2 items, merge them into a broader one.
- Names: English, Title Case, 1-3 words, at most 30 characters, ASCII only, no "/" and no emoji.
- Do NOT propose these, they already exist: {", ".join(sorted(RESERVED))}. Do NOT propose catch-alls like Other, Misc, General.
- The previous folders are the user's earlier attempt: reuse good names, ignore poor ones.
- For each category give a short concrete description (max 100 characters) that tells a classifier what belongs there,
  and 3-6 examples copied exactly from the overview (domains or item names).
"""

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "categories": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "examples": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name", "description", "examples"],
            },
        }
    },
    "required": ["categories"],
}


def estimate_num_ctx(prompt: str) -> int:
    """~3 chars per token for this kind of text, plus room for the answer, rounded up to a power of two."""
    need = len(prompt) // 3 + 3000
    ctx = 8192
    while ctx < need and ctx < 65536:
        ctx *= 2
    return ctx


# --- normalisation & validation -------------------------------------------


def clean_name(name: str) -> str:
    return " ".join((name or "").replace("/", " ").split())[:30].strip()


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise CategoryError(
            f"Invalid category name {name!r}: use English letters/digits, up to 30 chars, no '/'"
        )


def normalize_llm_categories(raw: dict[str, Any], ov: Overview) -> list[Category]:
    """Clean the model's answer: drop invalid/duplicate/reserved names and invented examples."""
    known = {d for d, _, _ in ov.domains} | {n for _, _, names in ov.domains for n in names} | set(ov.nameless)
    known_lower = {k.lower(): k for k in known}
    out: list[Category] = []
    seen: set[str] = set()
    for c in raw.get("categories") or []:
        name = clean_name(str(c.get("name", "")))
        key = name.lower()
        if not name or key in seen or key in BANNED or key in {r.lower() for r in RESERVED}:
            continue
        if not NAME_RE.match(name):
            continue
        examples = []
        for e in c.get("examples") or []:
            hit = known_lower.get(str(e).strip().lower())
            if hit and hit not in examples:
                examples.append(hit)
        seen.add(key)
        out.append(Category(name=name, description=" ".join(str(c.get("description", "")).split())[:120], examples=examples[:6]))
    return out[:MAX_LLM_CATEGORIES]


def with_fixed(categories: list[Category], type_counts: dict[str, int]) -> list[Category]:
    """Append the rule-based categories (only for types present) and Unsorted."""
    names = {c.name.lower() for c in categories}
    result = list(categories)
    for type_, name in TYPE_CATEGORIES.items():
        if type_counts.get(type_) and name.lower() not in names:
            result.append(Category(name, f"All items of type {type_} (assigned by type, not by the LLM)", fixed=True))
    if UNSORTED.lower() not in names:
        result.append(Category(UNSORTED, "Low-confidence items to sort by hand", fixed=True))
    return result


def validate_list(categories: list[Category]) -> list[Category]:
    if not categories:
        raise CategoryError("The category list is empty")
    seen: set[str] = set()
    for c in categories:
        validate_name(c.name)
        if c.name.lower() in seen:
            raise CategoryError(f"Duplicate category name: {c.name!r}")
        seen.add(c.name.lower())
    if UNSORTED.lower() not in seen:
        categories = [*categories, Category(UNSORTED, "Low-confidence items to sort by hand", fixed=True)]
    return categories


# --- YAML file ------------------------------------------------------------


def save_yaml(path: Path, account_id: str, categories: list[Category]) -> None:
    data = {
        "categories": [
            {"name": c.name, "description": c.description, "examples": c.examples} for c in categories
        ]
    }
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(YAML_HEADER.format(account=account_id[:8] + "...", unsorted=UNSORTED) + "\n" + body, encoding="utf-8")


def load_yaml(path: Path) -> list[Category]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CategoryError(f"{path} is not valid YAML: {exc}") from exc
    items = data.get("categories")
    if not isinstance(items, list):
        raise CategoryError(f"{path}: expected a top-level 'categories:' list")
    cats = []
    for i, c in enumerate(items, 1):
        if isinstance(c, str):
            c = {"name": c}
        if not isinstance(c, dict) or not c.get("name"):
            raise CategoryError(f"{path}: entry #{i} has no name")
        cats.append(
            Category(
                name=" ".join(str(c["name"]).split()),
                description=" ".join(str(c.get("description") or "").split()),
                examples=[str(e) for e in (c.get("examples") or [])],
                fixed=str(c["name"]).strip() in RESERVED,
            )
        )
    return validate_list(cats)


# --- DB -------------------------------------------------------------------


def store(conn: sqlite3.Connection, account_id: str, categories: list[Category]) -> None:
    with conn:
        conn.execute("DELETE FROM categories WHERE account_id=?", (account_id,))
        conn.executemany(
            "INSERT INTO categories(account_id, name, description, position) VALUES (?,?,?,?)",
            [(account_id, c.name, c.description, i) for i, c in enumerate(categories)],
        )


def load_stored(conn: sqlite3.Connection, account_id: str) -> list[Category]:
    rows = conn.execute(
        "SELECT name, description FROM categories WHERE account_id=? ORDER BY position", (account_id,)
    ).fetchall()
    return [Category(r["name"], r["description"], fixed=r["name"] in RESERVED) for r in rows]


def folder_plan(categories: list[Category], live_folders: list[dict]) -> list[tuple[Category, str | None]]:
    """Pair each category with an existing folder of the same name (case-insensitive), if any."""
    by_name = {f["name"].strip().lower(): f["id"] for f in live_folders}
    return [(c, by_name.get(c.name.lower())) for c in categories]
