"""Stage 3: assign every `new` item to one of the stored categories.

- cards / identities / SSH keys go to their fixed folder by type (no LLM), if that folder exists;
- everything else goes to the LLM in batches, sorted by domain so related items land together;
- the reply schema restricts `id` to the ids of the batch and `category` to the stored names,
  so the model cannot invent either; replies are validated again here;
- confidence below the threshold -> Unsorted (the model's pick is kept as `suggested_category`).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import categories as cat
from . import db
from .llm import LlmError, OllamaClient
from .sanitize import llm_payload

CONFIDENCE = {"high": 0.9, "medium": 0.6, "low": 0.3}
FALLBACK_SOURCE = "fallback"
MAX_FAILURES_IN_A_ROW = 3


@dataclass
class Pending:
    item_id: str
    type: str
    name: str
    domains: list[str]
    old_folder: str | None

    @property
    def sort_key(self) -> tuple[str, str]:
        return ((self.domains[0] if self.domains else "~"), self.name.lower())

    def payload(self) -> dict[str, Any]:
        return llm_payload(self.item_id, self.type, self.name, self.domains, self.old_folder)


@dataclass
class Decision:
    item_id: str
    category: str
    confidence: float | None
    source: str
    suggested: str | None = None


@dataclass
class ClassifyReport:
    by_rule: int = 0
    by_llm: int = 0
    low_confidence: int = 0
    fallback: int = 0
    batches: int = 0
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def load_pending(conn: sqlite3.Connection, account_id: str) -> list[Pending]:
    rows = db.items_with_status(conn, account_id, "new")
    items = [
        Pending(r["item_id"], r["type"], r["name"], json.loads(r["domains"]), r["current_folder_name"]) for r in rows
    ]
    return sorted(items, key=lambda p: p.sort_key)


def rule_category(item: Pending, names: set[str]) -> str | None:
    fixed = cat.TYPE_CATEGORIES.get(item.type)
    return fixed if fixed and fixed in names else None


def system_prompt(categories: list[cat.Category]) -> str:
    lines = []
    for c in categories:
        if c.name == cat.UNSORTED:
            continue
        line = f"- {c.name}: {c.description}" if c.description else f"- {c.name}"
        if c.examples:
            line += f" (e.g. {', '.join(c.examples[:6])})"
        lines.append(line)
    folders = "\n".join(lines)
    return f"""You sort the items of one person's password manager (Bitwarden) into folders.

Folders:
{folders}
- {cat.UNSORTED}: only when none of the folders above fits at all.

Each input item has: id, type (login, secure_note, card, identity, ssh_key), name, domains (websites; may be empty),
and optionally old_folder (the user's previous folder; a hint, not a rule).

For EVERY input item return exactly one result with:
- id: copied from the input,
- category: exactly one folder name from the list above,
- confidence: high (clearly belongs), medium (probably), low (a guess).
Decide by what the service is used for, judging from the domain and the name.
Items of the same service belong in the same folder."""


def response_schema(ids: list[str], names: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "enum": ids},
                        "category": {"type": "string", "enum": names},
                        "confidence": {"type": "string", "enum": list(CONFIDENCE)},
                    },
                    "required": ["id", "category", "confidence"],
                },
            }
        },
        "required": ["results"],
    }


def parse_results(
    raw: dict[str, Any], batch: list[Pending], names: set[str], min_conf: float
) -> tuple[list[Decision], list[Pending]]:
    """Validate the model's answer. Returns (decisions, items it failed to answer)."""
    by_id = {p.item_id: p for p in batch}
    decisions: dict[str, Decision] = {}
    for r in raw.get("results") or []:
        item_id = str(r.get("id", ""))
        category = str(r.get("category", ""))
        conf = CONFIDENCE.get(str(r.get("confidence", "")).lower())
        if item_id not in by_id or item_id in decisions or category not in names or conf is None:
            continue
        if category != cat.UNSORTED and conf < min_conf:
            decisions[item_id] = Decision(item_id, cat.UNSORTED, conf, "llm", suggested=category)
        else:
            decisions[item_id] = Decision(item_id, category, conf, "llm")
    missing = [p for p in batch if p.item_id not in decisions]
    return list(decisions.values()), missing


def chunks(items: list[Pending], size: int) -> Iterator[list[Pending]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def classify(
    conn: sqlite3.Connection,
    account_id: str,
    llm: OllamaClient,
    categories: list[cat.Category],
    *,
    batch_size: int = 20,
    min_confidence: str = "medium",
    limit: int | None = None,
    think: bool = False,
    on_batch: Callable[[int, int, float], None] | None = None,
) -> ClassifyReport:
    """Classify pending items; every batch is committed, so an interrupted run resumes where it stopped."""
    rep = ClassifyReport()
    names = [c.name for c in categories]
    name_set = set(names)
    if cat.UNSORTED not in name_set:
        raise ValueError(f"The category list must contain {cat.UNSORTED!r}")
    min_conf = CONFIDENCE[min_confidence]

    pending = load_pending(conn, account_id)
    if limit:
        pending = pending[:limit]

    def save(d: Decision) -> None:
        db.set_category(conn, account_id, d.item_id, d.category, d.confidence, d.source, d.suggested)

    for_llm: list[Pending] = []
    for p in pending:
        fixed = rule_category(p, name_set)
        if fixed:
            save(Decision(p.item_id, fixed, 1.0, "rule"))
            rep.by_rule += 1
        else:
            for_llm.append(p)

    sys_prompt = system_prompt(categories)
    done = rep.by_rule
    failures_in_a_row = 0
    for batch in chunks(for_llm, batch_size):
        answer = _ask(llm, sys_prompt, batch, names, name_set, min_conf, think, rep)
        if answer is None:
            # request failed: leave the batch as `new` so the next run retries it
            failures_in_a_row += 1
            if failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
                raise LlmError(f"{failures_in_a_row} LLM requests failed in a row; last error: {rep.errors[-1]}")
            done += len(batch)
            continue
        failures_in_a_row = 0
        decisions, missing = answer
        if missing:  # second chance: one smaller request for the items the model skipped
            retry = _ask(llm, sys_prompt, missing, names, name_set, min_conf, think, rep)
            if retry is None:
                missing = []  # stay `new`, retried next run
            else:
                decisions += retry[0]
                missing = retry[1]
        for d in decisions:
            save(d)
            rep.by_llm += 1
            rep.low_confidence += d.suggested is not None
        for p in missing:
            save(Decision(p.item_id, cat.UNSORTED, None, FALLBACK_SOURCE))
            rep.fallback += 1
        done += len(batch)
        if on_batch:
            on_batch(done, len(pending), rep.seconds)
    return rep


def _ask(
    llm: OllamaClient,
    sys_prompt: str,
    batch: list[Pending],
    names: list[str],
    name_set: set[str],
    min_conf: float,
    think: bool,
    rep: ClassifyReport,
) -> tuple[list[Decision], list[Pending]] | None:
    """One LLM request. None means the request itself failed (not that the model skipped items)."""
    user = json.dumps([p.payload() for p in batch], ensure_ascii=False, indent=1)
    schema = response_schema([p.item_id for p in batch], names)
    try:
        raw, secs = llm.chat_json(
            [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user}],
            schema,
            num_ctx=cat.estimate_num_ctx(sys_prompt + user),
            think=think,
        )
    except LlmError as exc:
        rep.errors.append(str(exc)[:200])
        return None
    rep.batches += 1
    rep.seconds += secs
    return parse_results(raw, batch, name_set, min_conf)
