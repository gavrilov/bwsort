"""bwsort command line. Read-only stages so far: `check`, `snapshot`, `status`."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import categories as cat
from . import classify as clf
from . import db
from . import review as rv
from .bw import BwClient, BwError
from .config import ConfigError, Settings, load_settings
from .llm import LlmError, OllamaClient
from .sanitize import SafeItem, llm_payload

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Sort Bitwarden items into folders with a local LLM.")
console = Console()

DB_FILE = "bwsort.db"
DEFAULT_SERVER = "https://vault.bitwarden.com"


def _settings() -> Settings:
    try:
        return load_settings()
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/] {exc}")
        raise typer.Exit(2)


def _require_unlocked(bw: BwClient) -> dict:
    st = bw.status()
    if st.get("status") != "unlocked" or not st.get("userId"):
        console.print(
            f"[red]Vault is not unlocked[/] (status={st.get('status')}).\n"
            "PowerShell:  [bold]$env:BW_SESSION = bw unlock --raw[/]\n"
            "or paste the output of `bw unlock --raw` into the BW_SESSION= line in .env"
        )
        raise typer.Exit(1)
    return st


def _open_db(s: Settings):
    return db.connect(s.data_dir / DB_FILE)


@app.command()
def check() -> None:
    """Stage 0: verify bw, the session and the local Ollama. Changes nothing."""
    s = _settings()
    ok = True
    t = Table(title="bwsort check")
    t.add_column("Check")
    t.add_column("Result")

    t.add_row(".env", str(s.env_file) if s.env_file else "[yellow]not found (using environment variables)[/]")
    t.add_row("BW_SESSION", "[green]set[/]" if s.bw_session else "[red]empty[/]")
    ok &= bool(s.bw_session)

    # Bitwarden
    try:
        bw = BwClient(s.bw_session, s.bw_bin)
        t.add_row("bw CLI", f"{bw.version()}  ({bw.bin})")
        st = bw.status()
        server = st.get("serverUrl") or DEFAULT_SERVER
        status = st.get("status")
        t.add_row("Server", server)
        t.add_row("Vault status", f"[green]{status}[/]" if status == "unlocked" else f"[red]{status}[/]")
        ok &= status == "unlocked"
        if server.rstrip("/") not in {DEFAULT_SERVER, "https://bitwarden.com"}:
            t.add_row("", "[yellow]server is not bitwarden.com (US); make sure this is expected[/]")
    except BwError as exc:
        t.add_row("bw CLI", f"[red]{exc}[/]")
        ok = False

    # Ollama
    llm = None
    try:
        llm = OllamaClient(s.ollama_url, s.model)
        t.add_row("Ollama", f"{s.ollama_url}  v{llm.version()}  [green](local)[/]")
        info = llm.ensure_model_is_local()
        size_gb = (info.get("size") or 0) / 1e9
        t.add_row("Model", f"{s.model}  {size_gb:.1f} GB  [green]local[/]")
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
        result, secs = llm.chat_json([{"role": "user", "content": 'Return JSON {"ok": true}.'}], schema)
        t.add_row("Test request", f"{result} in {secs:.1f}s (first call includes model load)")
        ok &= result.get("ok") is True
    except (LlmError, ConfigError) as exc:
        t.add_row("Ollama", f"[red]{exc}[/]")
        ok = False
    except Exception as exc:  # connection refused etc.
        t.add_row("Ollama", f"[red]unreachable: {type(exc).__name__}: {exc}[/]")
        ok = False
    finally:
        if llm:
            llm.close()

    console.print(t)
    if not ok:
        console.print("[red]Some checks failed, see the table above.[/]")
        raise typer.Exit(1)
    console.print("[green]All good, ready for `snapshot`.[/]")


@app.command()
def snapshot(
    sync: bool = typer.Option(True, help="Run `bw sync` first."),
    preview: int = typer.Option(8, help="How many pending items to show exactly as the LLM will see them."),
) -> None:
    """Stage 1: read the vault (no secrets kept) and merge it into data/bwsort.db."""
    s = _settings()
    try:
        bw = BwClient(s.bw_session, s.bw_bin)
        st = _require_unlocked(bw)
        if sync:
            with console.status("bw sync..."):
                bw.sync()
        with console.status("Reading folders and items..."):
            folders = bw.list_folders()
            items = bw.list_safe_items()
    except BwError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)

    account_id = st["userId"]
    conn = _open_db(s)
    try:
        db.ensure_account(conn, account_id, st.get("serverUrl") or DEFAULT_SERVER)
        run_id = db.start_run(conn, account_id, "snapshot")
        rep = db.sync_snapshot(conn, account_id, items, folders)
        db.finish_run(conn, run_id, asdict(rep))

        _print_vault_stats(items, folders)
        _print_sync_report(rep)
        _print_preview(conn, account_id, preview)
    finally:
        conn.close()

    console.print(f"\n[green]State saved:[/] {s.data_dir / DB_FILE}")
    console.print("[dim]The database holds only id, type, redacted name, domains and folder ids. No passwords, usernames or notes.[/]")


@app.command()
def status() -> None:
    """Show per-status item counts and recent runs from the local database."""
    s = _settings()
    conn = _open_db(s)
    try:
        accounts = conn.execute("SELECT account_id, server_url, last_seen FROM accounts ORDER BY last_seen DESC").fetchall()
        if not accounts:
            console.print("Database is empty. Run `bwsort snapshot` first.")
            return
        for acc in accounts:
            counts = db.status_counts(conn, acc["account_id"])
            t = Table(title=f"Account {acc['account_id'][:8]}...  ({acc['server_url']})")
            t.add_column("Status")
            t.add_column("Items", justify="right")
            t.add_column("Meaning")
            for st_name, meaning in STATUS_HELP.items():
                t.add_row(st_name, str(counts.get(st_name, 0)), meaning)
            console.print(t)

            runs = conn.execute(
                "SELECT run_id, command, started_at, finished_at FROM runs WHERE account_id=? ORDER BY run_id DESC LIMIT 5",
                (acc["account_id"],),
            ).fetchall()
            rt = Table(title="Recent runs")
            for col in ("#", "Command", "Started (UTC)", "Finished"):
                rt.add_column(col)
            for r in runs:
                rt.add_row(str(r["run_id"]), r["command"], r["started_at"], r["finished_at"] or "[yellow]interrupted[/]")
            console.print(rt)
    finally:
        conn.close()


STATUS_HELP = {
    "new": "not classified yet -> classify",
    "planned": "category chosen -> apply",
    "failed": "move failed -> apply will retry",
    "moved": "sorted by bwsort, skipped on re-runs",
    "manual": "placed by you, never overridden",
    "skipped": "organization item, never touched",
    "gone": "deleted from the vault",
}


def _print_vault_stats(items: list[SafeItem], folders: list[dict]) -> None:
    by_type = Counter(i.type for i in items)
    no_folder = sum(1 for i in items if not i.folder_id)
    no_domain = sum(1 for i in items if not i.domains)
    domains = Counter(d for i in items for d in i.domains)

    t = Table(title="Vault")
    t.add_column("Metric")
    t.add_column("Value", justify="right")
    for k, v in by_type.most_common():
        t.add_row(f"type: {k}", str(v))
    t.add_row("without folder", str(no_folder))
    t.add_row("in folders", str(len(items) - no_folder))
    t.add_row("existing folders", str(len(folders)))
    t.add_row("in organizations (skipped)", str(sum(i.in_organization for i in items)))
    t.add_row("without domain (name only)", str(no_domain))
    t.add_row("unique domains", str(len(domains)))
    console.print(t)

    top = Table(title="Top 15 domains")
    top.add_column("Domain")
    top.add_column("Items", justify="right")
    for d, n in domains.most_common(15):
        top.add_row(d, str(n))
    console.print(top)


def _print_sync_report(rep: db.SyncReport) -> None:
    t = Table(title="Compared with previous runs")
    t.add_column("")
    t.add_column("Items", justify="right")
    t.add_row("new since last run", str(rep.new))
    t.add_row("restored from trash", str(rep.restored))
    t.add_row("already sorted, unchanged (skip)", str(rep.already_moved))
    t.add_row("sorted earlier, moved by you since (skip)", str(rep.became_manual))
    t.add_row("new but already in a bwsort folder (skip)", str(rep.new_but_manual))
    t.add_row("organization items (skip)", str(rep.skipped_org))
    t.add_row("deleted from vault", str(rep.gone))
    console.print(t)
    p = rep.pending
    console.print(
        f"[bold]To process:[/] {p.get('new', 0)} to classify, "
        f"{p.get('planned', 0) + p.get('failed', 0)} waiting to be moved."
    )


def _print_preview(conn, account_id: str, n: int) -> None:
    if n <= 0:
        return
    rows = db.items_with_status(conn, account_id, "new")[:n]
    if not rows:
        return
    console.print(f"\n[bold]What the LLM will receive[/] (first {len(rows)} pending items):")
    for r in rows:
        view = llm_payload(r["item_id"], r["type"], r["name"], json.loads(r["domains"]), r["current_folder_name"])
        console.print_json(json.dumps(view, ensure_ascii=False))


CATEGORIES_FILE = "categories.yaml"


def _pick_account(conn, prefix: str | None) -> str:
    rows = conn.execute("SELECT account_id FROM accounts ORDER BY last_seen DESC").fetchall()
    ids = [r[0] for r in rows if not prefix or r[0].startswith(prefix)]
    if not ids:
        console.print("[red]No matching account in the database.[/] Run `bwsort snapshot` first.")
        raise typer.Exit(1)
    if len(ids) > 1 and not prefix:
        console.print(f"[yellow]Several accounts in the DB; using the most recent one ({ids[0][:8]}...). Use --account to pick another.[/]")
    return ids[0]


def _categories_table(title: str, cats: list[cat.Category], show_examples: bool = True) -> Table:
    t = Table(title=title, show_lines=False)
    t.add_column("#", justify="right")
    t.add_column("Folder", style="bold")
    t.add_column("Description")
    if show_examples:
        t.add_column("Examples", style="dim")
    for i, c in enumerate(cats, 1):
        name = f"{c.name} [dim](fixed)[/]" if c.fixed else c.name
        row = [str(i), name, c.description]
        if show_examples:
            row.append(", ".join(c.examples))
        t.add_row(*row)
    return t


@app.command()
def categories(
    import_: bool = typer.Option(False, "--import", help="Validate data/categories.yaml and store it as the category list."),
    show: bool = typer.Option(False, "--show", help="Show the stored category list."),
    show_input: bool = typer.Option(False, "--show-input", help="Print exactly what would be sent to the LLM and stop."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing data/categories.yaml."),
    think: bool = typer.Option(False, "--think", help="Let the model reason before answering (slower)."),
    account: str | None = typer.Option(None, help="Account id prefix, if the DB holds several accounts."),
) -> None:
    """Stage 2: propose folder categories with the LLM, then import your edited list."""
    s = _settings()
    path = s.data_dir / CATEGORIES_FILE
    conn = _open_db(s)
    try:
        account_id = _pick_account(conn, account)

        if show:
            stored = cat.load_stored(conn, account_id)
            if not stored:
                console.print("No stored categories yet. Run `bwsort categories`, edit the file, then `--import`.")
                return
            console.print(_categories_table("Stored categories", stored, show_examples=False))
            return

        if import_:
            try:
                cats = cat.load_yaml(path)
            except FileNotFoundError:
                console.print(f"[red]{path} not found.[/] Run `bwsort categories` first.")
                raise typer.Exit(1)
            except cat.CategoryError as exc:
                console.print(f"[red]{exc}[/]")
                raise typer.Exit(1)
            run_id = db.start_run(conn, account_id, "categories --import")
            cat.store(conn, account_id, cats)
            db.finish_run(conn, run_id, {"categories": [c.name for c in cats]})
            console.print(_categories_table(f"Imported {len(cats)} categories", cats))
            console.print("\nNext: [bold]uv run bwsort create-folders[/] (dry run), then add --apply to create them in Bitwarden.")
            return

        ov = cat.build_overview(conn, account_id)
        if ov.total == 0:
            console.print("[red]No items in the database.[/] Run `bwsort snapshot` first.")
            raise typer.Exit(1)
        prompt = cat.overview_text(ov)
        if show_input:
            console.print("[bold]System prompt:[/]")
            console.print(cat.SYSTEM_PROMPT, markup=False, highlight=False)
            console.print("[bold]User message:[/]")
            console.print(prompt, markup=False, highlight=False)
            return
        if path.exists() and not force:
            console.print(
                f"[yellow]{path} already exists.[/] Edit it and run `bwsort categories --import`, "
                "or use --force to generate a new proposal (overwrites your edits)."
            )
            raise typer.Exit(1)

        num_ctx = cat.estimate_num_ctx(cat.SYSTEM_PROMPT + prompt)
        console.print(
            f"Overview: {ov.total} items, {len(ov.domains)} domains, {len(ov.nameless)} names without a website, "
            f"{len(ov.old_folders)} old folders; ~{len(prompt) // 3} tokens, num_ctx={num_ctx}."
        )
        if ov.truncated:
            console.print("[yellow]Overview was truncated to the most common domains/names to fit the context.[/]")

        llm = OllamaClient(s.ollama_url, s.model)
        run_id = db.start_run(conn, account_id, "categories", s.model)
        try:
            llm.ensure_model_is_local()
            messages = [{"role": "system", "content": cat.SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
            proposed: list[cat.Category] = []
            for attempt in (1, 2):
                with console.status(f"Asking {s.model} for categories (attempt {attempt})..."):
                    raw, secs = llm.chat_json(
                        messages, cat.RESPONSE_SCHEMA, num_ctx=num_ctx, think=think,
                        temperature=0.0 if attempt == 1 else 0.4,
                    )
                proposed = cat.normalize_llm_categories(raw, ov)
                console.print(f"Model answered in {secs:.0f}s with {len(proposed)} usable categories.")
                if len(proposed) >= cat.MIN_LLM_CATEGORIES:
                    break
            if len(proposed) < cat.MIN_LLM_CATEGORIES:
                console.print("[red]The model did not return a usable list.[/] Try --think or another model (BWSORT_MODEL).")
                raise typer.Exit(1)
        except LlmError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(1)
        finally:
            llm.close()

        final = cat.with_fixed(proposed, ov.type_counts)
        cat.save_yaml(path, account_id, final)
        db.finish_run(conn, run_id, {"proposed": [c.name for c in final]})
        console.print(_categories_table("Proposed categories", final))
        console.print(
            f"\nSaved to [bold]{path}[/]. Edit it (rename, merge, delete, add), then run:\n"
            "  [bold]uv run bwsort categories --import[/]"
        )
    finally:
        conn.close()


@app.command("create-folders")
def create_folders(
    apply: bool = typer.Option(False, "--apply", help="Actually create the folders. Without it: dry run."),
) -> None:
    """Create a Bitwarden folder for every stored category (reuses folders with the same name)."""
    s = _settings()
    try:
        bw = BwClient(s.bw_session, s.bw_bin)
        st = _require_unlocked(bw)
        live = bw.list_folders()
    except BwError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)

    account_id = st["userId"]
    conn = _open_db(s)
    try:
        cats = cat.load_stored(conn, account_id)
        if not cats:
            console.print("[red]No stored categories for this account.[/] Run `bwsort categories` and `--import` first.")
            raise typer.Exit(1)

        plan = cat.folder_plan(cats, live)
        t = Table(title="Folders" + ("" if apply else " (dry run)"))
        t.add_column("Folder", style="bold")
        t.add_column("Action")
        run_id = db.start_run(conn, account_id, "create-folders" + (" --apply" if apply else "")) if apply else None
        created = reused = 0
        for c, folder_id in plan:
            if folder_id:
                if apply:
                    db.register_bwsort_folder(conn, account_id, folder_id, c.name)
                reused += 1
                t.add_row(c.name, "exists, reused")
                continue
            if not apply:
                t.add_row(c.name, "[cyan]will be created[/]")
                continue
            try:
                folder = bw.create_folder(c.name)
                db.register_bwsort_folder(conn, account_id, folder["id"], c.name)
                created += 1
                t.add_row(c.name, "[green]created[/]")
            except BwError as exc:
                t.add_row(c.name, f"[red]failed: {exc}[/]")
        console.print(t)
        if apply:
            db.finish_run(conn, run_id, {"created": created, "reused": reused})
            console.print(f"[green]Done:[/] {created} created, {reused} reused. Items have not been moved yet.")
        else:
            todo = sum(1 for _, fid in plan if not fid)
            console.print(f"Dry run: {todo} to create, {reused} already exist. Re-run with [bold]--apply[/].")
    finally:
        conn.close()

class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


@app.command()
def classify(
    limit: int | None = typer.Option(None, help="Classify at most N items (try a small run first)."),
    min_confidence: Confidence = typer.Option(Confidence.medium, help="Below this the item goes to Unsorted."),
    reclassify: bool = typer.Option(False, "--reclassify", help="Classify already planned items again (keeps your CSV edits)."),
    think: bool = typer.Option(False, "--think", help="Let the model reason before answering (much slower)."),
    account: str | None = typer.Option(None, help="Account id prefix, if the DB holds several accounts."),
) -> None:
    """Stage 3: pick a folder for every `new` item. Changes only the local DB, not the vault."""
    s = _settings()
    conn = _open_db(s)
    try:
        account_id = _pick_account(conn, account)
        cats = cat.load_stored(conn, account_id)
        if not cats:
            console.print("[red]No stored categories.[/] Run `bwsort categories` and `--import` first.")
            raise typer.Exit(1)
        if cat.UNSORTED not in {c.name for c in cats}:
            console.print(f"[red]The category list must contain {cat.UNSORTED!r}.[/] Fix categories.yaml and re-import.")
            raise typer.Exit(1)
        if reclassify:
            n = db.reset_planned(conn, account_id)
            console.print(f"{n} planned items reset to `new`.")

        pending = len(db.items_with_status(conn, account_id, "new"))
        total = min(pending, limit) if limit else pending
        if total == 0:
            console.print("Nothing to classify: no `new` items. Run `bwsort snapshot` to pick up new ones.")
            return
        if not any(c.examples for c in cats):
            console.print("[yellow]Stored categories have no examples. Re-run `bwsort categories --import` to include them (better accuracy).[/]")
        console.print(f"Classifying {total} items with {s.model}, batches of {s.batch_size}, min confidence: {min_confidence.value}.")

        llm = OllamaClient(s.ollama_url, s.model)
        run_id = db.start_run(conn, account_id, "classify", s.model)
        try:
            llm.ensure_model_is_local()
            with Progress(
                TextColumn("[bold]Classifying"), BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                TextColumn("{task.fields[info]}"), console=console,
            ) as progress:
                task = progress.add_task("classify", total=total, info="")

                def on_batch(done: int, _total: int, secs: float) -> None:
                    progress.update(task, completed=done, info=f"LLM time {secs:.0f}s")

                rep = clf.classify(
                    conn, account_id, llm, cats,
                    batch_size=s.batch_size, min_confidence=min_confidence.value,
                    limit=limit, think=think, on_batch=on_batch,
                )
        except LlmError as exc:
            console.print(f"[red]{exc}[/]\nProgress so far is saved; run `bwsort classify` again to continue.")
            raise typer.Exit(1)
        except KeyboardInterrupt:
            console.print("[yellow]Interrupted. Finished batches are saved; run `bwsort classify` again to continue.[/]")
            raise typer.Exit(130)
        finally:
            llm.close()

        db.finish_run(conn, run_id, {k: v for k, v in rep.__dict__.items() if k != "errors"} | {"errors": len(rep.errors)})
        console.print(
            f"Done: {rep.by_llm} by the LLM ({rep.batches} requests, {rep.seconds:.0f}s), {rep.by_rule} by item type, "
            f"{rep.low_confidence} low-confidence -> {cat.UNSORTED}, {rep.fallback} unanswered -> {cat.UNSORTED}."
        )
        if rep.errors:
            console.print(f"[yellow]{len(rep.errors)} failed requests; those items stay `new` and will be retried. Last: {rep.errors[-1]}[/]")
        _print_summary(conn, account_id)
        console.print("\nNext: [bold]uv run bwsort review[/] to inspect, [bold]--export[/] / [bold]--import[/] a CSV to correct.")
    finally:
        conn.close()


def _print_summary(conn, account_id: str) -> None:
    rows = rv.summary(conn, account_id)
    t = Table(title="Planned folders (nothing moved yet)")
    for col, just in (("Folder", "left"), ("Items", "right"), ("High", "right"), ("Medium", "right"),
                      ("By type", "right"), ("Your edits", "right"), ("Low -> Unsorted", "right"), ("Unanswered", "right")):
        t.add_column(col, justify=just)
    for r in rows:
        t.add_row(r["category"] or "-", str(r["items"]), str(r["high"] or 0), str(r["medium"] or 0),
                  str(r["by_rule"] or 0), str(r["by_user"] or 0), str(r["low_moved_to_unsorted"] or 0),
                  str(r["unanswered"] or 0))
    console.print(t)


@app.command()
def review(
    folder: str | None = typer.Option(None, help="List the items planned for this folder."),
    export: Path | None = typer.Option(None, "--export", help="Write all planned items to a CSV you can edit."),
    import_: Path | None = typer.Option(None, "--import", help="Apply the edited `category` column of a CSV."),
    account: str | None = typer.Option(None, help="Account id prefix, if the DB holds several accounts."),
) -> None:
    """Stage 4: inspect the plan and correct it. Changes only the local DB."""
    s = _settings()
    conn = _open_db(s)
    try:
        account_id = _pick_account(conn, account)
        if export:
            n = rv.export_csv(conn, account_id, export)
            console.print(f"Wrote {n} items to [bold]{export}[/]. Edit the `category` column, then: bwsort review --import {export}")
            return
        if import_:
            names = [c.name for c in cat.load_stored(conn, account_id)]
            changed, errors = rv.import_csv(conn, account_id, import_, names)
            for e in errors[:20]:
                console.print(f"[yellow]{e}[/]")
            if len(errors) > 20:
                console.print(f"[yellow]... and {len(errors) - 20} more[/]")
            console.print(f"[green]{changed} items updated.[/]")
            _print_summary(conn, account_id)
            return
        if folder:
            rows = rv.planned_items(conn, account_id, folder)
            t = Table(title=f"{folder}: {len(rows)} items")
            for col in ("Name", "Domains", "Old folder", "Confidence", "Source", "Model suggested"):
                t.add_column(col)
            for r in rows:
                conf = "" if r["confidence"] is None else f"{r['confidence']:.1f}"
                t.add_row(r["name"], " ".join(json.loads(r["domains"])), r["current_folder_name"] or "",
                          conf, r["category_source"] or "", r["suggested_category"] or "")
            console.print(t)
            return
        _print_summary(conn, account_id)
        console.print("Use --folder NAME to list items, --export plan.csv to edit in Excel.")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
