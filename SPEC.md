# bwsort: specification

A Python (uv) tool that sorts ~600 Bitwarden items into new folders. A local Ollama model picks each item's category from its name and domain. Secrets never leave the `bw` CLI <-> script process pair.

## Decisions

| Topic | Decision |
|---|---|
| Server | bitwarden.com (US), `https://vault.bitwarden.com` |
| Size | ~600 items |
| First run | **all** personal items, including ones already in folders; a fresh folder set is created |
| Later runs | only items added since the last run (tracked in SQLite, see below) |
| Old folders | removed after the move once empty (`--delete-old-folders`, asks for confirmation) |
| Folder names | English, flat list, one level |
| Organization items | skipped |
| Model | `qwen3.8:27b-q4_K_M` (newest and largest installed); fallback `qwen3.6:27b`. Thinking disabled (`think: false`), temperature 0 |
| Unlock | `BW_SESSION` from the environment or `.env` (environment wins) |
| Language | all code, comments and CLI output in English |

## Security

1. **Single exit point for item data**: `sanitize.to_safe_item()` keeps only id, type, name, domains, folderId and an organization flag. Password, username, notes, TOTP, custom fields, cards, identities, passkeys and password history are dropped.
2. **URI -> registrable domain only**: `https://user:pw@secure.chase.com/reset?t=...` becomes `chase.com`; LAN IPs become `private-ip`; Android apps become `androidapp:<package>`.
3. **Item name**: e-mail local parts become `<email>@domain`; digit runs of 6+ become `<num>`.
4. **Local Ollama only**: host must be `localhost`/`127.0.0.1`/`::1`; cloud models (`*-cloud`, `remote_host`) are refused; system HTTP proxies are ignored.
5. **`bw` subprocesses**: argument lists, no shell; the session key goes through the child's environment, not argv; only stderr is ever shown in errors.
6. **On disk** (`data/`, gitignored): metadata only, no raw vault JSON.
7. **Before any change**: mandatory `bw export --format encrypted_json` backup, dry-run by default, journal and rollback.
8. **After work**: `bw lock` and clear `BW_SESSION` in `.env`.
9. **Tests**: `tests/test_sanitize.py` asserts that no secret from a sample item survives sanitization; `tests/test_db.py` covers the item lifecycle across runs.

## What the LLM receives

For each item, exactly:

```json
{"id": "<bitwarden item uuid>", "type": "login", "name": "Chase bank <email>@gmail.com", "domains": ["chase.com"], "old_folder": "Banks"}
```

The id is a random UUID, not a secret. The JSON schema of the reply restricts `id` to the ids in the current batch (enum), so the model cannot invent or mangle one; replies are validated again locally.

## State database (`data/bwsort.db`, SQLite)

Keyed by Bitwarden account (`userId` from `bw status`), so several accounts can share one DB without mixing.

| Table | Purpose |
|---|---|
| `accounts` | account id, server, first/last seen |
| `runs` | every command run: command, model, start/finish, summary |
| `items` | per item: metadata, current/original/target folder, status, category, confidence, source, timestamps, last error |
| `folders` | known folders; `created_by_bwsort` marks the ones the tool created |
| `categories` | the approved category list (= folder names) per account |
| `moves` | journal of every move (from -> to) for rollback |
| `domain_cache` | domain -> category, to skip the LLM for known domains |

Item status lifecycle:

| Status | Meaning | Next run |
|---|---|---|
| `new` | seen, not classified | classified |
| `planned` | category chosen | moved by `apply` |
| `failed` | move failed | retried by `apply` |
| `moved` | sorted by bwsort and still in its target folder | skipped |
| `manual` | you moved it after bwsort, or a new item you already placed into a bwsort folder | skipped, your choice wins |
| `skipped` | organization item | never touched |
| `gone` | deleted from the vault | ignored; back to `new` if restored |

## Stages

| # | Command | What it does | Changes vault |
|---|---|---|---|
| 0 | `bwsort check` | bw, session, server, Ollama, model, test request | no |
| 1 | `bwsort snapshot` | `bw sync`, sanitized read, merge into DB, report new vs already sorted, preview of LLM input | no |
| — | `bwsort status` | item counts per status and recent runs | no |
| 2 | `bwsort categories` | first run only: LLM gets an aggregated overview (domains with counts and 2 sample names, names of items without a website, old folders) and proposes 12-20 categories -> `data/categories.yaml`. Fixed categories are added by rule: `Payment Cards`, `Identities`, `SSH Keys` (only if such items exist) and `Unsorted`. You edit the file; `--import` validates it and stores it in the DB; `--show` prints the stored list; `--show-input` prints exactly what the LLM would get. Later runs reuse the stored list | no |
| 2b | `bwsort create-folders [--apply]` | creates one Bitwarden folder per stored category; reuses an existing folder with the same name; marks them as bwsort folders in the DB. No item is moved | yes (folders only) |
| 3 | `bwsort classify` | `new` items in batches of 20; schema with enum of categories and ids; domain cache; cards/identities/SSH keys by type without the LLM; low confidence -> `Unsorted` | no |
| 4 | `bwsort review` | table of planned moves and per-folder summary; `--export plan.csv` / `--import plan.csv` for manual edits | no |
| 5 | `bwsort apply [--apply] [--delete-old-folders]` | backup, create folders, move (`bw get item` -> new `folderId` -> `bw encode \| bw edit item`), record in DB | yes |
| 6 | `bwsort rollback [--run N]` | restore previous folders from the `moves` journal | yes |

## Risks to verify before a bulk `apply`

- The `bw edit` round trip rewrites the whole item. Test on 1-2 items first that passkeys (fido2), password history, attachments and custom fields survive.
- Python cannot reliably wipe decrypted data from memory before the process exits. Accepted for a local run.
