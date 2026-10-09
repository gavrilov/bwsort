# bwsort

Sorts Bitwarden items into folders using a local Ollama model. Passwords never reach the model. Re-runs only process items added since the last run. Details: [SPEC.md](SPEC.md).

## Quick start (Windows, PowerShell)

```powershell
cd C:\Users\konst\Desktop\projects\bitwarden_sort

# 1. Once: Bitwarden CLI and login
winget install Bitwarden.CLI
bw login

# 2. Config
Copy-Item .env.example .env

# 3. Unlock. Option A, nothing written to disk (recommended):
$env:BW_SESSION = bw unlock --raw
#    Option B: paste the output of `bw unlock --raw` into the BW_SESSION= line in .env

# 4. Dependencies and tests
uv sync
uv run pytest -q

# 5. Read-only stages
uv run bwsort check
uv run bwsort snapshot
uv run bwsort status

# 6. Categories (stage 2)
uv run bwsort categories            # LLM proposal -> data/categories.yaml
notepad data\categories.yaml        # edit the list
uv run bwsort categories --import   # store it
uv run bwsort create-folders        # dry run
uv run bwsort create-folders --apply

# 7. Classification (stage 3) and review (stage 4): local DB only, vault untouched
uv run bwsort classify --limit 40     # trial run
uv run bwsort review --folder Unsorted
uv run bwsort classify                # the rest
uv run bwsort review                  # summary per folder
uv run bwsort review --export data\plan.csv
uv run bwsort review --import data\plan.csv

# 8. Move (stage 5) - changes the vault
uv run bwsort apply                          # dry run
uv run bwsort apply --apply --limit 2        # backup + 2 items, check them in Bitwarden
uv run bwsort apply --apply                  # the rest
uv run bwsort apply --apply --delete-old-folders
uv run bwsort rollback                       # dry run of undoing the last apply run

# When finished
bw lock
```

State lives in `data/bwsort.db` (SQLite, metadata only). Delete the `data/` folder to start from scratch.
