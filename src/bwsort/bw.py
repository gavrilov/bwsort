"""Thin wrapper around the official Bitwarden CLI (`bw`).

Rules:
- argument lists only, never shell=True;
- the session key goes to the child process via its environment, never argv;
- stdout of commands that return secrets is never logged or put into exceptions;
- raw items are converted to SafeItem immediately (see sanitize.py).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from typing import Any

from .sanitize import SafeItem, to_safe_item


class BwError(RuntimeError):
    pass


class BwClient:
    def __init__(self, session: str | None, bin_path: str | None = None, timeout: int = 300):
        path = bin_path or shutil.which("bw")
        if not path:
            raise BwError(
                "Bitwarden CLI (bw) not found. Install it with `winget install Bitwarden.CLI` "
                "or set BW_BIN in .env to the full path of bw.exe."
            )
        self.bin = path
        self._session = session
        self._timeout = timeout

    def _run(self, *args: str, stdin: str | None = None, needs_session: bool = True) -> str:
        env = os.environ.copy()
        env.pop("BW_SESSION", None)
        if needs_session and self._session:
            env["BW_SESSION"] = self._session
        try:
            proc = subprocess.run(
                [self.bin, *args, "--nointeraction"],
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            raise BwError(f"`bw {args[0]}` timed out after {self._timeout}s") from None
        if proc.returncode != 0:
            # stderr only; stdout may contain vault data
            msg = (proc.stderr or "").strip().splitlines()
            raise BwError(f"`bw {args[0]}` failed: {msg[-1] if msg else 'exit code ' + str(proc.returncode)}")
        return proc.stdout

    # --- read-only --------------------------------------------------------

    def version(self) -> str:
        return self._run("--version", needs_session=False).strip()

    def status(self) -> dict[str, Any]:
        return json.loads(self._run("status"))

    def sync(self) -> None:
        self._run("sync")

    def list_folders(self) -> list[dict[str, Any]]:
        folders = json.loads(self._run("list", "folders"))
        # Keep only id/name; "No Folder" pseudo-entry has id None
        return [{"id": f.get("id"), "name": f.get("name")} for f in folders if f.get("id")]

    # --- writes (folders only; no secrets involved) ------------------------

    def create_folder(self, name: str) -> dict[str, Any]:
        encoded = base64.b64encode(json.dumps({"name": name}).encode("utf-8")).decode("ascii")
        folder = json.loads(self._run("create", "folder", encoded))
        return {"id": folder.get("id"), "name": folder.get("name")}

    # --- items --------------------------------------------------------------

    def list_safe_items(self) -> list[SafeItem]:
        """Fetch all items and immediately reduce them to SafeItem.

        The raw JSON (which includes every secret) lives only in local variables
        of this function and is dropped before returning.
        """
        raw_text = self._run("list", "items")
        raw_items = json.loads(raw_text)
        del raw_text
        try:
            return [to_safe_item(r) for r in raw_items if not r.get("deletedDate")]
        finally:
            raw_items.clear()
            del raw_items
