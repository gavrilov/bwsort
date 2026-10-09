"""The single choke point between raw vault items and everything else.

`to_safe_item` reads an explicit allowlist of fields from a decrypted bw item and
returns a SafeItem. Nothing else in the program ever sees the raw item, so
passwords, usernames, notes, TOTP seeds, custom fields, card numbers, identity
data, passkeys and full URLs cannot reach disk, logs or the LLM.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import tldextract
from pydantic import BaseModel, ConfigDict

ITEM_TYPES = {1: "login", 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key"}

# Offline extractor: bundled public-suffix snapshot, no download, no disk cache.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_EMAIL_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_LONG_NUM_RE = re.compile(r"\d{6,}")
_MAX_NAME = 120
_MAX_DOMAINS = 5


class SafeItem(BaseModel):
    """Metadata that is safe to store locally and to show to the local LLM."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    type: str
    name: str
    domains: list[str]
    folder_id: str | None
    in_organization: bool

    def llm_view(self, old_folder: str | None) -> dict[str, Any]:
        """Exactly what gets sent to Ollama for this item."""
        return llm_payload(self.id, self.type, self.name, self.domains, old_folder)


def llm_payload(
    item_id: str, type_: str, name: str, domains: list[str], old_folder: str | None
) -> dict[str, Any]:
    """The only shape of item data the LLM ever receives.

    The Bitwarden item id is a random UUID, not a secret; the model echoes it back
    so answers map to items unambiguously (enforced by a JSON-schema enum).
    """
    view: dict[str, Any] = {"id": item_id, "type": type_, "name": name, "domains": domains}
    if old_folder:
        view["old_folder"] = old_folder
    return view


def redact_name(name: str) -> str:
    """Hide e-mail local parts and long digit runs (account/phone/card numbers)."""
    name = _EMAIL_RE.sub(r"<email>@\1", name or "")
    name = _LONG_NUM_RE.sub("<num>", name)
    name = " ".join(name.split())
    return name[:_MAX_NAME]


def domain_from_uri(uri: str | None) -> str | None:
    """Reduce a URI to its registrable domain; drop scheme, userinfo, port, path, query."""
    if not uri:
        return None
    uri = uri.strip()
    if not uri:
        return None

    lowered = uri.lower()
    for scheme in ("androidapp://", "iosapp://"):
        if lowered.startswith(scheme):
            app = uri[len(scheme):].split("/", 1)[0].split("?", 1)[0]
            return f"{scheme[:-3]}:{app.lower()}" if app else None

    if "://" not in uri:
        uri = "https://" + uri
    try:
        host = urlsplit(uri).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "private-ip" if (ip.is_private or ip.is_loopback or ip.is_link_local) else "public-ip"

    if "." not in host:
        return "local-host"

    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    if ext.suffix:  # host is itself a public suffix, e.g. "github.io"
        return ext.suffix
    return host


def to_safe_item(raw: dict[str, Any]) -> SafeItem:
    """Allowlist projection of one decrypted bw item. Do not add fields here lightly."""
    type_name = ITEM_TYPES.get(raw.get("type"), "unknown")

    domains: list[str] = []
    login = raw.get("login") or {}
    for entry in login.get("uris") or []:
        d = domain_from_uri((entry or {}).get("uri"))
        if d and d not in domains:
            domains.append(d)
        if len(domains) >= _MAX_DOMAINS:
            break

    return SafeItem(
        id=str(raw["id"]),
        type=type_name,
        name=redact_name(str(raw.get("name") or "")),
        domains=domains,
        folder_id=raw.get("folderId"),
        in_organization=bool(raw.get("organizationId")),
    )
