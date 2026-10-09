"""Settings loaded from the environment and the project's .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ConfigError(RuntimeError):
    pass


def assert_local_url(url: str) -> None:
    """Refuse anything that isn't a loopback HTTP endpoint."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ConfigError(f"Ollama URL must be http(s), got: {url!r}")
    if (parts.hostname or "").lower() not in LOCAL_HOSTS:
        raise ConfigError(
            f"Ollama URL must point to this machine (localhost/127.0.0.1/::1), got host {parts.hostname!r}. "
            "Refusing to send vault metadata over the network."
        )


def assert_local_model_name(model: str) -> None:
    """Ollama 'cloud' models are proxied to ollama.com; never use them here."""
    tag = model.split(":", 1)[1] if ":" in model else ""
    if "cloud" in tag.lower() or model.lower().endswith("-cloud"):
        raise ConfigError(f"Model {model!r} looks like an Ollama cloud model; only local models are allowed.")


@dataclass(frozen=True)
class Settings:
    ollama_url: str
    model: str
    batch_size: int
    bw_bin: str | None
    data_dir: Path
    env_file: Path | None
    # repr=False so the key never shows up in tracebacks or debug prints
    bw_session: str | None = field(default=None, repr=False)


def load_settings(project_dir: Path | None = None) -> Settings:
    project_dir = project_dir or Path.cwd()
    env_path = project_dir / ".env"
    found = env_path if env_path.is_file() else None
    if found:
        # override=False: a real environment variable wins over .env
        load_dotenv(found, override=False, encoding="utf-8")

    ollama_url = os.environ.get("BWSORT_OLLAMA_URL", "http://127.0.0.1:11434").strip()
    model = os.environ.get("BWSORT_MODEL", "qwen3.8:27b-q4_K_M").strip()
    assert_local_url(ollama_url)
    assert_local_model_name(model)

    try:
        batch_size = int(os.environ.get("BWSORT_BATCH_SIZE", "20"))
    except ValueError as exc:
        raise ConfigError("BWSORT_BATCH_SIZE must be an integer") from exc

    session = (os.environ.get("BW_SESSION") or "").strip() or None
    bw_bin = (os.environ.get("BW_BIN") or "").strip() or None

    return Settings(
        ollama_url=ollama_url.rstrip("/"),
        model=model,
        batch_size=max(1, batch_size),
        bw_bin=bw_bin,
        data_dir=project_dir / "data",
        env_file=found,
        bw_session=session,
    )
