import json

import pytest

from bwsort.config import ConfigError, assert_local_model_name, assert_local_url
from bwsort.sanitize import domain_from_uri, redact_name, to_safe_item

SECRETS = [
    "hunter2-SUPER-secret",
    "JBSWY3DPEHPK3PXP",
    "konst.private",
    "my secret note",
    "4111111111111111",
    "resetTOKEN123",
    "cfpass",
    "fido-key-material",
    "old-pass",
]

RAW_LOGIN = {
    "id": "11111111-aaaa",
    "organizationId": None,
    "folderId": "folder-1",
    "type": 1,
    "name": "Chase bank konst.private@gmail.com acct 12345678",
    "notes": "my secret note",
    "fields": [{"name": "pin", "value": "cfpass", "type": 1}],
    "login": {
        "username": "konst.private",
        "password": "hunter2-SUPER-secret",
        "totp": "JBSWY3DPEHPK3PXP",
        "uris": [
            {"match": None, "uri": "https://user:hunter2-SUPER-secret@secure.chase.com/reset?t=resetTOKEN123"},
            {"match": None, "uri": "chase.com"},
            {"match": None, "uri": "androidapp://com.chase.sig.android"},
        ],
        "fido2Credentials": [{"keyValue": "fido-key-material"}],
    },
    "passwordHistory": [{"password": "old-pass"}],
}

RAW_CARD = {
    "id": "22222222-bbbb",
    "organizationId": "org-1",
    "folderId": None,
    "type": 3,
    "name": "Visa",
    "card": {"number": "4111111111111111", "code": "123"},
}


def test_no_secret_survives():
    for raw in (RAW_LOGIN, RAW_CARD):
        item = to_safe_item(raw)
        dumped = json.dumps(item.model_dump()) + json.dumps(item.llm_view("Old"))
        for secret in SECRETS:
            assert secret not in dumped, secret


def test_login_projection():
    item = to_safe_item(RAW_LOGIN)
    assert item.type == "login"
    assert item.domains == ["chase.com", "androidapp:com.chase.sig.android"]
    assert item.name == "Chase bank <email>@gmail.com acct <num>"
    assert item.folder_id == "folder-1"
    assert not item.in_organization
    assert set(item.llm_view(None)) == {"id", "type", "name", "domains"}
    assert item.llm_view("Old")["old_folder"] == "Old"


def test_card_projection():
    item = to_safe_item(RAW_CARD)
    assert item.type == "card" and item.domains == [] and item.in_organization


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("https://accounts.google.com/signin", "google.com"),
        ("http://192.168.1.1:8080/admin", "private-ip"),
        ("8.8.8.8", "public-ip"),
        ("http://nas:5000", "local-host"),
        ("bbc.co.uk/news", "bbc.co.uk"),
        ("", None),
        ("   ", None),
        ("http://[::1", None),
    ],
)
def test_domain_from_uri(uri, expected):
    assert domain_from_uri(uri) == expected


def test_redact_name_keeps_plain_names():
    assert redact_name("  GitHub   work ") == "GitHub work"


def test_only_local_ollama_allowed():
    assert_local_url("http://127.0.0.1:11434")
    assert_local_url("http://localhost:11434")
    for bad in ("http://192.168.1.10:11434", "https://ollama.com", "http://0.0.0.0:11434"):
        with pytest.raises(ConfigError):
            assert_local_url(bad)


def test_cloud_models_rejected():
    assert_local_model_name("qwen3.8:27b-q4_K_M")
    for bad in ("gpt-oss:120b-cloud", "qwen3-coder:480b-cloud"):
        with pytest.raises(ConfigError):
            assert_local_model_name(bad)
