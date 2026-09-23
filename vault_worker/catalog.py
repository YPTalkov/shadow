"""In-memory, allowlisted catalog projection for an unlocked KDBX vault."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import secrets
import time
import unicodedata
from urllib.parse import urlsplit

from pykeepass import PyKeePass
from .secret_guard import SecretGuard, REDACTED
from .ingest import source_record


class CatalogError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _normalized(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _origin(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        try:
            ipaddress.ip_address(parsed.hostname)
            return None
        except ValueError:
            pass
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        if port not in (None, 443):
            return f"https://{host}:{port}"
        return f"https://{host}"
    except (ValueError, UnicodeError):
        return None


@dataclass(frozen=True)
class CatalogItem:
    id: str
    title: str
    username: str
    origins: tuple[str, ...]
    group: str
    revision: int = 1
    source_kind: str = "local"
    presence: str = "present"
    authorization: str = "unapproved"
    observed_at: str | None = None
    source_instance: str | None = None
    restriction_event: str | None = None
    conflicted: bool = False
    diverged: bool = False

    def public(self, account_ref: str) -> dict[str, object]:
        return {
            "account_ref": account_ref,
            "title": self.title,
            "username": self.username,
            "origins": list(self.origins),
            "group": self.group,
            "source_kind": self.source_kind,
            "presence": self.presence,
            "authorization": self.authorization,
            "observed_at": self.observed_at,
        }


class Catalog:
    def __init__(self, items: list[CatalogItem]):
        self._items = tuple(sorted(items, key=lambda item: (_normalized(item.title), _normalized(item.username), item.id)))
        self._cursors: dict[str, tuple[float, str, frozenset[str], int]] = {}

    @classmethod
    def from_vault(cls, vault: PyKeePass) -> Catalog:
        items: list[CatalogItem] = []
        guard = SecretGuard.from_vault(vault)
        recycle = vault.recyclebin_group
        for entry in vault.entries:
            if recycle is not None and recycle._element in entry._element.iterancestors():
                continue
            try:
                revision = int(entry.get_custom_property("shadow.revision") or "1")
                if not 1 <= revision < 2**63:
                    raise ValueError
            except ValueError:
                raise CatalogError("invalid_catalog") from None
            def protected(key):
                value = entry._element.find(f"String[Key='{key}']/Value")
                return value is not None and value.get("Protected") == "True"
            origin = "" if protected("URL") else guard.project(_origin(entry.url), maximum=512)
            source = source_record(entry)
            if source and source.get("archived"):
                continue
            if source and source.get("presence") not in {"present", "deleted_at_source", "access_lost", "unknown"}:
                raise CatalogError("invalid_catalog")
            items.append(CatalogItem(
                id=str(entry.uuid),
                title=REDACTED if protected("Title") else guard.project(entry.title),
                username=REDACTED if protected("UserName") else guard.project(entry.username),
                origins=(origin,) if origin and origin != REDACTED else (),
                group=guard.project(" / ".join(entry.group.path) if entry.group else ""),
                revision=revision,
                source_kind="mirrored" if source else "local",
                presence=source["presence"] if source else "present",
                authorization="blocked" if source and source.get("conflicted") else "unapproved",
                observed_at=source.get("last_observed") if source else None,
                source_instance=source["instance"] if source else None,
                restriction_event=source.get("restriction_event") if source else None,
                conflicted=bool(source and source.get("conflicted")),
                diverged=bool(source and source.get("diverged")),
            ))
        return cls(items)

    def search(
        self,
        query: str,
        *,
        approved_ids: set[str],
        ref_factory,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, object]:
        if not isinstance(query, str) or len(query) > 256 or not isinstance(limit, int) or not 1 <= limit <= 50:
            raise CatalogError("invalid_request")
        normalized_query = _normalized(query)
        scope = frozenset(approved_ids)
        offset = 0
        if cursor is not None:
            state = self._cursors.get(cursor)
            if state is None or state[0] < time.monotonic() or state[1] != normalized_query or state[2] != scope:
                raise CatalogError("invalid_cursor")
            offset = state[3]
        matching = [
            item for item in self._items
            if item.id in scope and (
                not normalized_query
                or normalized_query in _normalized(item.title)
                or normalized_query in _normalized(item.username)
                or any(normalized_query in _normalized(origin) for origin in item.origins)
            )
        ]
        selected: list[dict[str, object]] = []
        for item in matching[offset:offset + limit]:
            account_ref = ref_factory(item.id)
            if not isinstance(account_ref, str) or len(account_ref) != 64 or any(char not in "0123456789abcdef" for char in account_ref):
                raise CatalogError("invalid_reference")
            projected = item.public(account_ref)
            if len(json.dumps({"items": selected + [projected]}, ensure_ascii=False).encode("utf-8")) > 64 * 1024:
                break
            selected.append(projected)
        next_offset = offset + len(selected)
        next_cursor = None
        if next_offset < len(matching):
            if not selected:
                raise CatalogError("result_too_large")
            next_cursor = secrets.token_hex(32)
            self._cursors[next_cursor] = (time.monotonic() + 300, normalized_query, scope, next_offset)
        return {"items": selected, "next_cursor": next_cursor}

    def owner_page(self, offset: int) -> dict[str, object]:
        """Native-only metadata page; UUIDs never cross the public agent API."""
        selected = []
        for item in self._items[offset:offset + 50]:
            projected = item.public("")
            projected.pop("account_ref")
            projected["id"] = item.id
            projected["revision"] = item.revision
            projected["source_instance"] = item.source_instance
            projected["restriction_event"] = item.restriction_event
            projected["conflicted"] = item.conflicted
            projected["diverged"] = item.diverged
            if len(json.dumps(selected + [projected], ensure_ascii=False).encode()) > 60 * 1024:
                break
            selected.append(projected)
        next_offset = offset + len(selected)
        return {"items": selected, "next_offset": next_offset if next_offset < len(self._items) else None}
