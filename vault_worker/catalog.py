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


def _bounded(text: str | None, max_chars: int = 256) -> str:
    return (text or "")[:max_chars]


@dataclass(frozen=True)
class CatalogItem:
    id: str
    title: str
    username: str
    origins: tuple[str, ...]
    group: str
    source_kind: str = "local"
    presence: str = "present"
    authorization: str = "unapproved"
    observed_at: str | None = None

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
        for entry in vault.entries:
            origin = _origin(entry.url)
            items.append(CatalogItem(
                id=str(entry.uuid),
                title=_bounded(entry.title),
                username=_bounded(entry.username),
                origins=(origin,) if origin else (),
                group=_bounded(entry.group.name if entry.group else ""),
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
