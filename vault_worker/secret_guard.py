"""Bounded, in-memory known-value checks for allowlisted metadata.

This is defense in depth. It does not make arbitrary page text or custom fields
safe to disclose and is never a replacement for a typed output projection.
"""

from __future__ import annotations

from array import array
import base64
from collections import deque
import unicodedata
from urllib.parse import quote

REDACTED = "[withheld]"
MAX_STATES = 500_000
MAX_INPUT_CHARS = 4_000_000


def normalized(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


class SecretGuard:
    def __init__(self, values):
        # Aho-Corasick keeps lookup proportional to the small projected string,
        # rather than scanning every password for each account's metadata.
        self.edges: list[dict[str, int]] = [{}]
        self.failure = array("I", [0])
        self.terminal = bytearray([0])
        self.suppress_all = False
        total = 0
        for value in values:
            if not value:
                continue
            total += len(value)
            if total > MAX_INPUT_CHARS:
                self._suppress()
                return
            # All projected strings are <= 512 characters. Longer protected
            # values cannot be returned whole by those bounded projections.
            if len(value) > 1024:
                continue
            encoded = base64.b64encode(value.encode()).decode()
            variants = {value, quote(value, safe=""), encoded, encoded.rstrip("="), encoded.replace("+", "-").replace("/", "_").rstrip("=")}
            for pattern in variants:
                state = 0
                for character in normalized(pattern):
                    target = self.edges[state].get(character)
                    if target is None:
                        if len(self.edges) >= MAX_STATES:
                            self._suppress()
                            return
                        target = len(self.edges)
                        self.edges[state][character] = target
                        self.edges.append({})
                        self.failure.append(0)
                        self.terminal.append(0)
                    state = target
                self.terminal[state] = 1
        queue = deque(self.edges[0].values())
        while queue:
            state = queue.popleft()
            for character, target in self.edges[state].items():
                queue.append(target)
                fallback = self.failure[state]
                while fallback and character not in self.edges[fallback]:
                    fallback = self.failure[fallback]
                self.failure[target] = self.edges[fallback].get(character, 0)
                self.terminal[target] |= self.terminal[self.failure[target]]

    def _suppress(self):
        self.suppress_all = True
        self.edges = [{}]
        self.failure = array("I", [0])
        self.terminal = bytearray([0])

    def project(self, text: str | None, *, maximum: int = 256) -> str:
        value = (text or "")[:maximum]
        if not value:
            return ""
        if self.suppress_all:
            return REDACTED
        state = 0
        for character in normalized(value):
            while state and character not in self.edges[state]:
                state = self.failure[state]
            state = self.edges[state].get(character, 0)
            if self.terminal[state]:
                return REDACTED
        return value

    @staticmethod
    def vault_values(vault):
        yield vault.password
        for value in vault.tree.xpath("//String/Value | //Group/Notes | /KeePassFile/Meta/DatabaseDescription"):
            parent = value.getparent()
            key = parent.findtext("Key") if parent.tag == "String" else None
            if key and key.startswith("shadow."):
                continue
            if key in {"Title", "UserName", "URL"} and value.get("Protected") != "True":
                continue
            yield value.text

    @classmethod
    def from_vault(cls, vault):
        return cls(cls.vault_values(vault))
