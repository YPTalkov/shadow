"""Known-secret projection for encrypted vault metadata."""
from shadow_common.secret_guard import SecretGuard as ValueGuard, REDACTED


class SecretGuard(ValueGuard):
    @staticmethod
    def vault_values(vault):
        yield vault.password
        for value in vault.tree.xpath("//String/Value | //Group/Notes | /KeePassFile/Meta/DatabaseDescription"):
            parent = value.getparent()
            key = parent.findtext("Key") if parent.tag == "String" else None
            if key and key.startswith("shadow.") and not key.startswith(("shadow.baseline.", "shadow.incoming.")):
                continue
            # Mirrored metadata is encrypted with its baseline for reconciliation;
            # that does not turn a public title into a password. Password, notes
            # and TOTP baseline/incoming values still guard every projection.
            if key and key.startswith(("shadow.baseline.", "shadow.incoming.")) and key.rsplit(".", 1)[-1] in {"title", "username", "urls", "group"}:
                continue
            if key in {"Title", "UserName", "URL"} and value.get("Protected") != "True":
                continue
            yield value.text

    @classmethod
    def from_vault(cls, vault):
        return cls(cls.vault_values(vault))
