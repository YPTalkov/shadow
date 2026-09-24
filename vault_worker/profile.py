"""Strict KDBX profile qualification before password-based key derivation.

Only this host-private package handles KDBX. Callers must not pass exceptions or
raw file contents across the agent boundary.
"""

from __future__ import annotations

import io

from pykeepass import PyKeePass
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
from pykeepass.pykeepass import BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD
from pykeepass.kdbx_parsing import KDBX
from construct import ChecksumError

from .bounded_kdbx import BOUNDED_KDBX, BoundedKDBXError, validate_outer_header


MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_KDF_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_KDF_ITERATIONS = 20
MAX_KDF_LANES = 8
MANAGED_MEMORY_BYTES = 128 * 1024 * 1024
MANAGED_ITERATIONS = 3
MANAGED_LANES = 2


class ManagedKDBXError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def inspect_header(data: bytes | PyKeePass) -> dict[str, object]:
    """Inspect the untrusted header without running its requested KDF."""
    if isinstance(data, bytes):
        if not data or len(data) > MAX_FILE_BYTES:
            raise ManagedKDBXError("invalid_vault")
        try:
            validate_outer_header(data)
            header = KDBX.header.parse(data).value
        except BoundedKDBXError as error:
            raise ManagedKDBXError(error.code) from None
        except Exception:
            raise ManagedKDBXError("invalid_vault") from None
    else:
        header = data.kdbx.header.value
    try:
        version = (header.major_version, header.minor_version)
        if version != (4, 0):
            raise ManagedKDBXError("unsupported_profile")
        parameters = header.dynamic_header.kdf_parameters.data.dict
        profile = {
            "version": version,
            "cipher": header.dynamic_header.cipher_id.data,
            "kdf": "argon2id" if parameters["$UUID"].value == kdf_uuids["argon2id"] else "unsupported",
            "memory": parameters["M"].value,
            "iterations": parameters["I"].value,
            "lanes": parameters["P"].value,
        }
        if profile["memory"] > MAX_KDF_MEMORY_BYTES or profile["iterations"] > MAX_KDF_ITERATIONS or profile["lanes"] > MAX_KDF_LANES:
            raise ManagedKDBXError("kdf_limit_exceeded")
        if profile["memory"] < MANAGED_MEMORY_BYTES or profile["iterations"] < MANAGED_ITERATIONS or profile["lanes"] < MANAGED_LANES:
            raise ManagedKDBXError("unsupported_profile")
        if profile["cipher"] != "aes256" or profile["kdf"] != "argon2id":
            raise ManagedKDBXError("unsupported_profile")
        if parameters["V"].value != 19 or len(parameters["S"].value) != 32:
            raise ManagedKDBXError("unsupported_profile")
        return profile
    except ManagedKDBXError:
        raise
    except Exception:
        raise ManagedKDBXError("invalid_vault") from None


def create_managed(password: str) -> bytes:
    if not password:
        raise ManagedKDBXError("invalid_credentials")
    try:
        db = PyKeePass(BLANK_DATABASE_LOCATION, password=BLANK_DATABASE_PASSWORD)
        db.password = password
        params = db.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params["$UUID"].value = kdf_uuids["argon2id"]
        params["M"].value = MANAGED_MEMORY_BYTES
        params["I"].value = MANAGED_ITERATIONS
        params["P"].value = MANAGED_LANES
        output = io.BytesIO()
        db.save(output)
        result = output.getvalue()
        inspect_header(result)
        return result
    except ManagedKDBXError:
        raise
    except Exception:
        raise ManagedKDBXError("invalid_vault") from None


def load_managed(data: bytes, password: str) -> PyKeePass:
    inspect_header(data)
    try:
        # Construct an ordinary library object with our bounded read pipeline.
        # Saving still uses the pinned library's unchanged serializer/crypto.
        db = object.__new__(PyKeePass)
        db.filename = io.BytesIO(data)
        db._password = password
        db._keyfile = None
        db.kdbx = BOUNDED_KDBX.parse(data, password=password, keyfile=None, transformed_key=None, decrypt=True)
        if len(db.entries) > 50_000 or len(db.groups) > 10_000:
            raise ManagedKDBXError("limit_exceeded")
        identities = [entry.uuid for entry in db.entries] + [group.uuid for group in db.groups]
        if len(identities) != len(set(identities)):
            raise ManagedKDBXError("invalid_vault")
        return db
    except ManagedKDBXError:
        raise
    except BoundedKDBXError as error:
        raise ManagedKDBXError(error.code) from None
    except Exception as error:
        # The caller only sees a fixed code. Do not forward library diagnostics.
        if isinstance(error, ChecksumError) and error.path == "(parsing) -> body -> cred_check":
            raise ManagedKDBXError("invalid_credentials") from None
        raise ManagedKDBXError("invalid_vault") from None
