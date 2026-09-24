"""Private challenge primitives; generated codes never enter an agent result."""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
import struct
import time
from urllib.parse import parse_qs, urlsplit

from .errors import BrowserFailure, Code


@dataclass(frozen=True)
class ChallengeSpec:
    url: str
    action: str
    code: str
    submit: str

    def __post_init__(self):
        from .auth import exact_https_url
        if exact_https_url(self.url) != exact_https_url(self.action):
            raise BrowserFailure(Code.INVALID_REQUEST)
        if any(type(value) is not str or not 1 <= len(value) <= 256 for value in (self.code, self.submit)):
            raise BrowserFailure(Code.INVALID_REQUEST)


INSTALL_CHALLENGE = r"""(spec => {
  const unique = selector => {const nodes = document.querySelectorAll(selector); return nodes.length === 1 ? nodes[0] : null;};
  const code = unique(spec.code), submit = unique(spec.submit), form = code && code.form;
  const visible = node => node && node.isConnected && node.ownerDocument === document &&
    node.getClientRects().length > 0 && getComputedStyle(node).visibility === 'visible' &&
    getComputedStyle(node).display !== 'none' && !node.disabled && !node.readOnly;
  const checkpoint = {document, code, submit, form};
  checkpoint.valid = () => checkpoint.document === document && window === window.top && location.href === spec.url &&
    !document.querySelector('iframe,frame,input[type=password]') && unique(spec.code) === code && unique(spec.submit) === submit &&
    code instanceof HTMLInputElement && ['text','tel'].includes(code.type) && code.autocomplete === 'one-time-code' &&
    submit instanceof HTMLButtonElement && submit.type === 'submit' && form instanceof HTMLFormElement &&
    visible(code) && visible(submit) && code.form === form && submit.form === form && form.isConnected &&
    form.method.toLowerCase() === 'post' && form.action === spec.action &&
    (!submit.hasAttribute('formaction') || submit.formAction === spec.action) &&
    (!submit.hasAttribute('formmethod') || submit.formMethod.toLowerCase() === 'post') &&
    ['', '_self'].includes(form.target) && ['', '_self'].includes(submit.formTarget) &&
    form.enctype === 'application/x-www-form-urlencoded' &&
    (!submit.hasAttribute('formenctype') || submit.formEnctype === 'application/x-www-form-urlencoded');
  globalThis.__shadowCheckpoint = checkpoint;
  return checkpoint.valid();
})"""

FILL_CHALLENGE = r"""(value => {
  const checkpoint = globalThis.__shadowCheckpoint;
  if (!checkpoint?.valid()) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(checkpoint.code, value);
  checkpoint.code.dispatchEvent(new Event('input', {bubbles:true}));
  checkpoint.code.dispatchEvent(new Event('change', {bubbles:true}));
  return checkpoint.valid();
})"""


@dataclass(frozen=True, repr=False)
class Totp:
    secret: bytes = field(repr=False)
    algorithm: str
    digits: int
    period: int

    @classmethod
    def parse(cls, value):
        try:
            if type(value) is not str or not 1 <= len(value) <= 4096:
                raise ValueError
            algorithm, digits, period = "SHA1", 6, 30
            if value.startswith("otpauth:"):
                uri = urlsplit(value)
                if uri.scheme != "otpauth" or uri.netloc != "totp" or not uri.path.startswith("/") or len(uri.path) > 1024 or uri.fragment:
                    raise ValueError
                query = parse_qs(uri.query, strict_parsing=True, keep_blank_values=True, max_num_fields=8)
                if not set(query).issubset({"secret", "issuer", "algorithm", "digits", "period"}) or "secret" not in query or any(len(items) != 1 for items in query.values()):
                    raise ValueError
                value = query["secret"][0]
                algorithm = query.get("algorithm", ["SHA1"])[0].upper()
                digits = int(query.get("digits", ["6"])[0])
                period = int(query.get("period", ["30"])[0])
            if algorithm not in {"SHA1", "SHA256", "SHA512"} or digits not in {6, 8} or period not in {30, 60}:
                raise ValueError
            if re.fullmatch(r"[A-Za-z2-7]{16,208}={0,6}", value) is None:
                raise ValueError
            unpadded = value.rstrip("=")
            secret = base64.b32decode(unpadded + "=" * (-len(unpadded) % 8), casefold=True)
            if not 10 <= len(secret) <= 128:
                raise ValueError
            return cls(secret, algorithm, digits, period)
        except (ValueError, TypeError, UnicodeError):
            raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE) from None

    def code(self, *, now=None):
        # RFC 6238 / RFC 4226: an eight-byte time counter, HMAC, dynamic
        # truncation and decimal reduction. Reference vectors are in tests.
        try:
            now = time.time() if now is None else now
            if type(now) not in {int, float} or not math.isfinite(now) or not 0 <= now <= 2**63:
                raise ValueError
            counter = struct.pack("!Q", int(now // self.period))
            algorithm = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[self.algorithm]
            digest = hmac.digest(self.secret, counter, algorithm)
            offset = digest[-1] & 15
            value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
            return str(value % (10**self.digits)).zfill(self.digits)
        except (ValueError, TypeError, OverflowError, KeyError, struct.error):
            raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE) from None
