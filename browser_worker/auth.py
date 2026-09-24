"""Credential use in a pinned document, with a closed observation gate throughout."""
from collections.abc import Awaitable, Callable
import asyncio
from dataclasses import dataclass, field
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .errors import BrowserFailure, Code
from .output_gate import OutputGate, Phase
from .challenges import ChallengeSpec, Totp, INSTALL_CHALLENGE, FILL_CHALLENGE
from .watchdog import boot_time


@dataclass(frozen=True, repr=False)
class Credential:
    username: str = field(repr=False)
    password: str = field(repr=False)
    totp: str | None = field(default=None, repr=False)

    def __post_init__(self):
        for value in (self.username, self.password, self.totp):
            if value is not None and (type(value) is not str or len(value.encode("utf-8")) > 65536):
                raise BrowserFailure(Code.INVALID_REQUEST)


def exact_https_url(value: str) -> str:
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
                or url.query or url.fragment or url.port not in (None, 443) or url.hostname != url.hostname.lower()
                or len(value) > 2048 or not value.isascii() or "\\" in value or any(ord(c) <= 32 for c in value)):
            raise ValueError
        try:
            ipaddress.ip_address(url.hostname)
        except ValueError:
            pass
        else:
            raise ValueError
        if "." not in url.hostname:
            raise ValueError
        return "https://" + url.hostname
    except (ValueError, TypeError):
        raise BrowserFailure(Code.INVALID_REQUEST) from None


@dataclass(frozen=True)
class LoginSpec:
    url: str
    action: str
    success: str
    username: str
    password: str
    submit: str
    success_selector: str
    challenge: ChallengeSpec | None = None
    entry_url: str | None = None
    success_origin: str | None = None

    def __post_init__(self):
        origin = exact_https_url(self.url)
        if exact_https_url(self.action) != origin or exact_https_url(self.success) != (self.success_origin or origin):
            raise BrowserFailure(Code.INVALID_REQUEST)
        if self.success_origin is not None and exact_https_url(self.success_origin) != self.success_origin:
            raise BrowserFailure(Code.INVALID_REQUEST)
        if self.entry_url is not None and exact_https_url(self.entry_url) not in {origin, self.success_origin}:
            raise BrowserFailure(Code.INVALID_REQUEST)
        if type(self.challenge) is dict:
            object.__setattr__(self, "challenge", ChallengeSpec(**self.challenge))
        if self.challenge is not None and (not isinstance(self.challenge, ChallengeSpec) or exact_https_url(self.challenge.url) != origin):
            raise BrowserFailure(Code.INVALID_REQUEST)
        for selector in (self.username, self.password, self.submit, self.success_selector):
            if type(selector) is not str or not 1 <= len(selector) <= 256:
                raise BrowserFailure(Code.INVALID_REQUEST)


# This code runs in a CDP isolated world. Website scripts cannot replace its
# DOM prototypes or the checkpoint object. It accepts only packaged selectors.
INSTALL_CHECKPOINT = r"""(spec => {
  const unique = selector => {
    const nodes = document.querySelectorAll(selector);
    return nodes.length === 1 ? nodes[0] : null;
  };
  const username = unique(spec.username), password = unique(spec.password), submit = unique(spec.submit);
  const form = password && password.form;
  const visible = node => node && node.isConnected && node.ownerDocument === document &&
    node.getClientRects().length > 0 && getComputedStyle(node).visibility === 'visible' &&
    getComputedStyle(node).display !== 'none' && !node.disabled && !node.readOnly;
  const valid = () => document === checkpoint.document && window === window.top &&
    location.href === spec.url && document.querySelectorAll('iframe,frame').length === 0 &&
    username instanceof HTMLInputElement && password instanceof HTMLInputElement &&
    submit instanceof HTMLButtonElement && form instanceof HTMLFormElement &&
    unique(spec.username) === username && unique(spec.password) === password && unique(spec.submit) === submit &&
    ['text','email'].includes(username.type) && password.type === 'password' && submit.type === 'submit' &&
    visible(username) && visible(password) && visible(submit) &&
    username.form === form && submit.form === form && form.isConnected &&
    form.method.toLowerCase() === 'post' && form.action === spec.action &&
    (!submit.hasAttribute('formaction') || submit.formAction === spec.action) &&
    (!submit.hasAttribute('formmethod') || submit.formMethod.toLowerCase() === 'post') &&
    ['', '_self'].includes(form.target) && ['', '_self'].includes(submit.formTarget) &&
    form.enctype === 'application/x-www-form-urlencoded' &&
    (!submit.hasAttribute('formenctype') || submit.formEnctype === 'application/x-www-form-urlencoded');
  const checkpoint = {document, valid, username, password, form, submit};
  globalThis.__shadowCheckpoint = checkpoint;
  return valid();
})"""

FILL_CHECKPOINT = r"""(credential => {
  const checkpoint = globalThis.__shadowCheckpoint;
  if (!checkpoint || !checkpoint.valid()) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  for (const [node, value] of [[checkpoint.username, credential.username], [checkpoint.password, credential.password]]) {
    if (!checkpoint.valid()) return false;
    setter.call(node, value);
    node.dispatchEvent(new Event('input', {bubbles:true}));
    node.dispatchEvent(new Event('change', {bubbles:true}));
  }
  return checkpoint.valid();
})"""

SUBMIT_CHECKPOINT = r"""(() => {
  const checkpoint = globalThis.__shadowCheckpoint;
  if (!checkpoint || !checkpoint.valid()) return false;
  HTMLFormElement.prototype.requestSubmit.call(checkpoint.form, checkpoint.submit);
  return true;
})()"""


@dataclass(frozen=True)
class AuthResult:
    state: str
    code: str | None = None


class AtomicAuthenticator:
    def __init__(self, page, gate: OutputGate, spec: LoginSpec):
        self.page, self.gate, self.spec = page, gate, spec
        self._cdp = None
        self._context = None
        self._document = None
        self.submitted = False

    async def document(self) -> str:
        self._single_page()
        tree = (await self._cdp.send("Page.getFrameTree"))["frameTree"]
        if tree.get("childFrames"):
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        frame = tree["frame"]
        return frame["id"] + ":" + frame["loaderId"]

    async def _evaluate(self, expression: str):
        self._single_page()
        self.gate.lease.check()
        result = await self._cdp.send("Runtime.evaluate", {
            "expression": expression, "contextId": self._context,
            "returnByValue": True, "awaitPromise": False,
        })
        self.gate.lease.check()
        self._single_page()
        if "exceptionDetails" in result:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        return result.get("result", {}).get("value")

    async def _capture(self):
        self._single_page()
        tree = (await self._cdp.send("Page.getFrameTree"))["frameTree"]
        if tree.get("childFrames") or tree["frame"]["url"] != self.spec.url:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        self._document = tree["frame"]["id"] + ":" + tree["frame"]["loaderId"]
        self._context = (await self._cdp.send("Page.createIsolatedWorld", {
            "frameId": tree["frame"]["id"], "worldName": "shadow-protected", "grantUniveralAccess": False,
        }))["executionContextId"]
        fields = {name: getattr(self.spec, name) for name in ("url", "action", "username", "password", "submit")}
        if await self._evaluate(INSTALL_CHECKPOINT + "(" + json.dumps(fields) + ")") is not True:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)

    async def _validate(self):
        if await self.document() != self._document:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        if await self._evaluate("globalThis.__shadowCheckpoint?.valid() === true") is not True:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)

    async def _destination(self, *, permit_challenge):
        deadline = boot_time() + 15
        while boot_time() < deadline:
            self._single_page()
            self.gate.lease.check()
            tree = (await self._cdp.send("Page.getFrameTree"))["frameTree"]
            if tree.get("childFrames"):
                raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)
            url = tree["frame"]["url"]
            if url == self.spec.success:
                await self.page.wait_for_load_state("domcontentloaded", timeout=3000)
                return False
            if permit_challenge and self.spec.challenge is not None and url == self.spec.challenge.url:
                await self.page.wait_for_load_state("domcontentloaded", timeout=3000)
                return True
            await asyncio.sleep(0.05)
        raise BrowserFailure(Code.AUTHENTICATION_FAILED)

    def _single_page(self):
        if len(self.page.context.pages) != 1:
            raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)

    async def _challenge(self, credential, authorize, owner, protect):
        spec = self.spec.challenge
        self.gate.transition(Phase.OWNER)
        tree = (await self._cdp.send("Page.getFrameTree"))["frameTree"]
        if tree.get("childFrames") or tree["frame"]["url"] != spec.url:
            raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)
        self._document = tree["frame"]["id"] + ":" + tree["frame"]["loaderId"]
        self._context = (await self._cdp.send("Page.createIsolatedWorld", {"frameId": tree["frame"]["id"], "worldName": "shadow-protected", "grantUniveralAccess": False}))["executionContextId"]
        if await self._evaluate(INSTALL_CHALLENGE + "(" + json.dumps({name: getattr(spec, name) for name in ("url", "action", "code", "submit")}) + ")") is not True:
            raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)
        if credential.totp:
            seed = Totp.parse(credential.totp)
            await authorize("challenge_fill")
            await self._validate()
            value = seed.code()
            protect(value)
            if await self._evaluate(FILL_CHALLENGE + "(" + json.dumps(value) + ")") is not True:
                raise BrowserFailure(Code.DOCUMENT_CHANGED)
            value = None
            await authorize("challenge_submit")
            await self._validate()
            try:
                if await self._evaluate(SUBMIT_CHECKPOINT) is not True:
                    raise BrowserFailure(Code.DOCUMENT_CHANGED)
            except Exception:
                self.gate.lease.check()
        else:
            if owner is None:
                raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)
            # Remember completed OTP inputs in the trusted process before the
            # owner can navigate away. A page that reflects the code into a
            # qualified safe field must still be rejected by the output guard.
            codes, invalid = set(), False
            context = self._context

            def owner_input(event):
                nonlocal invalid
                if event.get("name") != "__shadowOwnerCode" or event.get("executionContextId") != context:
                    return
                value = event.get("payload")
                if type(value) is not str or re.fullmatch(r"[0-9]{6,8}", value) is None or len(codes) >= 64:
                    invalid = True
                elif value not in codes:
                    codes.add(value)
                    protect(value)

            await self._cdp.send("Runtime.addBinding", {"name": "__shadowOwnerCode", "executionContextId": context})
            self._cdp.on("Runtime.bindingCalled", owner_input)
            await self._evaluate(r'''(() => {
                const checkpoint = globalThis.__shadowCheckpoint;
                const capture = () => {
                    if (!checkpoint.valid()) { __shadowOwnerCode('invalid'); return; }
                    const value = checkpoint.code.value;
                    if (value.length >= 6) __shadowOwnerCode(value.length <= 8 ? value : 'invalid');
                };
                window.addEventListener('input', event => { if (event.target === checkpoint.code) capture(); }, true);
                window.addEventListener('submit', capture, true);
            })()''')
            await asyncio.wait_for(owner(), timeout=120)
            # Flush earlier binding events before releasing the protected gate.
            await self._cdp.send("Runtime.evaluate", {"expression": "1", "returnByValue": True})
            if invalid or not codes:
                raise BrowserFailure(Code.UNSUPPORTED_CHALLENGE)
        await self._destination(permit_challenge=False)

    async def run(self, resolve: Callable[[], Awaitable[Credential]], authorize: Callable[[str], Awaitable[None]], *, owner=None, protect=lambda _: None) -> AuthResult:
        """The caller holds its session lock. Each callback rechecks native authority.

        authorize('submit') must persist the uncertain-submit checkpoint before
        acknowledging it. The entire context is destroyed after any failure.
        """
        credential = None
        try:
            self.gate.transition(Phase.NAVIGATING)
            await authorize("navigate")
            await self.page.goto(self.spec.entry_url or self.spec.url, wait_until="domcontentloaded", timeout=15000)
            if self.spec.entry_url:
                await self.page.wait_for_url(self.spec.url, wait_until="domcontentloaded", timeout=15000)
            self._cdp = await self.page.context.new_cdp_session(self.page)
            await self._capture()
            self.gate.transition(Phase.RESOLVING)
            await authorize("resolve")
            await self._validate()
            credential = await resolve()
            if not isinstance(credential, Credential):
                raise BrowserFailure(Code.INVALID_REQUEST)
            await authorize("fill")
            await self._validate()
            self.gate.transition(Phase.AUTHENTICATING)
            values = json.dumps({"username": credential.username, "password": credential.password})
            if await self._evaluate(FILL_CHECKPOINT + "(" + values + ")") is not True:
                raise BrowserFailure(Code.DOCUMENT_CHANGED)
            del values
            await authorize("submit")
            await self._validate()
            # Set before the asynchronous CDP send: transport failure can occur
            # after the website has already received the form submission.
            self.submitted = True
            try:
                acknowledged = await self._evaluate(SUBMIT_CHECKPOINT)
            except Exception:
                # A successful form navigation can destroy the isolated world
                # before CDP acknowledges requestSubmit. Verify the destination
                # independently; never resend the submission.
                self.gate.lease.check()
            else:
                if acknowledged is not True:
                    raise BrowserFailure(Code.DOCUMENT_CHANGED)
            if await self._destination(permit_challenge=True):
                await self._challenge(credential, authorize, owner, protect)
            self.gate.transition(Phase.VERIFYING)
            await authorize("verify")
            # A fresh document discards the form's JS state. Context secrets and
            # cookies remain inside the trusted VM for the session's lifetime.
            await self.page.goto(self.spec.success, wait_until="domcontentloaded", timeout=15000)
            if self.page.url != self.spec.success or await self.page.locator(self.spec.success_selector).count() != 1:
                raise BrowserFailure(Code.AUTHENTICATION_FAILED)
            if await self.page.locator('input[type="password"],iframe,frame').count():
                raise BrowserFailure(Code.UNSUPPORTED_VIEW)
            await authorize("output")
            self.gate.ready(await self.document())
            return AuthResult("succeeded")
        except BaseException as error:
            self.gate.close()
            try:
                await self.page.context.close()
            except BaseException:
                pass
            code = error.code if isinstance(error, BrowserFailure) else Code.UNAVAILABLE
            if self.submitted:
                return AuthResult("outcome_unknown", code.value)
            return AuthResult("failed", code.value)
        finally:
            credential = None
