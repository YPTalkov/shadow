"""Credential use in a pinned document, with a closed observation gate throughout."""
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import ipaddress
import json
from urllib.parse import urlsplit

from .errors import BrowserFailure, Code
from .output_gate import OutputGate, Phase


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

    def __post_init__(self):
        if len({exact_https_url(value) for value in (self.url, self.action, self.success)}) != 1:
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
        tree = (await self._cdp.send("Page.getFrameTree"))["frameTree"]
        if tree.get("childFrames"):
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        frame = tree["frame"]
        return frame["id"] + ":" + frame["loaderId"]

    async def _evaluate(self, expression: str):
        self.gate.lease.check()
        result = await self._cdp.send("Runtime.evaluate", {
            "expression": expression, "contextId": self._context,
            "returnByValue": True, "awaitPromise": False,
        })
        self.gate.lease.check()
        if "exceptionDetails" in result:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        return result.get("result", {}).get("value")

    async def _capture(self):
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

    async def run(self, resolve: Callable[[], Awaitable[Credential]], authorize: Callable[[str], Awaitable[None]]) -> AuthResult:
        """The caller holds its session lock. Each callback rechecks native authority.

        authorize('submit') must persist the uncertain-submit checkpoint before
        acknowledging it. The entire context is destroyed after any failure.
        """
        credential = None
        try:
            self.gate.transition(Phase.NAVIGATING)
            await authorize("navigate")
            await self.page.goto(self.spec.url, wait_until="domcontentloaded", timeout=15000)
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
            await self.page.wait_for_url(self.spec.success, wait_until="domcontentloaded", timeout=15000)
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
            if self.submitted:
                return AuthResult("outcome_unknown", Code.OUTCOME_UNKNOWN.value)
            code = error.code if isinstance(error, BrowserFailure) else Code.UNAVAILABLE
            return AuthResult("failed", code.value)
        finally:
            credential = None
