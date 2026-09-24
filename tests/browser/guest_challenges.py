"""Synthetic-only challenge tests inside the real headed Chromium VM."""
import asyncio
from urllib.parse import parse_qs

from browser_worker.auth import AtomicAuthenticator, Credential
from browser_worker.challenges import Totp
from browser_worker.errors import BrowserFailure, Code
from browser_worker.output_gate import OutputGate, Phase
from browser_worker.watchdog import WorkerLease
from site_adapters import login_spec

SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
FORM = '<form action="/session" method="post"><input id="username" name="username"><input id="password" name="password" type="password"><button id="submit" type="submit">Sign in</button></form>'
CHALLENGE = '<form action="/verify-session" method="post"><input id="code" name="code" autocomplete="one-time-code"><button id="verify" type="submit">Verify</button></form>'


async def scenario(browser, mode):
    spec = login_spec("synthetic-sso-v1" if mode == "sso" else "synthetic-v1")
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    gate = OutputGate(lease)
    context = await browser.new_context(service_workers="block")
    page = await context.new_page()
    submits, stages, protected, owner_calls = [], [], [], []

    async def route_request(route):
        request = route.request
        if request.url == spec.entry_url:
            content = '<script>location.replace("' + spec.url + '")</script>'
        elif request.url == spec.url:
            content = FORM
        elif request.url == spec.action and request.method == "POST":
            submits.append("password")
            destination = spec.challenge.url
            content = '<script>location.replace("' + destination + '")</script>'
        elif request.url == spec.challenge.url:
            content = CHALLENGE
            if mode == "unsupported":
                content = '<main><button>Use a passkey or recovery code</button></main>'
        elif request.url == spec.challenge.action and request.method == "POST":
            if parse_qs(request.post_data).get("code") != [Totp.parse(SEED).code()]:
                raise AssertionError("synthetic_code_mismatch")
            submits.append("code")
            content = '<script>location.replace("' + spec.success + '")</script>'
        elif request.url == spec.success:
            content = '<main data-view="items">Ready</main>'
        else:
            await route.abort()
            return
        await route.fulfill(status=200, content_type="text/html", body=content)

    await context.route("**/*", route_request)

    async def resolve():
        return Credential("synthetic-user", "synthetic-challenge-password", SEED if mode.startswith("totp") else None)

    async def authorize(stage):
        stages.append(stage)
        assert gate.phase != Phase.READY
        if stage == "challenge_fill" and mode == "totp_replaced":
            await page.evaluate('document.querySelector("#code").outerHTML = \'<input id="code" autocomplete="one-time-code">\'')
        if stage == "challenge_submit" and mode == "totp_action":
            await page.evaluate('document.querySelector("form").action="https://other.shadow.test/verify-session"')

    async def owner():
        owner_calls.append(True)
        assert gate.phase == Phase.OWNER
        try:
            gate.output_checkpoint("any")
            raise AssertionError("owner_output_open")
        except BrowserFailure as error:
            assert error.code == Code.OUTPUT_CLOSED
        if mode == "cancel":
            raise BrowserFailure(Code.SESSION_CLOSED)
        if mode == "expire":
            lease.revoke()
            return
        if mode == "early_complete":
            # Owner completion without a successful site challenge must not
            # reopen output. Expire the lease to bound this negative probe.
            asyncio.get_running_loop().call_later(0.1, lease.revoke)
            return
        await page.locator("#code").fill(Totp.parse(SEED).code())
        await page.locator("#verify").click()
        await page.wait_for_url(spec.success)

    result = await AtomicAuthenticator(page, gate, spec).run(resolve, authorize, owner=owner, protect=protected.append)
    assert SEED not in repr(result) and "synthetic-challenge-password" not in repr(result)
    if mode in {"totp", "owner", "sso"}:
        assert result.state == "succeeded" and gate.phase == Phase.READY, (mode, result.state, stages)
        assert submits == ["password", "code"]
        assert len(protected) == 1
        from shadow_common.secret_guard import SecretGuard
        # Use the same projection guard as observations: owner-entered codes
        # must be protected after the challenge document has disappeared.
        assert SecretGuard(protected).project("Echo: " + protected[0]) == "[withheld]"
    else:
        assert result.state == "outcome_unknown" and gate.phase == Phase.CLOSED, mode
        assert submits == ["password"]
    if mode in {"unsupported", "totp", "totp_replaced", "totp_action"}:
        assert not owner_calls
    await context.close()


async def run(browser):
    modes = ("totp", "owner", "sso", "cancel", "expire", "early_complete", "unsupported", "totp_replaced", "totp_action")
    for mode in modes:
        await scenario(browser, mode)
    print("BROWSER_CHALLENGES=pass", flush=True)
    print("BROWSER_CHALLENGE_SCENARIOS=" + str(len(modes)), flush=True)
