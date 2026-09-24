"""Real Chromium hostile-view cases, packaged only in the diagnostic image."""
import base64
import html
import json
from urllib.parse import quote

from browser_worker.errors import BrowserFailure
from browser_worker.observations import Observations
from browser_worker.output_gate import OutputGate, Phase
from browser_worker.watchdog import WorkerLease
from site_adapters import manifest

PASSWORD = "synthetic-view/password&canary"
COOKIE = "synthetic-view-cookie-canary"
ORIGIN = "https://app.shadow.test"


async def scenario(browser, mode):
    context = await browser.new_context(accept_downloads=False, service_workers="block")
    try:
        await context.add_cookies([{"name": "session", "value": COOKIE, "domain": "app.shadow.test", "path": "/", "secure": True, "httpOnly": True}])
        values = {"plain": PASSWORD, "url": quote(PASSWORD, safe=""), "base64": base64.b64encode(PASSWORD.encode()).decode(), "html": html.escape(PASSWORD), "cookie": COOKIE}
        title = html.escape(values.get(mode, "Example report"))
        href = "/items/report-1" + ("?token=" + quote(PASSWORD, safe="") if mode == "token_link" else "")
        extra = {
            "password": '<input type="password" value="' + html.escape(PASSWORD, quote=True) + '">',
            "iframe": '<iframe src="about:blank"></iframe>',
            "hidden": '<input type="hidden" value="' + html.escape(PASSWORD, quote=True) + '"><img alt="' + html.escape(COOKIE, quote=True) + '" src="data:image/png;base64,AA==">',
        }.get(mode, "")
        content = f'<main data-view="items"><ul><li data-record><span data-field="title">{title}</span><a data-action="open" href="{href}">Open</a></li></ul></main>{extra}'

        async def route(request):
            await request.fulfill(status=200, content_type="text/html", body=content)

        await context.route("**/*", route)
        page = await context.new_page()
        await page.goto(ORIGIN + ("/settings/security" if mode == "settings" else "/items"))
        lease = WorkerLease(); lease.renew(sequence=1, ttl_ms=10000)
        gate = OutputGate(lease)
        observations = Observations(page, gate, manifest("synthetic-v1"), [PASSWORD])
        if mode == "popup":
            await context.new_page()
        if mode in {"output_race", "output_node"}:
            read_cookies = context.cookies

            async def changed_during_projection():
                if mode == "output_race":
                    await page.evaluate("history.replaceState(null, '', '/settings/security')")
                else:
                    await page.locator("main").evaluate("node => node.replaceWith(node.cloneNode(true))")
                return await read_cookies()

            context.cookies = changed_during_projection
        try:
            _, document = await observations.document()
            gate.transition(Phase.VERIFYING); gate.ready(document)
            view = await observations.observe("items")
        except BrowserFailure:
            assert mode in {"password", "iframe", "settings", "token_link", "popup", "output_race", "output_node"}, mode
            return
        assert mode not in {"password", "iframe", "settings", "token_link", "popup", "output_race", "output_node"}, mode
        encoded = json.dumps(view)
        assert PASSWORD not in encoded and COOKIE not in encoded, mode
        field = view["records"][0]["fields"][0]["value"]
        assert field == ("[withheld]" if mode in values else "Example report"), mode
        element = view["records"][0]["actions"][0]["element_ref"]
        assert len(element) == 64 and "href" not in encoded and "token=" not in encoded
        if mode in {"node", "href", "navigation", "history"}:
            if mode == "node":
                await page.locator("a").evaluate("node => node.replaceWith(node.cloneNode(true))")
            elif mode == "href":
                await page.locator("a").evaluate("node => node.href='/items/other'")
            elif mode == "history":
                await page.evaluate("history.replaceState(null, '', '/settings/security')")
            else:
                await page.goto(ORIGIN + "/items")
            try:
                await observations.click(element)
            except BrowserFailure:
                pass
            else:
                raise AssertionError(mode)
    finally:
        await context.close()


async def run(browser):
    modes = ("allowed", "plain", "url", "base64", "html", "cookie", "hidden", "password", "iframe", "settings", "token_link", "popup", "node", "href", "navigation", "history", "output_race", "output_node")
    for mode in modes:
        await scenario(browser, mode)
    print("BROWSER_SAFE_VIEWS=pass", flush=True)
    print("BROWSER_SAFE_VIEW_SCENARIOS=" + str(len(modes)), flush=True)
