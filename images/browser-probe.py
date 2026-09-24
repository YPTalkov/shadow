"""Synthetic Linux/Chromium bootstrap; never used to handle real credentials."""
import asyncio
import os
from pathlib import Path

CHROMIUM_ARGUMENTS = ["--disable-breakpad", "--disable-crash-reporter", "--crash-dumps-dir=/opt/shadow/crashes"]


async def main():
    from playwright.async_api import async_playwright
    print("BROWSER_NETWORK_DEVICES=" + ",".join(p.name for p in Path("/sys/class/net").iterdir()), flush=True)
    print("BROWSER_DRM_DEVICES=" + ",".join(p.name for p in Path("/dev/dri").glob("*")), flush=True)
    print("BROWSER_INPUT_DEVICES=" + str(len(list(Path("/sys/class/input").glob("event*")))), flush=True)
    print("BROWSER_UID=" + str(os.getuid()), flush=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel="chromium", headless=False, chromium_sandbox=True, args=CHROMIUM_ARGUMENTS)
        context = await browser.new_context(accept_downloads=False, service_workers="block")
        page = await context.new_page()
        await page.set_content('<form><input name="username"><input type="password"><button>Sign in</button></form>')
        await page.locator('input[type=password]').fill("synthetic-browser-bootstrap-canary")
        assert await page.locator('input[type=password]').input_value() == "synthetic-browser-bootstrap-canary"
        print("BROWSER_ENGINE=pass", flush=True)
        print("BROWSER_VERSION=" + browser.version, flush=True)
        await context.close()
        from browser_scenarios import run
        await run(browser)
        from guest_safe_views import run as safe_views
        await safe_views(browser)
        from guest_challenges import run as challenges
        await challenges(browser)
        await browser.close()
        from browser_worker.egress import ConnectProxy
        from browser_worker.watchdog import WorkerLease
        from browser_worker.output_gate import OutputGate
        from browser_worker.auth import AtomicAuthenticator, Credential
        from browser_scenarios import SPEC, PASSWORD
        lease = WorkerLease()
        lease.renew(sequence=1, ttl_ms=10000)
        proxy = ConnectProxy(lease)
        proxy.start()
        try:
            browser = await playwright.chromium.launch(channel="chromium", headless=False, chromium_sandbox=True,
                proxy={"server": f"http://127.0.0.1:{proxy.port}"}, args=CHROMIUM_ARGUMENTS)
            context = await browser.new_context(accept_downloads=False, service_workers="block")
            page = await context.new_page()
            failures = []
            page.on("requestfailed", lambda request: failures.append(request.failure if request.failure in {"net::ERR_CERT_AUTHORITY_INVALID", "net::ERR_PROXY_CONNECTION_FAILED", "net::ERR_TUNNEL_CONNECTION_FAILED", "net::ERR_INTERNET_DISCONNECTED", "net::ERR_CONNECTION_CLOSED", "net::ERR_CONNECTION_RESET"} else "other"))
            phases = []

            async def resolve():
                return Credential("synthetic-user", PASSWORD)

            async def authorize(stage):
                lease.check()
                phases.append(stage)

            result = await AtomicAuthenticator(page, OutputGate(lease), SPEC).run(resolve, authorize)
            assert result.state == "succeeded", ("https", result.state, result.code, phases, failures)
            assert await page.locator("[data-field=title]").inner_text() == "Example report"
            print("BROWSER_HTTPS_AUTH=pass", flush=True)
            crash_page = await context.new_page()
            await crash_page.set_content('<input type="password">')
            await crash_page.locator("input").fill(PASSWORD)
            crashed = asyncio.Event()
            crash_page.on("crash", lambda: crashed.set())
            crash_channel = await context.new_cdp_session(crash_page)
            trigger = asyncio.create_task(crash_channel.send("Page.crash"))
            try:
                await asyncio.wait_for(crashed.wait(), timeout=3)
            finally:
                trigger.cancel()
                await asyncio.gather(trigger, return_exceptions=True)
            await asyncio.sleep(0.5)
            dumps = [path for directory in ("/home/pwuser", "/tmp") for path in Path(directory).rglob("*")
                     if path.is_file() and (path.suffix == ".dmp" or path.name == "core" or
                                           ("Crash Reports" in path.parts and path.parent.name in {"pending", "completed"}))]
            assert not dumps, "synthetic_crash_dump_created"
            print("BROWSER_CRASH_DUMPS=absent", flush=True)
            await context.close()
            await browser.close()
        finally:
            proxy.close()


if __name__ == "__main__":
    asyncio.run(main())
