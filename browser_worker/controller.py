"""One serialized protected session on a root-provided private channel."""
import asyncio
import os
import signal
import socket

from .auth import AtomicAuthenticator, Credential
from .control import ControlChannel
from .egress import ConnectProxy
from .errors import BrowserFailure, Code
from .output_gate import OutputGate
from .watchdog import Watchdog, WorkerLease
from site_adapters import login_spec

CHROMIUM_ARGUMENTS = [
    "--disable-breakpad", "--disable-crash-reporter", "--crash-dumps-dir=/opt/shadow/crashes",
    "--disable-quic", "--disable-http2", "--proxy-bypass-list=<-loopback>",
]


async def run(channel: ControlChannel, lease: WorkerLease):
    from playwright.async_api import async_playwright

    await asyncio.wait_for(channel.ready.wait(), timeout=10)
    lease.check()
    watchdog = Watchdog(lease, lambda: os.killpg(os.getpgrp(), signal.SIGKILL))
    watchdog.start()
    proxy = ConnectProxy(lease)
    proxy.start()
    gate = OutputGate(lease)
    try:
        async with async_playwright() as playwright:
            # XDG_CONFIG_HOME is the immutable config directory supplied by
            # PID 1. Crashpad cannot write dumps there; the profile is tmpfs.
            browser = await playwright.chromium.launch(channel="chromium", headless=False, chromium_sandbox=True,
                proxy={"server": f"http://127.0.0.1:{proxy.port}"}, args=CHROMIUM_ARGUMENTS)
            context = await browser.new_context(accept_downloads=False, service_workers="block")
            page = await context.new_page()
            await channel.send({"kind": "ready"})
            command = await channel.receive()
            if set(command) != {"kind", "adapter_id"} or command["kind"] != "login":
                raise BrowserFailure(Code.INVALID_REQUEST)
            spec = login_spec(command["adapter_id"])

            async def authorize(stage):
                await channel.send({"kind": "authorize", "stage": stage})
                if await channel.receive() != {"kind": "authorized", "stage": stage}:
                    raise BrowserFailure(Code.INVALID_REQUEST)

            async def resolve():
                await channel.send({"kind": "resolve"})
                message = await channel.receive()
                if set(message) != {"kind", "username", "password", "totp"} or message.pop("kind") != "credential":
                    raise BrowserFailure(Code.INVALID_REQUEST)
                return Credential(**message)

            result = await AtomicAuthenticator(page, gate, spec).run(resolve, authorize)
            await channel.send({"kind": "authentication", "state": result.state})
            if result.state != "succeeded":
                return
            # U10 adds only manifest-defined safe actions here. The controller
            # cannot expose page objects, selectors, JS, screenshots or cookies.
            while True:
                command = await channel.receive(timeout=None)
                if command == {"kind": "close"}:
                    return
                raise BrowserFailure(Code.INVALID_REQUEST)
    finally:
        gate.close()
        proxy.close()
        watchdog.stop()


async def main():
    connection = socket.socket(fileno=os.dup(0))
    reader, writer = await asyncio.open_connection(sock=connection)
    lease = WorkerLease()
    channel = ControlChannel(reader, writer, lease)
    try:
        await run(channel, lease)
    except BaseException:
        pass  # All product diagnostics use fixed native codes, never tracebacks.
    finally:
        await channel.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException:
        pass
