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
from .observations import Observations
from .watchdog import Watchdog, WorkerLease
from site_adapters import login_spec, manifest

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
            adapter = manifest(command["adapter_id"])
            protected_values = []

            async def authorize(stage):
                await channel.send({"kind": "authorize", "stage": stage})
                if await channel.receive() != {"kind": "authorized", "stage": stage}:
                    raise BrowserFailure(Code.INVALID_REQUEST)

            async def resolve():
                await channel.send({"kind": "resolve"})
                message = await channel.receive()
                if set(message) != {"kind", "username", "password", "totp"} or message.pop("kind") != "credential":
                    raise BrowserFailure(Code.INVALID_REQUEST)
                credential = Credential(**message)
                protected_values.extend(value for value in (credential.password, credential.totp) if value)
                return credential

            result = await AtomicAuthenticator(page, gate, spec).run(resolve, authorize)
            await channel.send({"kind": "authentication", "state": result.state})
            if result.state != "succeeded":
                return
            observations = Observations(page, gate, adapter, protected_values)
            while True:
                command = await channel.receive(timeout=None)
                if command == {"kind": "close"}:
                    return
                if set(command) != {"kind", "operation", "arguments"} or command["kind"] != "action" or type(command["arguments"]) is not dict:
                    raise BrowserFailure(Code.INVALID_REQUEST)
                operation, arguments = command["operation"], command["arguments"]
                try:
                    if operation == "browser.observe" and set(arguments) == {"view_id"}:
                        view = await observations.observe(arguments["view_id"])
                        await channel.send({"kind": "view", "view": view})
                    elif operation == "browser.extract" and set(arguments) == {"schema_id"}:
                        view = await observations.observe(arguments["schema_id"])
                        await channel.send({"kind": "view", "view": view})
                    elif operation == "browser.click" and set(arguments) == {"element_ref"}:
                        await observations.click(arguments["element_ref"])
                        await channel.send({"kind": "completed"})
                    elif operation == "browser.navigate" and set(arguments) == {"route_id"}:
                        await observations.navigate(arguments["route_id"])
                        await channel.send({"kind": "completed"})
                    else:
                        raise BrowserFailure(Code.INVALID_REQUEST)
                except BrowserFailure as error:
                    # Fixed code only, then destroy the unsupported session.
                    await channel.send({"kind": "error", "code": error.code.value})
                    return
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
