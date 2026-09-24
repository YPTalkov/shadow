"""JSON CLI for the same safe API used by MCP and PTC."""

import argparse
import sys

from .client import ShadowClient
from .protocol import AgentError, MAX_FRAME, decode, encode


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise AgentError("invalid_request")


def main(argv=None, *, client=None, stdin=None, stdout=None) -> int:
    parser = Parser(prog="shadow", description="Use Shadow's protected agent API. Arguments are metadata and opaque references only.")
    parser.add_argument("operation")
    parser.add_argument("--arguments", default="{}", help="JSON arguments, or - to read bounded JSON from stdin")
    parser.add_argument("--request-id", help="Stable UUID for an explicit retry; never automatically replay uncertain actions")
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    try:
        args = parser.parse_args(argv)
        raw = stdin.read(MAX_FRAME + 1) if args.arguments == "-" else args.arguments.encode()
        arguments = decode(raw)
        result = (client or ShadowClient()).call(args.operation, arguments, request_id=args.request_id)
        stdout.write(encode({"result": result}) + b"\n")
        return 0
    except AgentError as error:
        stdout.write(encode({"error": {"code": error.code}}) + b"\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
