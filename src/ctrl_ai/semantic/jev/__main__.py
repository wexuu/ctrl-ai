"""Command-line check: print a Jev verdict for a text.

    python -m ctrl_ai.semantic.jev "some text"
    python -m ctrl_ai.semantic.jev --file path/to/file.txt
    python -m ctrl_ai.semantic.jev --raw "some text"

Exit code 0 for ok, 2 for disabled (no key), 1 otherwise. Never prints the key.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

import httpx

from ctrl_ai.semantic.jev.client import check_text


class _CapturingTransport(httpx.AsyncBaseTransport):
    """Passes requests through and keeps the last response body for --raw."""

    def __init__(self) -> None:
        self._inner = httpx.AsyncHTTPTransport()
        self.status_code: int | None = None
        self.body: bytes | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        self.body = await response.aread()
        self.status_code = response.status_code
        return httpx.Response(response.status_code, headers=response.headers, content=self.body)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m ctrl_ai.semantic.jev", description="Print a Jev verdict for a text."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("text", nargs="?", help="the text to judge")
    source.add_argument("--file", help="read the text from this file")
    parser.add_argument("--raw", action="store_true", help="also print the unmodified Jev response")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = args.text

    capture = _CapturingTransport() if args.raw else None
    result = asyncio.run(check_text(text, transport=capture))

    print(json.dumps(result, indent=2))
    if capture is not None:
        print("\n--- raw Jev response ---")
        if capture.body is None:
            print("(no response received)")
        else:
            print(f"HTTP {capture.status_code}")
            try:
                print(json.dumps(json.loads(capture.body), indent=2))
            except ValueError:
                print(capture.body.decode("utf-8", errors="replace"))

    if result["status"] == "ok":
        return 0
    if result["status"] == "disabled":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
