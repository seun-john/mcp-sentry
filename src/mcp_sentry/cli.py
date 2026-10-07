"""Command line for MCP Sentry."""

from __future__ import annotations

import argparse
from typing import Any

from .access import accessmap
from .core import finding, report
from .runner import Command, main_wrapper, run
from .sentry import baseline, mcpsentry


def _scan(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    return mcpsentry(data)


def _baseline(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    fps = baseline(data)
    return report(
        "MCP Sentry",
        [
            finding(
                "BASELINE", "Fingerprints of the supplied tools, ready to approve.", count=len(fps)
            )
        ],
        baseline=fps,
    )


def _access(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    return accessmap(data)


COMMANDS = {
    "scan": Command(_scan, "Scan tool definitions and decide recorded calls", frozenset()),
    "baseline": Command(
        _baseline,
        "Fingerprint a tool list so you can approve it",
        frozenset({"BASELINE"}),
    ),
    "access": Command(_access, "Map declared integration permissions", frozenset()),
}


def main(argv: list[str] | None = None) -> int:
    return run("mcp-sentry", "Audit MCP tools, calls and permissions offline.", COMMANDS, argv)


if __name__ == "__main__":
    main_wrapper(main)
