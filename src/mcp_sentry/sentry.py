"""Offline scanner and decision evaluator for MCP tool definitions and tool calls.

It reads descriptions of tools and records of calls. It does not sit between a client and a
server, so it cannot block anything by itself: it tells you what a gateway or a person
should block.
"""

from __future__ import annotations

import re
from typing import Any

from .core import InputError, digest, finding, report, require
from .redact import redact

INSTRUCTION_SHAPED = re.compile(
    r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)?\s*"
    r"(?:instructions?|rules?|prompts?)"
    r"|reveal\s+(?:the\s+)?(?:system\s+prompt|secrets?|api\s*keys?)"
    r"|(?:send|post|upload|email)\b.{0,40}\b(?:credentials?|passwords?|tokens?|api\s*keys?|private\s*keys?)"
    r"|override\b.{0,30}\bpolic(?:y|ies)"
    r"|do\s+not\s+(?:tell|inform|mention|show)\s+(?:this\s+to\s+)?the\s+user"
    r"|<\s*important\s*>"
    r"|(?:read|cat|open|include)\b.{0,30}(?:~/\.ssh|\.env\b|id_rsa|\.aws/credentials)",
    re.I | re.S,
)
# Zero-width and bidi controls, and the Unicode "tag" block that can smuggle ASCII invisibly.
HIDDEN = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")


def _strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    """Every string in a nested structure, with where it was found."""
    if isinstance(value, str):
        return [(path or "value", value)]
    if isinstance(value, dict):
        return [
            pair
            for k, v in value.items()
            for pair in _strings(v, f"{path}.{k}" if path else str(k))
        ]
    if isinstance(value, list):
        return [pair for i, v in enumerate(value) for pair in _strings(v, f"{path}[{i}]")]
    return []


def fingerprint(tool: dict[str, Any]) -> str:
    """Hash of the whole definition, so any change to wording or schema changes it."""
    return digest(tool)


def baseline(data: dict[str, Any]) -> dict[str, str]:
    """Approved fingerprints for every tool in `data['tools']`."""
    result: dict[str, str] = {}
    for tool in require(data, "tools", list):
        name = require(tool, "name", str)
        if name in result:
            raise InputError(f"Duplicate tool name: {name}")
        result[name] = fingerprint(tool)
    return result


def mcpsentry(data: dict[str, Any]) -> dict[str, Any]:
    tools = require(data, "tools", list)
    approved = data.get("baseline", {})
    policy = data.get("policy", {})
    if not isinstance(approved, dict) or not isinstance(policy, dict):
        raise InputError("'baseline' and 'policy' must be objects")
    out: list[dict[str, Any]] = []
    fingerprints: dict[str, str] = {}
    for tool in tools:
        name = require(tool, "name", str)
        if name in fingerprints:
            raise InputError(f"Duplicate tool name: {name}")
        fp = fingerprint(tool)
        fingerprints[name] = fp
        if name not in approved:
            out.append(
                finding(
                    "UNAPPROVED",
                    "No approved fingerprint for this tool.",
                    tool=name,
                    fingerprint=fp,
                )
            )
        elif approved[name] != fp:
            out.append(
                finding(
                    "CHANGED",
                    "Definition differs from the approved fingerprint (possible rug pull).",
                    tool=name,
                    fingerprint=fp,
                )
            )
        for where, text in _strings({k: v for k, v in tool.items() if k != "name"}):
            if HIDDEN.search(text):
                out.append(
                    finding(
                        "HIDDEN_TEXT",
                        "Invisible control or tag characters found; they can hide instructions.",
                        tool=name,
                        where=where,
                    )
                )
            match = INSTRUCTION_SHAPED.search(text)
            if match:
                out.append(
                    finding(
                        "SUSPICIOUS",
                        "Text shaped like an instruction to the model matched a heuristic.",
                        tool=name,
                        where=where,
                        matched=match.group()[:80],
                    )
                )
    for name in sorted(set(approved) - set(fingerprints)):
        out.append(finding("MISSING", "Approved tool is no longer offered.", tool=name))

    decisions = []
    for call in data.get("calls", []):
        decisions.append(_decide(call, fingerprints, approved, policy))
    return report(
        "MCP Sentry",
        out,
        fingerprints=fingerprints,
        decisions=decisions,
        scope="offline decisions only; does not intercept calls or sandbox tools",
    )


def _decide(
    call: dict[str, Any],
    fingerprints: dict[str, str],
    approved: dict[str, str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    name = require(call, "tool", str)
    rule = policy.get(name)
    reasons: list[str] = []
    if name not in fingerprints or approved.get(name) != fingerprints.get(name):
        reasons.append("unknown, unapproved or changed tool")
    if not isinstance(rule, dict) or rule.get("allow") is not True:
        reasons.append("no explicit allow rule")
    args = call.get("arguments", {})
    if not isinstance(args, dict):
        raise InputError("'arguments' must be an object")
    if isinstance(rule, dict):
        allowed = rule.get("argument_values", {})
        for key, value in args.items():
            if key not in allowed or value not in allowed[key]:
                reasons.append(f"argument value not explicitly allowed: {key}")
        for key in rule.get("required_arguments", []):
            if key not in args:
                reasons.append(f"required argument absent: {key}")
        if rule.get("side_effect") is True and not call.get("approval_id"):
            reasons.append("approval reference required (it is not authenticated here)")
    result_text = str(call.get("result", ""))
    if INSTRUCTION_SHAPED.search(result_text) or HIDDEN.search(result_text):
        reasons.append("instruction-shaped or hidden text in the result")
    clean, _ = redact(result_text)
    return {
        "tool": name,
        "decision": "BLOCK" if reasons else "ALLOW",
        "reasons": reasons,
        "redacted_result": clean,
    }
