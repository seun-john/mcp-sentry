"""Turn a declared permission inventory into plain-language capabilities and flags.

Permissions must be mapped into the small vocabulary below by you. Real OAuth scopes are
not interpreted, no account is contacted and nothing is enforced.
"""

from __future__ import annotations

from typing import Any

from .core import InputError, finding, report, require

ACTIONS = {
    "read": "Read the resource",
    "write": "Create or modify the resource",
    "delete": "Delete the resource",
    "send": "Send a message or other content out",
    "publish": "Publish content publicly",
    "execute": "Run code or commands",
    "admin": "Manage access or configuration",
}
HIGH_IMPACT = {"delete", "send", "publish", "execute", "admin"}
BROAD = {"*", "all", "/**", "**", "/"}


def _list_of_str(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InputError(f"'{field}' must be an array of strings")
    return value


def accessmap(data: dict[str, Any]) -> dict[str, Any]:
    integrations = require(data, "integrations", list)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    for item in integrations:
        ident = require(item, "id", str)
        if not ident or ident in seen:
            raise InputError("Integration ids must be non-empty and unique")
        seen.add(ident)
        permissions = require(item, "permissions", list)
        if not permissions:
            out.append(
                finding(
                    "NO_DECLARED_PERMISSIONS",
                    "No capabilities declared; the real access is unknown.",
                    integration=ident,
                )
            )
        for permission in permissions:
            resource = require(permission, "resource", str)
            actions = _list_of_str(permission.get("actions", []), "actions")
            destinations = _list_of_str(permission.get("destinations", []), "destinations")
            for action in actions:
                if action not in ACTIONS:
                    out.append(
                        finding(
                            "UNKNOWN_PERMISSION",
                            "No interpretation for this action; read the provider's documentation.",
                            integration=ident,
                            action=action,
                            resource=resource,
                        )
                    )
                    continue
                cap = {
                    "integration": ident,
                    "resource": resource,
                    "action": action,
                    "description": ACTIONS[action],
                    "destinations": destinations,
                }
                capabilities.append(cap)
                if action in HIGH_IMPACT:
                    out.append(
                        finding(
                            "HIGH_IMPACT_CAPABILITY",
                            "Review before enabling this integration.",
                            **cap,
                        )
                    )
                if resource.strip().lower() in BROAD:
                    out.append(
                        finding("BROAD_RESOURCE", "The permission covers every resource.", **cap)
                    )
                if action in ("send", "publish") and not destinations:
                    out.append(
                        finding(
                            "DESTINATION_UNSPECIFIED",
                            "An outbound capability names no destination.",
                            **cap,
                        )
                    )
        if item.get("requested_use"):
            out.append(
                finding(
                    "HUMAN_REVIEW_REQUIRED",
                    "Compare the declared capabilities with the intended use.",
                    integration=ident,
                    requested_use=item["requested_use"],
                )
            )
    return report(
        "MCP Sentry Access Map",
        out,
        capabilities=capabilities,
        scope="translates a permission inventory you supply; no account is inspected or enforced",
    )
