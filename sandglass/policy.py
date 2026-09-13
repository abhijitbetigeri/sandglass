"""Capability manifest: load, verify, and resolve a role into a sandbox config.

This is the policy language of Sandglass. Everything the host is willing to do
is written here; anything absent is unreachable by construction.

Capabilities are scoped by ACTION and by RESOURCE. `fs.read` alone is not a
capability — `fs.read` over `workspace/**` is. A role that may read its own
workspace therefore still cannot read a key path, even if the path existed.

Verified against wasmer-sdk 0.2.1, whose real signature is:

    await Wasmer().create_sandbox(
        packages=..., files=..., env=..., network=..., shell=...
    )

There is no `mounts` parameter. The guest gets a virtual root and sees only what
`files` seeds into /workspace. Measured: reading /keys/node.ed25519 from inside
raises FileNotFoundError [Errno 44], and socket.create_connection raises
OSError [Errno 58] Not supported under the default NetworkPolicy.DISABLED.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

NET_DISABLED = "disabled"
NET_HOST = "host"
ANY = "*"


class PolicyError(Exception):
    pass


class RollbackRejected(PolicyError):
    """Raised when a node is handed a manifest older than the one it holds."""


def _normalise_allow(raw) -> dict[str, list[str]]:
    """Accept either ["fs.read", ...] or {fs.read: ["workspace/**"], ...}."""
    if not raw:
        return {}
    if isinstance(raw, list):
        out: dict[str, list[str]] = {}
        for item in raw:
            if isinstance(item, dict):          # - fs.read: ["workspace/**"]
                for action, pats in item.items():
                    out[action] = _patterns(pats)
            else:                                # - sign
                out[item] = [ANY]
        return out
    return {action: _patterns(pats) for action, pats in raw.items()}


def _patterns(pats) -> list[str]:
    if pats in (True, None, ANY):
        return [ANY]
    if isinstance(pats, str):
        return [pats]
    return [str(p) for p in pats]


@dataclass
class SandboxSpec:
    """Resolves 1:1 onto Wasmer.create_sandbox(**spec.as_create_kwargs())."""

    packages: list[str]
    network: str = NET_DISABLED
    seed: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    allow: dict[str, list[str]] = field(default_factory=dict)

    def as_create_kwargs(self, extra_files: dict | None = None) -> dict:
        files = dict(self.seed)
        if extra_files:
            files.update(extra_files)
        kwargs: dict = {"packages": list(self.packages), "network": self.network}
        if files:
            kwargs["files"] = files
        if self.env:
            kwargs["env"] = dict(self.env)
        return kwargs


class Manifest:
    def __init__(self, doc: dict):
        self.doc = doc
        self.version = int(doc["version"])
        self.threshold = int(doc.get("committee_threshold", 3))
        self.committee_size = int(doc.get("committee_size", 5))

    @classmethod
    def load(cls, path: str | Path, current_version: int | None = None) -> "Manifest":
        m = cls(yaml.safe_load(Path(path).read_text()))
        if current_version is not None and m.version < current_version:
            raise RollbackRejected(
                f"policy version regression: offered v{m.version}, node holds v{current_version}"
            )
        return m

    def digest(self) -> str:
        blob = json.dumps(self.doc, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

    def spec_for(self, role: str) -> SandboxSpec:
        try:
            r = self.doc["roles"][role]
        except KeyError as exc:
            raise PolicyError(f"unknown role: {role}") from exc
        return SandboxSpec(
            packages=r.get("packages", []),
            network=NET_HOST if r.get("network", False) else NET_DISABLED,
            seed=r.get("seed", {}) or {},
            env=r.get("env", {}) or {},
            allow=_normalise_allow(r.get("allow")),
        )

    # ---- the two-part check: action, then resource ---------------------
    def allows(self, role: str, action: str, target: str = "") -> bool:
        scope = self.spec_for(role).allow.get(action)
        if scope is None:
            return False
        return any(fnmatchcase(target, pat) for pat in scope)

    def approves(self, role: str, action: str, target: str = "") -> bool:
        """May this role CO-SIGN the action? Distinct from being able to perform it.

        A supervisor exists to authorize a breaker operation it will never carry
        out itself, so `approve` is a separate grant from `allow`.
        """
        r = self.doc.get("roles", {}).get(role, {})
        scope = _normalise_allow(r.get("approve")).get(action)
        if scope is None:
            return False
        return any(fnmatchcase(target, pat) for pat in scope)

    def is_irreversible(self, action: str) -> bool:
        return bool(self.doc.get("actions", {}).get(action, {}).get("irreversible", False))

    def deny_reason(self, role: str, action: str, target: str = "") -> str:
        if action not in self.doc.get("actions", {}):
            return f"unknown action {action!r} — not in manifest v{self.version}"
        scope = self.spec_for(role).allow.get(action)
        if scope is None:
            return f"capability not granted for role={role}"
        return (f"resource out of scope for role={role} — "
                f"{action} limited to {', '.join(scope)}")
