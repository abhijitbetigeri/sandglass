"""Capability manifest: load, verify, and resolve a role into a sandbox config.

This is the policy language of Sandglass. Everything the host is willing to do
is written here; anything absent is unreachable by construction.

Verified against wasmer-sdk 0.2.1, whose real signature is:

    await Wasmer().create_sandbox(
        packages=..., files=..., env=..., network=..., shell=...
    )

Note there is NO `mounts` parameter. The guest gets a virtual root and can see
only what `files` seeds into /workspace — the host filesystem is not reachable
at all. Measured: reading /keys/node.ed25519 from inside raises
FileNotFoundError [Errno 44], and socket.create_connection raises
OSError [Errno 58] Not supported under the default NetworkPolicy.DISABLED.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

NET_DISABLED = "disabled"
NET_HOST = "host"


class PolicyError(Exception):
    pass


class RollbackRejected(PolicyError):
    """Raised when a node is handed a manifest older than the one it holds."""


@dataclass
class SandboxSpec:
    """Resolves 1:1 onto Wasmer.create_sandbox(**spec.as_create_kwargs())."""

    packages: list[str]
    network: str = NET_DISABLED
    seed: dict = field(default_factory=dict)   # files the role may see in /workspace
    env: dict = field(default_factory=dict)
    allow: set[str] = field(default_factory=set)

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
        net = r.get("network", False)
        return SandboxSpec(
            packages=r.get("packages", []),
            network=NET_HOST if net else NET_DISABLED,
            seed=r.get("seed", {}) or {},
            env=r.get("env", {}) or {},
            allow=set(r.get("allow", [])),
        )

    def allows(self, role: str, action: str) -> bool:
        return action in self.spec_for(role).allow

    def is_irreversible(self, action: str) -> bool:
        return bool(self.doc.get("actions", {}).get(action, {}).get("irreversible", False))

    def deny_reason(self, role: str, action: str) -> str:
        if action not in self.doc.get("actions", {}):
            return f"unknown action {action!r} — not in manifest v{self.version}"
        return f"capability not granted for role={role}"
