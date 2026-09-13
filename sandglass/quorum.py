"""Boundary 2: the committee.

Capability confinement (Boundary 1) stops a hijacked *application*. It cannot
stop a captured *device*, because whoever owns the host owns the key and the
effector with it. Quorum is the answer to that: authority for irreversible
actions lives across five nodes, and no single node can act alone.

The part that makes this more than a counter: each peer re-checks the request
against its OWN manifest copy and its OWN local facts. A peer may know something
the requesting node does not — a safety lockout on the target, say — and will
refuse to sign even a request that is perfectly within the requester's rights.
That is the real-world case: a line crew sets a hot line tag, and the peers
refuse to re-energize the line no matter what the local agent believes.

Ed25519 via PyNaCl. Keys are derived deterministically from a fleet seed so the
demo needs no key-exchange step; a real deployment provisions them at
commissioning and never lets the private half leave the device.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

FLEET_SEED = b"sandglass-demo-fleet-v1"


def _seed_for(node_id: str) -> bytes:
    return hashlib.sha256(FLEET_SEED + node_id.encode()).digest()


def keypair(node_id: str) -> tuple[SigningKey, VerifyKey]:
    sk = SigningKey(_seed_for(node_id))
    return sk, sk.verify_key


def canonical(req: dict) -> bytes:
    """Sign the request, not a rendering of it — field order must not matter."""
    body = {k: req[k] for k in sorted(req) if k in ("action", "target", "nonce")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Peer:
    """One committee member. Holds its own policy view and its own local facts."""

    node_id: str
    role: str
    manifest: object                       # its own Manifest copy
    locked_targets: set[str] = field(default_factory=set)
    reachable: bool = True

    def consider(self, req: dict) -> tuple[str, bytes | None, str]:
        """Return (node_id, signature or None, reason)."""
        if not self.reachable:
            return self.node_id, None, "unreachable — partitioned"

        action, target = req.get("action", ""), req.get("target", "")

        # A peer signs on its own authority, not the requester's say-so.
        # Note this is `approves`, not `allows`: authorizing an action and
        # performing it are separate rights.
        if not self.manifest.approves(self.role, action, target):
            return self.node_id, None, f"peer role={self.role} may not approve {action}"

        # Local facts the requesting node may not hold.
        if target in self.locked_targets:
            return self.node_id, None, f"safety lockout active on {target}"

        sk, _ = keypair(self.node_id)
        return self.node_id, sk.sign(canonical(req)).signature, "signed"


class Committee:
    def __init__(self, peers: list[Peer], threshold: int = 3):
        self.peers = peers
        self.threshold = threshold
        self.last_round: list[tuple[str, bool, str]] = []

    def partition(self, *node_ids: str) -> None:
        for p in self.peers:
            if p.node_id in node_ids:
                p.reachable = False

    def lockout(self, target: str, *node_ids: str) -> None:
        """Set a safety tag. Peers holding it will refuse to sign for that target."""
        for p in self.peers:
            if not node_ids or p.node_id in node_ids:
                p.locked_targets.add(target)

    async def collect(self, req: dict) -> list[str]:
        """Gather signatures; return the node ids whose signatures verify."""
        signers, round_log = [], []
        for peer in self.peers:
            node_id, sig, reason = peer.consider(req)
            ok = False
            if sig is not None:
                try:
                    _, vk = keypair(node_id)
                    vk.verify(canonical(req), sig)
                    ok = True
                    signers.append(node_id)
                except BadSignatureError:
                    reason = "signature failed verification"
            round_log.append((node_id, ok, reason))
        self.last_round = round_log
        return signers

    def explain(self) -> str:
        return "; ".join(
            f"{n} {'signed' if ok else 'refused'}"
            + ("" if ok else f" ({why})")
            for n, ok, why in self.last_round
        )


def build(manifest, size: int = 5, threshold: int = 3) -> Committee:
    """A standard five-node committee: an operator, two supervisors, a field node."""
    roles = ["supervisor", "supervisor", "field", "field", "operator"]
    peers = []
    for i in range(size):
        role = roles[i % len(roles)]
        if role not in manifest.doc.get("roles", {}):
            role = "supervisor"
        peers.append(Peer(node_id=f"peer-{i+1:02d}", role=role, manifest=manifest))
    return Committee(peers, threshold=threshold)
