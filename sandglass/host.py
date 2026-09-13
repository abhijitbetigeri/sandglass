"""The Sandglass host runtime — the trusted half of a node.

Boundary 1 lives here. The agent runs inside a Wasmer sandbox built strictly
from its role's capability set. The signing key and the effector handle stay in
THIS process and are never seeded into the sandbox, so the guest's only way to
affect anything is to print a JSON request to stdout, which we read and judge.

wasmer-sdk 0.2.1 exposes no line-by-line stdout stream (Process only has
id/kill/terminate/wait), so the loop is turn-based: one FRESH sandbox per turn,
run to completion, parse its requests, adjudicate, feed verdicts into the next
turn. A fresh sandbox per turn is the stronger design anyway — no state carries
between turns, and warm creation measured 0.4ms, so it is effectively free.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from wasmer_sdk import Wasmer

from .audit import AuditChain
from .effector import Effector
from .policy import Manifest, SandboxSpec


class Host:
    def __init__(self, node_id, role, manifest, effector, quorum=None, audit_path=None):
        self.node_id = node_id
        self.role = role
        self.manifest = manifest
        self.effector = effector
        self.quorum = quorum  # None => single-node; irreversible actions stay HELD
        self.audit = AuditChain(node_id, audit_path)
        self.spec: SandboxSpec = manifest.spec_for(role)

    # ---- boundary 3: adjudicate one request ----------------------------
    async def handle(self, req: dict) -> dict:
        action, target = req.get("action", ""), req.get("target", "")
        common = dict(role=self.role, agent=req.get("agent", "guest"),
                      action=action, target=target)

        if not self.manifest.allows(self.role, action, target):
            e = self.audit.append(
                decision="DENY",
                reason=self.manifest.deny_reason(self.role, action, target), **common)
            return {"action": action, "decision": "DENY", "reason": e.reason}

        if self.manifest.is_irreversible(action):
            signers = await self.quorum.collect(req) if self.quorum else []
            have, need = len(signers), self.manifest.threshold
            if have < need:
                detail = self.quorum.explain() if self.quorum else "no committee configured"
                e = self.audit.append(
                    decision="HELD", quorum=f"{have}/{need}", signers=signers,
                    reason=f"irreversible action held at {have}/{need} — {detail}", **common)
                return {"action": action, "decision": "HELD", "reason": e.reason}
            result = self.effector.apply(action, target)
            self.audit.append(decision="ALLOW", quorum=f"{have}/{need}", signers=signers,
                              reason=f"quorum reached, host performed action ({result})", **common)
            return {"action": action, "decision": "ALLOW", "result": result}

        result = self.effector.apply(action, target)
        self.audit.append(decision="ALLOW", reason="policy match", **common)
        return {"action": action, "decision": "ALLOW", "result": result}

    # ---- boundary 1 + the loop -----------------------------------------
    async def run(self, guest_source: str, turns: int = 3, scenario: str = "benign"):
        wasmer = Wasmer()
        verdicts: list[dict] = []

        for turn in range(1, turns + 1):
            kwargs = self.spec.as_create_kwargs(extra_files={
                "agent.py": guest_source,
                "verdicts.json": json.dumps(verdicts),
            })
            kwargs.setdefault("env", {})["SANDGLASS_SCENARIO"] = scenario
            kwargs["env"]["SANDGLASS_TURN"] = str(turn)

            # Nothing else exists in here: no host fs, and network=disabled
            # means socket() fails with OSError [Errno 58] Not supported.
            sandbox = await wasmer.create_sandbox(**kwargs)
            out = await sandbox.command("python", ["/workspace/agent.py"]).run(check=False)

            turn_verdicts = []
            for line in out.text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    print(f"  [{self.node_id}] guest said: {line}")
                    continue
                v = await self.handle(req)
                turn_verdicts.append(v)
                print(f"  [{self.node_id}] {v['decision']:<5} "
                      f"{req.get('action',''):<15}{req.get('target','')}\n"
                      f"        └─ {v.get('reason', v.get('result',''))}")
            verdicts.extend(turn_verdicts)
            if not turn_verdicts:
                break

        ok = self.audit.verify()
        print(f"\n[{self.node_id}] audit chain verified={ok}  "
              f"{len(self.audit.entries)} entries  head={self.audit.head[:12]}")
        print(f"[{self.node_id}] effector state: {self.effector.targets}")
        return self.audit


def main():
    ap = argparse.ArgumentParser(description="Run one Sandglass node.")
    ap.add_argument("--node", default="node-01")
    ap.add_argument("--role", default="monitor")
    ap.add_argument("--manifest", default="manifest.yaml")
    ap.add_argument("--guest", default="guest/agent.py")
    ap.add_argument("--scenario", choices=["benign", "attack"], default="attack")
    ap.add_argument("--turns", type=int, default=1)
    ap.add_argument("--audit", default=None)
    ap.add_argument("--quorum", action="store_true",
                    help="enable the 5-node committee (Boundary 2)")
    ap.add_argument("--lockout", default=None,
                    help="set a safety tag on a target; peers refuse to sign for it")
    ap.add_argument("--partition", default="",
                    help="comma-separated peer ids to mark unreachable")
    args = ap.parse_args()

    manifest = Manifest.load(args.manifest)

    committee = None
    if args.quorum:
        from . import quorum as q
        committee = q.build(manifest, manifest.committee_size, manifest.threshold)
        if args.lockout:
            committee.lockout(args.lockout)
        if args.partition:
            committee.partition(*[p.strip() for p in args.partition.split(",") if p.strip()])

    host = Host(args.node, args.role, manifest, Effector(),
                quorum=committee, audit_path=args.audit)
    print(f"manifest v{manifest.version} ({manifest.digest()})  node={args.node} "
          f"role={args.role} scenario={args.scenario}")
    print(f"sandbox spec: {json.dumps(host.spec.as_create_kwargs())[:200]}\n")
    asyncio.run(host.run(Path(args.guest).read_text(), args.turns, args.scenario))


if __name__ == "__main__":
    main()
