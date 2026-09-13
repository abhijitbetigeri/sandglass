# Sandglass

**Run AI agents on edge devices as if they're already compromised.**

Agents on edge devices inherit the device's full authority, and there is no cloud out
there to authorize anything. Hijack the agent and you get the keys, the network, and
the wire to the hardware.

Sandglass gives the agent none of it. The agent runs inside a Wasmer sandbox with no
network and no keys mounted, so it **cannot act — only request**. A host process checks
every request against a signed capability manifest, and irreversible actions
additionally require 3-of-5 peer signatures. All enforced locally, offline.

Built for the AI Security Hackathon, San Francisco, 13 September 2026.

---

## The three boundaries

```
┌─ EDGE DEVICE ────────────────────────────────────────────────────┐
│                                                                   │
│   ┌── WASMER SANDBOX ── untrusted ──────────────────┐             │
│   │   agent logic + LLM-generated code              │             │
│   │     packages: ["python/python"]                 │             │
│   │     network:  disabled                          │             │
│   │   no signing key · no effector · no egress      │             │
│   └───────────────────┬─────────────────────────────┘             │
│            BOUNDARY 1 │  stdout JSON — the only way out           │
│                       ▼                                           │
│   ┌── HOST RUNTIME ── trusted ──────────────────────┐             │
│   │   parse → authorize → sign → quorum → execute   │             │
│   │   holds: node private key, effector handle      │             │
│   └───────┬──────────────────────────┬──────────────┘             │
│  BOUNDARY 3│                          │                            │
│           ▼                          ▼                            │
│      EFFECTOR                   AUDIT CHAIN                       │
│   breaker / funds / deploy      hash-linked, append-only          │
└───────────┼──────────────────────────┼────────────────────────────┘
            │             BOUNDARY 2   │
      ┌─────┴───────────────────────────────────────┐
      │  COMMITTEE — 5 peer nodes                   │
      │  each re-checks against its OWN manifest    │
      │  copy, then signs or refuses  →  3-of-5     │
      └─────────────────────────────────────────────┘
```

**Boundary 1** is Wasmer: untrusted code can't reach a key or a socket it was never
given. **Boundary 2** is the fleet: a fully owned node still can't gather signatures.
**Boundary 3** is the host: only it touches the real world, and only after 1 and 2 pass.

Each layer covers a genuinely different attack:

| Threat | Stopped by |
|---|---|
| Hijacked **application** (prompt injection, poisoned dependency) | Wasmer sandbox |
| Captured **device** (root, physical access) | 3-of-5 peer quorum |
| Stale policy replayed at a partitioned node | Version-monotonic manifest |

---

## Measured, not claimed

Probed against a live `wasmer-sdk` 0.2.1 sandbox:

| Probe | Result |
|---|---|
| Warm sandbox creation | 5 sandboxes in 0.002s — **~0.4 ms each** |
| Cold creation (first, pulls package) | 5.81 s |
| `socket.create_connection` under default policy | `OSError [Errno 58] Not supported` |
| Reading `/keys/node.ed25519` from the guest | `FileNotFoundError [Errno 44]` |
| Entire filesystem visible to the guest | `bin dev etc nix tmp usr workspace` |

Network denial and host-filesystem invisibility are the **default state**, not something
you configure. The 0.4 ms figure is what makes a fresh sandbox per action affordable.

A 5-node fleet on real Tenki microVMs, running the hijacked agent:

```
5/5 nodes completed in 18s — about $0.002 of Tenki credit
decisions across the fleet:  ALLOW 6   DENY 18   HELD 1
no agent reached the network, a key, or an effector on any node.
```

---

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.local.example .env.local     # then fill in your keys
```

Run a hijacked agent against a locked-down role, locally, no credentials needed:

```bash
.venv/bin/python -m sandglass.host --node node-02 --role monitor --scenario attack
```

```
[node-02] DENY  net.connect    api.exfil-relay.sh:443
      └─ capability not granted for role=monitor
[node-02] DENY  grid.actuate   breaker-B
      └─ capability not granted for role=monitor
[node-02] DENY  funds.transfer acct-9931
      └─ capability not granted for role=monitor

[node-02] audit chain verified=True  5 entries
[node-02] effector state: {'breaker-B': 'CLOSED', ...}
```

Launch a real fleet on Tenki microVMs (needs `TENKI_API_KEY`):

```bash
.venv/bin/python fleet/launch_tenki.py --nodes 5 --scenario attack
.venv/bin/python fleet/launch_tenki.py --nodes 5 --scenario benign   # the legit path
```

---

## Layout

| Path | What it is |
|---|---|
| `manifest.yaml` | The policy language: roles → capability sets, versioned and signed |
| `sandglass/policy.py` | Resolves a role into a concrete `create_sandbox()` config |
| `sandglass/host.py` | The trusted host: builds the sandbox, adjudicates every request |
| `sandglass/effector.py` | The only code that touches the real world |
| `sandglass/audit.py` | Hash-chained append-only log, written by the host |
| `guest/agent.py` | The **untrusted** guest — assume every line is attacker-controlled |
| `fleet/launch_tenki.py` | Launches the fleet on Tenki microVMs |

---

## Notes on the SDKs

Corrections found while building, against the published docs:

- The Wasmer Python SDK's real call is
  `await Wasmer().create_sandbox(packages=, files=, env=, network=, shell=)`.
  There is **no `mounts` parameter** — the guest sees only what `files` seeds.
- `Process` exposes only `id/kill/terminate/wait`, so there is no stdout streaming.
  The host loop is therefore turn-based, with **one fresh sandbox per turn** — which
  is the stronger design anyway, since no state carries between turns.
- The Tenki SDK has no file read/write; upload via
  `sb.exec("sh","-c","cat > f", input=...)`.
- Running Wasmer sandboxes locally is **free**. Credits burn on Edge hosting and
  registry package storage.

## Honest limitations

- Capabilities are scoped per **action**, not yet per **resource**, so
  `fs.read /keys/...` returns ALLOW even though the path is unreachable inside the
  sandbox. Path scoping is the next fix.
- The quorum protocol is not implemented yet; irreversible actions correctly fail
  safe as `HELD`.
- The sandbox does not stop an agent writing bad code. It guarantees the bad code's
  only path to production is a reviewable diff, and that secrets never leave.
- Nothing protects you if the manifest signing key is stolen. That is the root of trust.

## License

MIT
