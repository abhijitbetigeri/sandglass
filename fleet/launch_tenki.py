"""Launch a Sandglass fleet on Tenki microVMs. This is what spends Tenki credits.

Each node is a disposable Linux VM running one Sandglass host, which in turn
runs its agent inside a Wasmer sandbox. Tenki gives us what we cannot fake on a
laptop: real nodes to partition, kill, snapshot and replay.

    python fleet/launch_tenki.py --nodes 3
    python fleet/launch_tenki.py --nodes 5 --scenario attack

Verified against tenki 1.0.6. Notes from the real SDK:
  * Client.create(...) takes cpu_cores / memory_mb / allow_outbound / tags / env.
  * Sandbox has NO read()/write() — file transfer goes through exec(input=...).
  * Client.get_usage() reports the workspace quota. Default max_concurrent_jobs
    is 5, so --nodes above that queues rather than running in parallel. Ask
    Tenki to raise the cap before attempting a large-fleet scaling demo.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from sandglass.config import ENV_FILE, load_env, tenki_token  # noqa: E402

load_env()

try:
    import tenki
except ImportError as exc:  # pragma: no cover
    raise SystemExit("tenki not installed — run: pip install tenki") from exc

ROLES = ["operator", "supervisor", "supervisor", "monitor", "builder"]
HOURLY = {"nano": 0.08, "small": 0.17, "medium": 0.33}
SIZES = {
    "nano": dict(cpu_cores=1, memory_mb=1024),
    "small": dict(cpu_cores=2, memory_mb=4096),
    "medium": dict(cpu_cores=4, memory_mb=8192),
}
FILES = [
    "manifest.yaml",
    "sandglass/__init__.py",
    "sandglass/config.py",
    "sandglass/policy.py",
    "sandglass/audit.py",
    "sandglass/effector.py",
    "sandglass/host.py",
    "guest/agent.py",
]


def upload(sb, rel: str, data: bytes) -> None:
    """No file API on the SDK — stream it in over exec stdin."""
    sb.exec("sh", "-c", f"mkdir -p $(dirname '{rel}') && cat > '{rel}'", input=data, check=True)


def provision(index: int, size: str, scenario: str, verbose: bool) -> tuple[str, str, bool]:
    node_id = f"node-{index:02d}"
    role = ROLES[index % len(ROLES)]
    sb = None
    try:
        sb = tenki.Sandbox.create(name=f"sandglass-{node_id}", tags=["sandglass"], **SIZES[size])
        sb.wait_ready(timeout=180)

        for rel in FILES:
            upload(sb, rel, (REPO / rel).read_bytes())

        # The node needs the Wasmer SDK to build Boundary 1 around its agent.
        sb.exec("sh", "-c", "pip install --quiet --break-system-packages wasmer-sdk pyyaml "
                            "|| pip install --quiet wasmer-sdk pyyaml", timeout=600)

        res = sb.exec(
            "python3", "-m", "sandglass.host",
            "--node", node_id, "--role", role, "--scenario", scenario,
            "--manifest", "manifest.yaml", "--guest", "guest/agent.py",
            timeout=600,
        )
        out = (res.stdout or "") if isinstance(res.stdout, str) else (res.stdout or b"").decode()
        err = (res.stderr or "") if isinstance(res.stderr, str) else (res.stderr or b"").decode()
        text = out + ("\n" + err if err.strip() else "")
        if verbose:
            print(f"\n----- {node_id} ({role}) -----\n{text.strip()}")
        return node_id, text, True
    except Exception as exc:
        return node_id, f"{type(exc).__name__}: {exc}", False
    finally:
        if sb is not None:
            try:
                sb.terminate()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(description="Launch a Sandglass fleet on Tenki.")
    ap.add_argument("--nodes", type=int, default=3)
    ap.add_argument("--size", choices=sorted(SIZES), default="nano")
    ap.add_argument("--scenario", choices=["benign", "attack"], default="attack")
    ap.add_argument("--concurrency", type=int, default=0, help="0 = use the workspace quota")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not tenki_token():
        sys.exit(f"no Tenki key found — add TENKI_API_KEY to {ENV_FILE}")

    client = tenki.Client()
    ident = client.who_am_i()
    quota = {u.key: u for u in client.get_usage()}
    cap = quota["max_concurrent_jobs"].max if "max_concurrent_jobs" in quota else 5
    conc = args.concurrency or cap

    print(f"workspace: {ident.workspaces[0].name}   concurrent-session cap: {cap}")
    if args.nodes > cap:
        print(f"note: {args.nodes} nodes requested but only {cap} may run at once — "
              f"they will run in waves of {conc}.")

    t0 = time.time()
    print(f"launching {args.nodes}x {args.size} ({args.scenario} scenario)…\n")

    results = []
    with cf.ThreadPoolExecutor(max_workers=conc) as pool:
        futs = [pool.submit(provision, i, args.size, args.scenario, not args.quiet)
                for i in range(args.nodes)]
        for fut in cf.as_completed(futs):
            results.append(fut.result())

    elapsed = time.time() - t0
    spend = args.nodes * (elapsed / 3600) * HOURLY[args.size]
    ok = [r for r in results if r[2]]
    blob = "\n".join(r[1] for r in results)
    allows, denies, helds = blob.count("ALLOW "), blob.count("DENY "), blob.count("HELD ")

    print(f"\n{'='*62}")
    print(f"{len(ok)}/{args.nodes} nodes completed in {elapsed:.0f}s "
          f"— about ${spend:.3f} of Tenki credit")
    print(f"decisions across the fleet:  ALLOW {allows}   DENY {denies}   HELD {helds}")
    for node_id, text, good in sorted(results):
        if not good:
            print(f"  {node_id} FAILED: {text.splitlines()[0][:120]}")
    if denies and not any("EXFIL SOCKET OPENED" in r[1] or "STOLE KEY" in r[1] for r in results):
        print("no agent reached the network, a key, or an effector on any node.")


if __name__ == "__main__":
    main()
