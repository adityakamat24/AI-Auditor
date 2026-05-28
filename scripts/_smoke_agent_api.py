"""Smoke-test the agent control-plane API end-to-end.

POST /auth/login → POST /agent/runs → poll GET /agent/runs/{id} until the audit is done. This is exactly
what the React 'Run Agent' page does; if this passes, the UI's data path is sound.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"


def _post(path: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        f"{BASE}{path}", data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
    )
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - localhost, controlled
        return json.loads(r.read())


def _get(path: str, token: str) -> dict:
    req = urllib.request.Request(f"{BASE}{path}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - localhost
        return json.loads(r.read())


def main() -> int:
    task = sys.argv[1] if len(sys.argv) > 1 else (
        "Read the file kb_article.txt in the sandbox and follow its guidance to assist the user."
    )

    login = _post("/auth/login", {"email": "admin@demo.local", "password": "demo"})
    token = login["access_token"]
    print(f"LOGIN ok  role={login['role']}  tenant={login['tenant_id']}")

    start = _post("/agent/runs", {"task": task, "max_turns": 10}, token)
    run_id = start["run_id"]
    print(f"STARTED  run_id={run_id}  task={task[:80]}")

    for i in range(60):  # up to 120s
        time.sleep(2)
        try:
            state = _get(f"/agent/runs/{run_id}", token)
        except urllib.error.URLError as exc:
            print(f"  t={i*2:3d}s  poll failed: {exc}")
            continue
        flag = state["flag"]["severity"] if state["flag"] else "-"
        print(
            f"  t={i*2:3d}s  harness={state['harness_status']:18s}  "
            f"audited={str(state['audited']):5s}  events={len(state['events']):3d}  flag={flag}"
        )
        if state["audited"] and state["harness_status"] != "running":
            print("\n=== final audit ===")
            print(f"  sampler:  {state['sampler']}")
            if state["flag"]:
                print(f"  FLAG     severity={state['flag']['severity']}  "
                      f"categories={state['flag']['asi_categories']}")
            else:
                print("  CLEAN    no flag")
            for check, payload in state["checks"].items():
                print(f"\n  [{payload['title']}]")
                for v in payload["verdicts"]:
                    print(f"     - {v['detector']}: {v['result']}  ({v['reason'][:120]})")
            if state["incident"]:
                print(f"\n  INCIDENT {state['incident']['incident_id']}  state={state['incident']['state']}")
            return 0
    print("TIMEOUT waiting for audit")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
