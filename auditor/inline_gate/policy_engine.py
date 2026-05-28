"""OPA policy-engine client for the inline gate (PRD §9.4.1).

Loads the tenant's Rego into the OPA server (``PUT /v1/policies/<id>``) and evaluates the gate decision
per event (``POST /v1/data/auditor/gate/decision``) over a persistent ``httpx.AsyncClient``.

To keep the hot path fast, identical policy inputs are cached for a short TTL: the policy is a pure
function of its input, so repeated decisions (the steady-state case, §16.2) are served from memory in
sub-microseconds instead of crossing the network to OPA. Cache is cleared on ``load_policy``.
"""

from __future__ import annotations

import json
import time

import httpx

from auditor.logging import get_logger

log = get_logger("auditor.gate.opa")

DEFAULT_POLICY_ID = "auditor/gate"
_CACHE_MAX = 10_000


class OpaClient:
    def __init__(
        self, base_url: str, *, policy_path: str = "auditor/gate", cache_ttl_s: float = 5.0
    ) -> None:
        self._policy_path = policy_path
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=2.0)
        self._cache_ttl = cache_ttl_s
        self._cache: dict[str, tuple[dict, float]] = {}

    async def load_policy(self, rego: str, policy_id: str = DEFAULT_POLICY_ID) -> None:
        resp = await self._client.put(
            f"/v1/policies/{policy_id}", content=rego, headers={"Content-Type": "text/plain"}
        )
        resp.raise_for_status()
        self._cache.clear()  # a new policy invalidates cached decisions
        log.info("opa.policy_loaded", policy_id=policy_id)

    async def evaluate(self, event_input: dict) -> dict:
        """Return ``{"decision","reasons"}``. Raises on transport/HTTP error (caller fails closed)."""
        key = json.dumps(event_input, sort_keys=True, default=str)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and cached[1] > now:
            return cached[0]

        resp = await self._client.post(
            f"/v1/data/{self._policy_path}/decision", json={"input": event_input}
        )
        resp.raise_for_status()
        result = resp.json().get("result")
        decision = (
            {"decision": "ALLOW", "reasons": []}
            if not result
            else {"decision": result.get("decision", "ALLOW"), "reasons": list(result.get("reasons", []))}
        )
        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()
        self._cache[key] = (decision, now + self._cache_ttl)
        return decision

    async def health(self) -> bool:
        try:
            resp = await self._client.get("/health")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def aclose(self) -> None:
        await self._client.aclose()


__all__ = ["OpaClient", "DEFAULT_POLICY_ID"]
