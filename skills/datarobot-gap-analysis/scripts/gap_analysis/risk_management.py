# Copyright (c) 2026 DataRobot, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Layer 4 (regulatory): the org's live DataRobot risk-management policy
decides WHAT is required, and an LLM judges whether the repo satisfies it.

There is no gap-analysis-defined regulatory checklist. The policy named by
`regulatory.policy_name` is fetched from DataRobot risk-management, and every
mitigation it requires (union across its risk tiers, the strictest honest
reading for a repo that isn't deployed anywhere yet) is assessed against the
repo the same way Layer 2 assesses its conditions: the LLM reads the relevant
files (per-type `files_glob` in risk_management_mitigations.yaml) and judges
whether there is evidence the mitigation is implemented, or wired up to be
provided by DataRobot at deployment time. This is deliberately a
pre-deployment, "would this be compliant if we deployed it" check; it does not
inspect deployed entities.

Unsatisfied (or unverifiable) required mitigations become findings. Satisfying
almost all of them means adopting the corresponding DataRobot platform feature
(deployment monitoring, GenAI Guards, RBAC, Model Registry documentation,
...), not patching code in place, that's why every dynamically-generated
finding is `fix_type="advisory"` and `structural=True` unless the mitigation's
own metadata says otherwise (currently only `ai_literacy`, a staff-training
requirement, isn't).

Degradation, the same "skipped-with-reason, never guess" philosophy as every
other layer: if DataRobot risk-management isn't reachable (no credentials,
feature not enabled for the org, no matching policy), Layer 4 finds nothing
and says why; if no LLM client is configured (--no-llm, or no model creds),
required mitigations are still fetched and reported, but as "required, not
assessed" rather than confirmed gaps.

The risk-management API (MLOps/risk_management in the DataRobot platform
repo) is not yet publicly released as of this writing: routes are gated
behind the MLOPS_GOVERNANCE_COMPLIANCE feature flag and annotated
public_as_of=FUTURE, and there is no client for it in the public `datarobot`
SDK (checked directly against datarobot==3.18.0). This module calls it over
plain HTTP with stdlib urllib, no new dependency, following the standard
DataRobot Public API v2 convention of mounting under whatever
DATAROBOT_ENDPOINT already points at. Confirm paths against the live OpenAPI
spec once the feature is GA; a not-yet-public API carries no compatibility
guarantee.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from . import paths
from .inventory import files_matching
from .llm import LLMClient, parse_json
from .models import Finding, Severity

EU_AI_ACT_POLICY_NAME = "EU AI Act"
_TIMEOUT_SECONDS = 15
_MAX_FILES = 12  # cap files fed per mitigation, mirrors Layer 2's cap
_PROMPT_FILE = "prompts/risk-management-mitigation.md"
_DEFAULT_MAX_WORKERS = 4
_SUBMIT_STAGGER_SECONDS = 0.25


class RiskManagementClient:
    """Minimal stdlib HTTP client for the DataRobot risk-management API."""

    def __init__(self, endpoint: str, token: str):
        self.endpoint = endpoint.rstrip("/")
        self.token = token

    def get(self, path: str) -> Any | None:
        """GET a relative path under the risk-management API. None on any failure."""
        url = f"{self.endpoint}/{path.lstrip('/')}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None


def _drconfig_credentials() -> tuple[str | None, str | None]:
    """(endpoint, token) from the dr CLI / SDK config file, or (None, None)."""
    cfg = Path.home() / ".config" / "datarobot" / "drconfig.yaml"
    try:
        data = yaml.safe_load(cfg.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return None, None
    return data.get("endpoint"), data.get("token")


def get_client() -> RiskManagementClient | None:
    """Return a client, or None if credentials aren't configured.

    Env vars win; otherwise fall back to the dr CLI's config file, so a
    `dr auth login`-ed machine needs no DATAROBOT_* exports for Layer 4.
    """
    endpoint = os.environ.get("DATAROBOT_ENDPOINT")
    token = os.environ.get("DATAROBOT_API_TOKEN")
    if not endpoint or not token:
        cfg_endpoint, cfg_token = _drconfig_credentials()
        endpoint = endpoint or cfg_endpoint
        token = token or cfg_token
    if not endpoint or not token:
        return None
    return RiskManagementClient(endpoint, token)


def _as_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", [])
    return []


def fetch_mitigation_catalog(
    client: RiskManagementClient,
) -> list[dict[str, Any]] | None:
    """GET the live catalog of mitigation method types. None on any failure."""
    data = client.get("mitigationMethods/")
    return None if data is None else _as_list(data)


def fetch_policy_by_name(
    client: RiskManagementClient, name: str
) -> dict[str, Any] | None:
    """Find a risk policy by name (e.g. "EU AI Act"). None if not found or unreachable.

    Does not disambiguate multiple policies sharing a name, returns the first
    match. An org with more than one policy under the same name needs a more
    precise lookup than this; treat that as a known gap, not a solved case.
    """
    data = client.get("riskPolicies/")
    if data is None:
        return None
    for policy in _as_list(data):
        if policy.get("name") == name:
            return policy
    return None


def required_mitigation_types(policy: dict[str, Any]) -> set[str]:
    """Every mitigation method type the policy requires, union across all risk
    tiers. Nothing is deployed or assessed yet, so no tier can be assumed; the
    union is the strictest honest reading for a pre-deployment check."""
    types: set[str] = set()
    for section in policy.get("mitigations", []) or []:
        for method in section.get("methods", []) or []:
            method_type = method.get("type")
            if method_type:
                types.add(method_type)
    return types


def load_mitigation_metadata(
    path: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Load risk_management_mitigations.yaml, keyed by mitigation_type."""
    p = Path(path) if path else paths.risk_management_mitigations_file()
    data = yaml.safe_load(p.read_text()) or {}
    return {m["mitigation_type"]: m for m in data.get("mitigations", [])}


def validate_metadata_against_catalog(
    metadata: dict[str, dict[str, Any]], catalog: list[dict[str, Any]]
) -> dict[str, list[str]]:
    """Compare the shipped metadata against a live catalog. Returns drift, never raises."""
    catalog_types = {c["type"] for c in catalog if "type" in c}
    known_types = set(metadata)
    return {
        "new_in_catalog": sorted(catalog_types - known_types),
        "removed_from_catalog": sorted(known_types - catalog_types),
    }


def _condition_id(mitigation_type: str) -> str:
    return "POL-DR-" + mitigation_type.upper().replace("_", "-")


def _gather_files(
    workspace: Path, inventory: dict[str, Any], globs: list[str], max_bytes: int
) -> list[tuple[str, str]]:
    rels = files_matching(inventory, globs)[:_MAX_FILES]
    out = []
    for rel in rels:
        try:
            data = (workspace / rel).read_text(errors="ignore")
        except OSError:
            continue
        if len(data.encode("utf-8", "ignore")) > max_bytes:
            data = data[:max_bytes] + "\n…[truncated]…"
        out.append((rel, data.replace("\x00", "")))
    return out


def _finding_for_mitigation(
    mitigation_type: str,
    meta: dict[str, Any],
    item: dict[str, Any] | None,
) -> Finding:
    """Build a Layer-4 Finding for one required-but-unsatisfied mitigation.

    `item` is the LLM's finding payload when the gap was confirmed by evidence
    assessment; None when the requirement couldn't be assessed (no LLM, no
    matching files, organizational-only), in which case the finding is framed
    as "required by policy, not verified" rather than a confirmed gap.
    """
    assessed = item is not None
    item = item or {}
    explanation = item.get("explanation") or (
        "Required by the org's DataRobot risk-management policy; not assessed "
        "against this repo, so treat as unresolved rather than passed."
    )
    remediation = f"{meta['remediation']} ({meta['datarobot_feature']})"
    return Finding(
        condition_id=_condition_id(mitigation_type),
        pillar="POL",
        severity=Severity(meta["default_severity"]),
        title=f"DataRobot risk-management: {meta['title']} not satisfied",
        file=item.get("file"),
        line=item.get("line"),
        evidence=str(item.get("evidence", "") or f"mitigation type: {mitigation_type}")[
            :500
        ],
        explanation=str(explanation),
        remediation=remediation,
        fix_type="advisory",
        fix_risk="none",
        confidence=item.get("confidence", "high") if assessed else "medium",
        layer=4,
        detector=f"risk_management:{mitigation_type}",
        structural=bool(meta["structural"]),
    )


def _assess_mitigation(
    llm: LLMClient,
    workspace: Path,
    inventory: dict[str, Any],
    mitigation_type: str,
    meta: dict[str, Any],
    prompt: str,
    contract: str,
    max_bytes: int,
) -> tuple[str, dict[str, Any] | None, str | None]:
    """LLM-judge one mitigation against the repo.

    Returns (verdict, finding_item, skip_reason): verdict is "pass" | "gap" |
    "skipped"; finding_item is the LLM's finding payload when verdict is "gap".
    """
    files = _gather_files(workspace, inventory, meta.get("files_glob") or [], max_bytes)
    if not files:
        return "skipped", None, "no files matched this mitigation's globs"
    system = (
        f"{prompt}\n\n---\n# Mitigation under assessment\n"
        f"- id: {_condition_id(mitigation_type)}\n"
        f"- requirement: {meta['title']}\n"
        f"- satisfied by (at deployment): {meta['datarobot_feature']}\n"
        f"- what counts as evidence: {meta['evidence']}\n"
        f"\n---\n# Output contract\n{contract}\n\n"
        f"You are checking condition {_condition_id(mitigation_type)}. "
        "Return ONLY the JSON object."
    )
    user = "\n\n".join(f"=== FILE: {rel} ===\n{content}" for rel, content in files)
    try:
        result = parse_json(llm.complete(system, user))
    except Exception as e:  # noqa: BLE001
        return "skipped", None, f"LLM/parse error: {e}"
    status = result.get("status", "found")
    if status == "not_found":
        return "pass", None, None
    if status == "skipped":
        return "skipped", None, result.get("skip_reason", "model reported skipped")
    items = result.get("findings") or [{}]
    return "gap", items[0], None


def run_dynamic_layer4(
    llm_client: LLMClient | None,
    workspace: str | Path,
    inventory: dict[str, Any],
    policy_name: str = EU_AI_ACT_POLICY_NAME,
    max_bytes: int = 200_000,
    mitigation_metadata_path: str | Path | None = None,
    progress: Any = None,
    max_workers: int = _DEFAULT_MAX_WORKERS,
) -> tuple[list[Finding], list[dict[str, str]], list[str]]:
    """Run Layer 4: fetch the org's policy, LLM-assess each required mitigation.

    Returns (findings, coverage, notes). `coverage` lists every mitigation
    considered, not just the ones that became findings, {mitigation_type,
    title, status}, status one of "pass" | "gap" | "not_assessed" |
    "unknown_type" (a live mitigation type this skill's metadata doesn't
    recognize yet, see validate_risk_management_mapping.py). Never raises:
    any failure here just means an empty result with a reason in `notes`.
    """
    notes: list[str] = []

    def _tick(msg: str) -> None:
        if progress:
            progress(msg)

    client = get_client()
    if client is None:
        notes.append(
            "Layer 4 (DataRobot risk-management) skipped, no DataRobot "
            "credentials found (DATAROBOT_API_TOKEN/DATAROBOT_ENDPOINT env "
            "vars, or the dr CLI config written by `dr auth login`)."
        )
        return [], [], notes

    policy = fetch_policy_by_name(client, policy_name)
    if policy is None:
        notes.append(
            f"Layer 4 (DataRobot risk-management) skipped, no policy named "
            f"'{policy_name}' was reachable (the feature may not be enabled "
            "for this org)."
        )
        return [], [], notes

    required = sorted(required_mitigation_types(policy))
    metadata = load_mitigation_metadata(mitigation_metadata_path)
    workspace = Path(workspace)
    prompt = contract = None
    if llm_client is not None:
        prompt = paths.resolve(_PROMPT_FILE).read_text()
        contract = (paths.prompts_dir() / "_contract.md").read_text()
    else:
        notes.append(
            "Layer 4: no LLM client configured, required mitigations are "
            "reported as not assessed instead of judged against the repo."
        )

    # LLM-assess all judgeable mitigations in parallel; each assessment is an
    # independent (prompt, files) completion, so only the aggregation below
    # needs to stay in `required` order for deterministic output.
    assessable = [
        mt
        for mt in required
        if metadata.get(mt)
        and metadata[mt].get("files_glob")
        and llm_client is not None
    ]
    assessed: dict[str, tuple[str, dict[str, Any] | None, str | None]] = {}
    if assessable:
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
            futures = {}
            for i, mt in enumerate(assessable):
                if i:
                    time.sleep(_SUBMIT_STAGGER_SECONDS)
                futures[
                    pool.submit(
                        _assess_mitigation,
                        llm_client,
                        workspace,
                        inventory,
                        mt,
                        metadata[mt],
                        prompt,
                        contract,
                        max_bytes,
                    )
                ] = mt
            for future in as_completed(futures):
                mt = futures[future]
                done += 1
                assessed[mt] = future.result()
                _tick(
                    f"Layer 4 (risk-management): {mt} done [{done}/{len(assessable)}]"
                )

    findings: list[Finding] = []
    coverage: list[dict[str, str]] = []
    for mitigation_type in required:
        meta = metadata.get(mitigation_type)
        if meta is None:
            coverage.append(
                {
                    "mitigation_type": mitigation_type,
                    "title": mitigation_type,
                    "status": "unknown_type",
                }
            )
            notes.append(
                f"Layer 4: DataRobot risk-management requires mitigation type "
                f"'{mitigation_type}', which isn't in this skill's assessment "
                "metadata yet (run validate_risk_management_mapping.py to confirm)."
            )
            continue

        verdict, item, skip_reason = "skipped", None, None
        if not meta.get("files_glob"):
            skip_reason = "organizational requirement, not assessable from code"
        elif mitigation_type in assessed:
            verdict, item, skip_reason = assessed[mitigation_type]

        if verdict == "pass":
            coverage.append(
                {
                    "mitigation_type": mitigation_type,
                    "title": meta["title"],
                    "status": "pass",
                }
            )
            continue

        if verdict == "gap":
            findings.append(_finding_for_mitigation(mitigation_type, meta, item))
            coverage.append(
                {
                    "mitigation_type": mitigation_type,
                    "title": meta["title"],
                    "status": "gap",
                }
            )
            continue

        # Required but not assessable right now: still surfaced, never silently
        # passed, but framed as unverified rather than a confirmed gap.
        if skip_reason:
            notes.append(f"Layer 4: {mitigation_type} not assessed, {skip_reason}.")
        findings.append(_finding_for_mitigation(mitigation_type, meta, None))
        coverage.append(
            {
                "mitigation_type": mitigation_type,
                "title": meta["title"],
                "status": "not_assessed",
            }
        )

    if findings:
        _tick(
            f"{len(findings)} mitigation(s) required by '{policy_name}' are "
            "unsatisfied or unverified."
        )
    return findings, coverage, notes
