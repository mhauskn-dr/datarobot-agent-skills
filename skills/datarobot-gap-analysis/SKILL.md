---
name: datarobot-gap-analysis
description: >-
  Use when the user wants to assess whether an AI agent repository (DataRobot-built
  or not) is enterprise-ready, run a gap analysis / readiness scan against security,
  governance, reliability, or regulatory standards, score an agent against EU AI Act
  requirements, or find and fix gaps (secrets, unpinned models, missing CI, missing
  guardrails, over-permissioned identity, etc.) before deploying an agent to
  production. Works on any repository, not only ones built with DataRobot.
---

# DataRobot Gap Analysis

This skill scores any agent repository (GitHub URL or local path) against an
**enterprise-readiness framework** spanning **seven risk pillars** (Security, Identity,
AI Governance, Reliability, Ops, IT Conformance, Regulatory & Policy) across **four
evaluation layers**: deterministic scanning, LLM-based code reasoning, policy
conformance, and a regulatory layer driven by the org's own **DataRobot
risk-management policy** (EU AI Act by default), not a hardcoded checklist. It then
recommends a remediation path (**Patch**, **Hybrid**, or **Re-platform**) and can
apply the safe fixes itself. Regulatory gaps are satisfied by adopting the DataRobot
platform feature the policy calls for (deployment monitoring, GenAI Guards, RBAC,
Model Registry documentation), so their remediation usually points at converting the
architecture to deploy through DataRobot rather than patching code.

Unlike `datarobot-agent-assist`, this skill needs nothing but a repo. It does not
require an `agent_spec.md` or a prior design conversation, so it works equally well on
an agent someone built entirely outside DataRobot.

---

## Pre-requisite Check

Run in order before proceeding:

1. **Git** — run `git --version`. If missing, tell the user to install it and stop.
2. **Python** — run `python3 --version`. If missing or below 3.11, tell the user to
   install Python 3.11+ and stop.
3. **uv** — run `uv --version`. If missing, tell the user to install it from
   https://docs.astral.sh/uv/getting-started/installation/ and stop. All script
   invocations below use `uv run`, which resolves the script's own dependencies
   (PyYAML) automatically — no manual `pip install` step.

## Script Path Resolution

Resolve `<skill_scripts_dir>` once for the session: the `scripts/` subdirectory of the
directory containing this `SKILL.md`. Confirm it exists with
`ls <path_to_this_skill_dir>/scripts/`. Use the resolved absolute path for every
`<skill_scripts_dir>/...` reference below.

---

## Conversation Flow

### 1. Collect the target

Ask for:
- **Repo**: a GitHub URL or a local path. Private GitHub repos need `GITHUB_TOKEN` in
  the environment — if cloning fails with an auth error, ask for a token or suggest the
  user runs `git clone` themselves and passes the local path instead.
- **Ref** (optional): branch/tag/commit to check out.
- **Policy** (optional): a path to an org policy YAML (Python version floor, approved
  models, license denylist, base images, EU AI Act pack toggles). If the user doesn't
  have one, run with the built-in defaults and mention that a custom policy is
  supported — see [references/policy-authoring.md](references/policy-authoring.md).
### 2. Check for DataRobot credentials, run the assessment

`DATAROBOT_API_TOKEN` + `DATAROBOT_ENDPOINT` power two things: the 20 Layer-2
LLM-reasoning conditions (via the LLM Gateway; a `GAP_LLM_MODEL` override works for a
non-DataRobot provider) and the Layer-4 regulatory checks (fetching the org's
risk-management policy, then LLM-judging the repo against each required mitigation).
**If credentials are missing or invalid, invoke the `datarobot-setup` skill before
retrying**, do not print manual setup instructions. If the user explicitly wants a
fast pass, offer `--no-llm`: Layers 1 and 3 still run, and Layer 4 still fetches the
policy but reports its requirements as "required, not assessed" instead of judging
the code.

The regulatory layer is a pre-deployment check: it never inspects deployed entities,
it judges whether this repo would satisfy the org's policy if deployed. If DataRobot
risk-management isn't reachable (feature not enabled for the org, no matching
policy), Layer 4 reports nothing and says why in the report's Engine Notes; tell the
user plainly that regulatory coverage was not assessed rather than implying it
passed. There is no local fallback checklist.

Invoke via the **Monitor tool if available**, so the developer sees each layer complete
as a live notification instead of a silent multi-minute wait. Fall back to Bash (same
output, shown at the end) on harnesses without a Monitor-equivalent.

```
uv run <skill_scripts_dir>/run_gap_analysis.py <repo> \
  --ref <ref>                    # optional
  --policy <path>                # optional
  --out gap-report.md            # or --html gap-report.html for a browser-viewable report
  --no-llm                       # optional: skip LLM checks (Layer 2, and Layer 4 evidence judging)
```

Full flag reference (including `--fix`, `--select`, `--verify`, `--env-file`): run
`uv run <skill_scripts_dir>/run_gap_analysis.py --help`.

### 3. Summarize the report

Read the written report back and summarize for the user:
- The composite finding count and severity breakdown.
- The **remediation posture** (Patch / Hybrid / Re-platform) and its one-line rationale.
  See [references/remediation-paths.md](references/remediation-paths.md) if the user
  asks why a posture was assigned.
- The three or four highest-severity findings, in plain language, with file:line
  evidence — never invent a finding; if a condition was skipped (e.g. a relational
  check missing one of its file groups), say so rather than guessing.

- Any regulatory (`POL-DR-*`) findings deserve their own framing: they come from the
  org's own DataRobot risk-management policy, and each one names the DataRobot
  platform feature that satisfies it. Propose adapting the architecture to deploy
  through DataRobot and adopt those features (that is how the org complies with its
  EU AI Act policy), rather than treating them as code bugs to patch.

The developer can ask follow-up questions in this same conversation (why a condition
fired, what a specific fix changes, what a risk-management mitigation requires); the
skill running as a normal chat turn already grounds those answers in the same report
and codebase, no separate Q&A surface needed.

### 4. Offer remediation

State the posture and let it drive the offer — the unit of decision is the *gap*, not
the whole agent:

- **PATCH** → offer to re-run with `--fix`. Plumbing fixes (secrets → env vars, model
  pins, CI/logging scaffolding) are surgical and safe.
- **HYBRID** → offer `--fix` for the plumbing now; flag which findings are structural
  and will need a targeted human review or a Re-platform pass later.
- **RE-PLATFORM** → too many structural gaps to patch safely in place. Recommend the
  guided extraction path (below) instead of leading with `--fix`.

Ask **which** findings to fix: all auto-fixable, a selected subset (`--select
SEC-002,ITA-003`), or none. A blanket "fix everything" only ever applies
plumbing-classified fixes; business-logic fixes must be named explicitly.

**Safety rails, never skip these:**
- Fixes land on a new `gap-fixes/<timestamp>` branch in the cloned workspace — never
  the default branch, never in place.
- Nothing is pushed or opened as a PR without a **separate, explicit** approval after
  the developer has reviewed the diff.
- After `--fix`, offer `--verify` to re-score the fix branch and show a before/after
  deploy-readiness verdict.

### 5. Re-platform hand-off (structural gaps)

When the posture is Re-platform (or a post-fix rescore still shows structural gaps),
run the script with `--fix` omitted and instead point the developer at the engine's
guided extraction: it lifts the agent's business logic (prompts, tools, decision flow)
into a reviewable `agent_spec.md`. **Show the spec and get explicit approval before
anything is scaffolded.** Once approved, the natural next step is the
`datarobot-agent-assist` skill (design/code flow) to scaffold a governed replacement
from that spec; install it if it isn't already, rather than trying to scaffold from
inside this skill.

Regulatory (`POL-DR-*`) findings feed this same path: a DataRobot-scaffolded
replacement gets the platform features those mitigations require (logging, tracing,
monitoring, guards, RBAC) largely by construction, so re-platforming is usually how
a repo full of unsatisfied risk-management mitigations becomes compliant.

---

## Reference material

- [references/pillars-and-layers.md](references/pillars-and-layers.md) — the 7-pillar /
  4-layer model, condition ID prefixes, and severity scale, to cite accurately in
  conversation.
- [references/policy-authoring.md](references/policy-authoring.md) — how a policy file
  overrides defaults, how to add a new condition to the taxonomy without a code
  change, and how the regulatory layer sources its checks from DataRobot
  risk-management.
- [references/remediation-paths.md](references/remediation-paths.md) — how the
  Patch/Hybrid/Re-platform posture is computed, for when a user asks "why."
