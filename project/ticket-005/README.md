# Ticket 005: Adopt new-project standard 0.18.6

- **ID**: ticket-005
- **Owner**: agent:gemini under SESSION_EXECUTION_AUTHORIZATION
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-08-23

## Goal and scope

Adopt published `wellmanifest/new-project` 0.18.6 into `wellmanifest/authority-lifecycle` in one atomic transaction through `create_adoption_lock.py`.
Brings the host-agnostic contract (CLAUDE.md, GEMINI.md, Cursor rule, pre-commit hook, agent-hosts.json validator) and `governance / enforce` CI job.

## Acceptance criteria

- [ ] AC-01: `python3 .governance/agent_host_check.py --root .` → `GOV-AGENT-HOST-PASS` after `./scripts/install-agent-hosts.sh`.
- [ ] AC-02: `./project/governance-check.sh --actor agent` → `GOV-PASS`, all managed digests match lock.
- [ ] AC-03: `python3 -m unittest discover -s tests -v` passes; domain contracts unaffected.

## Participants

- Human participant: authorized via active session.
- Agent participant: [ai-gemini.md](ai-gemini.md)
