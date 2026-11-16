# 2026-11-16 — Claude Code context system

**Author:** andrew  
**Area:** repo tooling

## Goal
Add CLAUDE.md and a shared folder where Claude Code keeps project context across sessions.

## Done
- `CLAUDE.md` (project rules, stack, layout, DB conventions, ownership, context-system instructions).
- `claude-context/` with README, STATE, DECISIONS, GOTCHAS, session template.
- `.claude/settings.json` + `.claude/hooks/session-start.sh` (prints context) and `context-check.sh` (Stop hook: requires a context update when files changed). Hooks are portable to macOS bash 3.2.
- `CLAUDE.md`: added a "Skills (pick by prompt)" table mapping prompt types to skills, plus skills not to use.
- Pre-push cleanup: added `.gitattributes` (LF for .sh/.sql/Dockerfile so Windows checkouts don't break containers); `.gitignore` ignores `.claude/settings.local.json`, dropped the docker-compose line; README lists `claude-context/` and `.claude/`.

## Verified
- Hook scripts: `bash -n` OK; stop hook returns 2 when work is newer than context, 0 after context is updated or when `stop_hook_active` is true. Not yet run inside a real Claude Code session.
- `database/init/001`–`007` loaded cleanly into a scratch PostgreSQL 16.15: 25 tables, 9 views, 10 `*_svc` logins.

## Decisions
- No EJBCA; own implementation only.
- Context lives in `claude-context/`, committed to git.

## Left open / next
- Run one Claude Code session on Windows to confirm both hooks fire (needs Git Bash on PATH).
