# claude-context/

Shared, committed memory for Claude Code on this repo. Every teammate's sessions read from and write to this folder, so context survives across sessions, machines and people.

| File | What goes in it | Loaded |
|---|---|---|
| `STATE.md` | Where the project stands now: what's done, in progress, next | Every session (imported by `CLAUDE.md`) |
| `DECISIONS.md` | Append-only log of decisions the team made | Every session |
| `GOTCHAS.md` | Pitfalls that cost time and their fixes | Every session |
| `sessions/` | One log per Claude Code session | Latest few printed by the SessionStart hook |

## How it's enforced

- `.claude/hooks/session-start.sh` (SessionStart) — prints the branch, recent commits and the newest session logs into Claude's context.
- `.claude/hooks/context-check.sh` (Stop) — if files outside `claude-context/` changed more recently than anything inside it, Claude is told to update the context before it can finish. It only blocks once per stop, so it can't loop.

Both are registered in `.claude/settings.json`. On Windows they run through Git Bash (`bash` must be on PATH).

## Rules

- One session file per session, named `YYYY-MM-DD_<author>_<topic>.md`. Don't edit other people's session files — that's what keeps merges conflict-free.
- `DECISIONS.md` is append-only. To change a decision, add a new entry that supersedes the old one.
- Facts only: what happened, what was decided, what broke. No secrets, keys, passwords or personal data.
- Keep `STATE.md` short (it's loaded every session). Move detail into session logs.
- When `sessions/` gets long, summarize old logs into `sessions/ARCHIVE.md` and delete the originals.
