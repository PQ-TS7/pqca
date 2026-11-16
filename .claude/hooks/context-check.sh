#!/usr/bin/env bash
# Stop hook: if files outside claude-context/ changed more recently than anything
# inside it, block once and ask Claude to update the context. Exit 2 = block (stderr goes to Claude).
input="$(cat)"
# Already blocked once for this stop -> let it finish (prevents loops).
echo "$input" | grep -Eq '"stop_hook_active"[[:space:]]*:[[:space:]]*true' && exit 0

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

# File mtime in epoch seconds (GNU stat on Linux/Git Bash, BSD stat on macOS)
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }

latest_work=0; latest_ctx=0
while IFS= read -r line; do
  path="${line:3}"; path="${path#\"}"; path="${path%\"}"
  case "$path" in *" -> "*) path="${path##* -> }";; esac
  [ -e "$path" ] || continue
  if [ -d "$path" ]; then
    t=0
    while IFS= read -r f; do m=$(mtime "$f"); [ "$m" -gt "$t" ] && t=$m; done < <(find "$path" -type f 2>/dev/null)
  else
    t=$(mtime "$path")
  fi
  case "$path" in
    claude-context/*) [ "$t" -gt "$latest_ctx" ] && latest_ctx=$t ;;
    *)                [ "$t" -gt "$latest_work" ] && latest_work=$t ;;
  esac
done < <(git status --porcelain 2>/dev/null)

# No uncommitted work, or context already updated after the latest work change.
[ "$latest_work" -eq 0 ] && exit 0
[ "$latest_ctx" -ge "$latest_work" ] && exit 0

cat >&2 <<MSG
Files changed this session but claude-context/ wasn't updated after them.
Before finishing:
  1. Add claude-context/sessions/$(date +%F)_<author>_<topic>.md (copy _TEMPLATE.md; author = git user.name).
  2. Update STATE.md / DECISIONS.md / GOTCHAS.md if anything there changed.
Only record what actually happened or what the user decided. If the user said to skip context, just finish.
MSG
exit 2
