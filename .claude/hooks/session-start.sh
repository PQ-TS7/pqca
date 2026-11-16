#!/usr/bin/env bash
# SessionStart hook: anything printed here is added to Claude's context.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
dir="claude-context/sessions"

echo "=== PQ-CA context ==="
echo "Branch: $(git branch --show-current 2>/dev/null || echo unknown)"
echo
echo "Recent commits:"
git log --oneline -8 2>/dev/null || echo "(no git history)"
echo

[ -d "$dir" ] || exit 0
logs=$(ls -1 "$dir"/*.md 2>/dev/null | grep -v -e '_TEMPLATE.md$' -e 'ARCHIVE.md$' | sort -r)
echo "Session logs: $(printf '%s\n' "$logs" | grep -c .) total. Newest first:"
printf '%s\n' "$logs" | head -n 10 | sed 's/^/  /'
echo

for f in $(printf '%s\n' "$logs" | head -n 3); do
  echo "----- $f -----"
  head -n 60 "$f"
  echo
done
echo "Before finishing a session that changes files: add a session log and update STATE/DECISIONS/GOTCHAS as needed (see CLAUDE.md)."
exit 0
