#!/usr/bin/env bash
# Layout-independent installer for cloud-offensive-security.
# Locates any existing install by frontmatter name, backs it up, installs, and
# preserves operator-edited files as .new. Kali-safe: no pip, stdlib scripts only.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="cloud-offensive-security"
SKILLS_ROOT="${HERMES_SKILLS:-$HOME/.hermes/skills}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

# Find an existing install by frontmatter name (layout-independent).
EXISTING=""
if [ -d "$SKILLS_ROOT" ]; then
  while IFS= read -r f; do
    if grep -qE "^name:[[:space:]]*$NAME\$" "$f" 2>/dev/null; then
      EXISTING="$(cd "$(dirname "$f")" && pwd)"; break
    fi
  done < <(find "$SKILLS_ROOT" -maxdepth 3 -name SKILL.md 2>/dev/null)
fi
DEST="${EXISTING:-$SKILLS_ROOT/$NAME}"

# Fingerprint the payload (for the release manifest).
manifest() {
  ( cd "$1" && find . -type f ! -name RELEASE_MANIFEST -print0 \
      | sort -z | xargs -0 sha256sum ) 2>/dev/null
}

echo "source : $SRC"
echo "dest   : $DEST"
[ -n "$EXISTING" ] && echo "note   : updating existing install" || echo "note   : fresh install"

if [ "$APPLY" -eq 0 ]; then
  echo
  echo "DRY RUN. Files that would be installed:"
  ( cd "$SRC" && find . -type f ! -path './.git/*' ! -path '*/__pycache__/*' ! -name '*.pyc' | sort | sed 's/^/  /' )
  echo
  echo "Re-run with:  bash install.sh --apply"
  exit 0
fi

mkdir -p "$DEST"
if [ -n "$EXISTING" ]; then
  BK="$DEST.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$DEST" "$BK"
  echo "backup : $BK"
fi

# Copy, preserving operator-edited config/state files as .new instead of clobbering.
PRESERVE_GLOBS=( "authorization.json" "*.local.md" )
while IFS= read -r rel; do
  s="$SRC/$rel"; d="$DEST/$rel"
  mkdir -p "$(dirname "$d")"
  keep=0
  for g in "${PRESERVE_GLOBS[@]}"; do
    case "$(basename "$rel")" in $g) keep=1;; esac
  done
  if [ "$keep" -eq 1 ] && [ -e "$d" ]; then
    cp -a "$s" "$d.new"; echo "preserve: $rel (new -> $rel.new)"
  else
    cp -a "$s" "$d"
  fi
done < <( cd "$SRC" && find . -type f ! -path './.git/*' ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name RELEASE_MANIFEST | sed 's|^\./||' )

manifest "$DEST" > "$DEST/RELEASE_MANIFEST"
echo "manifest: $DEST/RELEASE_MANIFEST ($(wc -l < "$DEST/RELEASE_MANIFEST") files)"

echo
echo "Installed. Next steps:"
echo "  1. Reload Hermes skills / start a new session (skills cache at session start)."
echo "  2. Run the acknowledgement (human, interactive):  bash $DEST/scripts/acknowledge.sh"
echo "  3. Verify:  python3 $DEST/scripts/self_test.py"
