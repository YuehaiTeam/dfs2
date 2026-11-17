#!/usr/bin/env bash
# Rebuild a git history with credentials stripped. git fetch / commit / push stay here;
# dfs2 redact does the text rewrite.
#
#   mirror.sh --source /path/to/real-clone --target /tmp/mirror \
#     [--branch main] [--push URL] [--push-branch main]
#
# DFS2 defaults to `dfs2` on PATH.
# Exit: 0 ok, 2 redact found a leftover credential (nothing pushed), 3 usage.

set -euo pipefail

SOURCE=""
TARGET=""
BRANCH="main"
PUSH=""
PUSH_BRANCH=""
DFS2="${DFS2:-dfs2}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE=$2; shift 2 ;;
    --target) TARGET=$2; shift 2 ;;
    --branch) BRANCH=$2; shift 2 ;;
    --push) PUSH=$2; shift 2 ;;
    --push-branch) PUSH_BRANCH=$2; shift 2 ;;
    *) echo "error: unknown argument $1" >&2; exit 3 ;;
  esac
done

if [[ -z "$SOURCE" || -z "$TARGET" ]]; then
  echo "error: --source and --target are required" >&2
  exit 3
fi
if [[ ! -d "$SOURCE/.git" ]]; then
  echo "error: $SOURCE is not a git repo" >&2
  exit 3
fi
PUSH_BRANCH="${PUSH_BRANCH:-$BRANCH}"

if ! command -v "$DFS2" >/dev/null 2>&1 && [[ ! -x "$DFS2" ]]; then
  echo "error: dfs2 not found (set DFS2=... )" >&2
  exit 3
fi

git -C "$SOURCE" fetch --unshallow >/dev/null 2>&1 || true

mapfile -t SHAS < <(git -C "$SOURCE" rev-list --reverse --first-parent "$BRANCH")
if [[ ${#SHAS[@]} -eq 0 ]]; then
  echo "error: no commits found" >&2
  exit 3
fi
echo "source: ${#SHAS[@]} first-parent commits on $BRANCH"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
IN="$WORK/in"
OUT="$WORK/out"
META="$WORK/meta"
mkdir -p "$IN" "$META"

i=0
for sha in "${SHAS[@]}"; do
  d=$(printf "%06d" "$i")
  mkdir -p "$IN/$d"
  git -C "$SOURCE" archive "$sha" | tar -x -C "$IN/$d"
  {
    printf '%s\n' "$sha"
    git -C "$SOURCE" log -1 --format='%an' "$sha"
    git -C "$SOURCE" log -1 --format='%ae' "$sha"
    git -C "$SOURCE" log -1 --format='%aI' "$sha"
    git -C "$SOURCE" log -1 --format='%cn' "$sha"
    git -C "$SOURCE" log -1 --format='%ce' "$sha"
    git -C "$SOURCE" log -1 --format='%cI' "$sha"
    git -C "$SOURCE" log -1 --format='%B' "$sha"
  } > "$META/$d"
  i=$((i + 1))
done

set +e
"$DFS2" redact "$IN" "$OUT"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  exit "$rc"
fi
echo "redact ok"

if [[ -e "$TARGET" ]] && [[ -n "$(ls -A "$TARGET" 2>/dev/null || true)" ]]; then
  if [[ -d "$TARGET/.git" ]]; then
    rm -rf "$TARGET"
  else
    echo "error: $TARGET exists and is not a mirror repo" >&2
    exit 3
  fi
fi
mkdir -p "$TARGET"
git -C "$TARGET" init -q -b "$BRANCH"

n=${#SHAS[@]}
i=0
for d in "$OUT"/*; do
  [[ -d "$d" ]] || continue
  name=$(basename "$d")
  {
    read -r sha
    read -r an
    read -r ae
    read -r ad
    read -r cn
    read -r ce
    read -r cd
    msg=$(cat)
  } < "$META/$name"

  find "$TARGET" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -a "$d"/. "$TARGET"/
  git -C "$TARGET" add -A
  msg=${msg%$'\n'}
  printf '%s\n\nSource-Commit: %s\n' "$msg" "$sha" > "$WORK/commit-msg"
  GIT_AUTHOR_NAME="$an" GIT_AUTHOR_EMAIL="$ae" GIT_AUTHOR_DATE="$ad" \
    GIT_COMMITTER_NAME="$cn" GIT_COMMITTER_EMAIL="$ce" GIT_COMMITTER_DATE="$cd" \
    git -C "$TARGET" commit -q --allow-empty -F "$WORK/commit-msg"
  i=$((i + 1))
  if (( i % 50 == 0 || i == n )); then
    echo "commits: $i/$n"
  fi
done

if [[ -n "$PUSH" ]]; then
  git -C "$TARGET" push --force "$PUSH" "HEAD:refs/heads/$PUSH_BRANCH"
  echo "force-pushed mirror to $PUSH_BRANCH"
fi

echo "OK: mirror clean"
