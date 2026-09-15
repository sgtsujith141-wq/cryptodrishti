#!/bin/sh
# Restore a saved frontend.  Usage: ./.backup/restore.sh [name]
# With no argument it restores V7, the current design.
#
#   V7            V6 + browse fix, live progress, new exposure graph (CURRENT)
#   V6            V1 + V2 + V5 — console, dial, scene deck
#   V5            the instrument — console landing, treemap, ledger
#   V4            scene deck reorganised: masthead nav, ranked inventory
#   V3            institutional assessment record
#   V2            full-viewport scene deck
#   V1            soft light/dark console with the radial dial
#   glass         V2 in glass over a drifting aurora        (rejected)
#   panes         three-pane operator console               (rejected)
#   editorial     serif editorial document                  (rejected)
#   dashboard     the first dark dashboard                  (rejected)
set -e
cd "$(dirname "$0")/.."
V="${1:-V7}"
case "$V" in
  V7|v7|current)              SRC=.backup/V7 ;;
  V6|v6|combined)             SRC=.backup/V6 ;;
  V6-base|v6-base)            SRC=.backup/V6-base ;;
  V5|v5|instrument)           SRC=.backup/V5 ;;
  V4|v4|console)              SRC=.backup/v11-console ;;
  V3|v3|record)               SRC=.backup/v10-record ;;
  V2|v2|scenes)               SRC=.backup/v8-scenes ;;
  V1|v1|dial)                 SRC=.backup/v6-approved ;;
  glass)                      SRC=.backup/v9-glass ;;
  polished)                   SRC=.backup/v7-polished ;;
  panes)                      SRC=.backup/web-v5 ;;
  editorial)                  SRC=.backup/web-v4 ;;
  dashboard)                  SRC=.backup/web-v2 ;;
  *) echo "unknown: $V"; sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
[ -d "$SRC" ] || { echo "missing: $SRC"; exit 1; }
cp "$SRC"/index.html "$SRC"/style.css "$SRC"/app.js app/web/
echo "frontend restored from $SRC"
[ -f "$SRC/MANIFEST.txt" ] && sed 's/^/  /' "$SRC/MANIFEST.txt"
exit 0
