#!/system/bin/sh
# JCC scan launcher (ASCII-only to avoid Windows encoding breakage)
# Usage:
#   su
#   sh /sdcard/jcc-scan/run-on-phone.sh

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/jcc-scan"

echo ""
echo "============================================"
echo "  JCC Scan start"
echo "  dir: $DIR"
echo "============================================"
echo ""

if [ ! -f "$BIN" ]; then
  echo "[ERR] jcc-scan not found"
  echo "need: jcc-scan  libJCC.so  JCC.sh  run-on-phone.sh"
  exit 1
fi

chmod 755 "$DIR/jcc-scan" 2>/dev/null
chmod 755 "$DIR/JCC.sh" 2>/dev/null
chmod 755 "$DIR/libJCC.so" 2>/dev/null

# root check
if ! id | grep -q "uid=0"; then
  echo "[ERR] need root. run: su"
  echo "then: sh $DIR/run-on-phone.sh"
  exit 1
fi

if [ ! -f "$DIR/libJCC.so" ] || [ ! -f "$DIR/JCC.sh" ]; then
  echo "[ERR] missing libJCC.so or JCC.sh"
  exit 1
fi

echo "[info] force-stop game -> start game -> wait engine -> inject -> scan"
echo "[info] stay on login/lobby, do NOT queue match"
echo "[info] terminal shows step progress"
echo ""
sleep 1

cd "$DIR" || exit 1
"$BIN" "$@"
RC=$?

echo ""
case "$RC" in
  0)
    echo "============================================"
    echo "  DONE. send folder to PC:"
    echo "  /sdcard/Download/jcc-scan/"
    echo "============================================"
    ;;
  5)
    echo "[ERR] inject failed (maps has no libJCC)."
    echo "send: host_progress.txt + inject_log.txt"
    ;;
  6)
    echo "[ERR] scan timeout."
    echo "send: status.txt + host_progress.txt"
    ;;
  *)
    echo "[ERR] exit=$RC"
    echo "send logs under /sdcard/Download/jcc-scan/"
    ;;
esac
exit $RC
