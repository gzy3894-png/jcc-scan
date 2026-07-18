#!/system/bin/sh
# 金铲铲数据扫描 — 只跑这一条（无 UI，终端进度）
#   su
#   sh /sdcard/jcc-scan/开始扫描.sh

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/jcc-scan"

echo ""
echo "============================================"
echo "  JCC Scan  开始"
echo "  目录: $DIR"
echo "============================================"
echo ""

if [ ! -f "$BIN" ]; then
  echo "[错误] 找不到 jcc-scan"
  echo "需要同目录: jcc-scan  libJCC.so  JCC.sh  开始扫描.sh"
  exit 1
fi
chmod 755 "$DIR/jcc-scan" "$DIR/JCC.sh" 2>/dev/null
chmod 755 "$DIR/libJCC.so" 2>/dev/null

id | grep -q "uid=0" || {
  echo "[错误] 需要 root。请先 su，再执行本脚本。"
  exit 1
}

if [ ! -f "$DIR/libJCC.so" ] || [ ! -f "$DIR/JCC.sh" ]; then
  echo "[错误] 缺少 libJCC.so 或 JCC.sh"
  exit 1
fi

echo "[说明] 脚本会：强制停止游戏 → 自行拉起 → 等引擎 → 注入 → 扫表"
echo "[说明] 请不要手动排队进局；停在登录页/大厅即可"
echo "[说明] 终端会打印每一步状态"
echo ""
sleep 1

cd "$DIR" || exit 1
"$BIN" "$@"
RC=$?

echo ""
case "$RC" in
  0)
    echo "============================================"
    echo "  已完成。请把文件夹发回电脑："
    echo "  /sdcard/Download/jcc-scan/"
    echo "============================================"
    ;;
  5)
    echo "注入校验失败（maps 无 libJCC / 无 SO 状态）。请把 inject_log.txt 发回。"
    ;;
  6)
    echo "扫表超时。请把 status.txt / host_progress.txt 发回。"
    ;;
  *)
    echo "失败，退出码=$RC。请把该目录下日志发回："
    echo "  /sdcard/Download/jcc-scan/"
    ;;
esac
exit $RC
