#!/system/bin/sh
# 金铲铲数据扫描 — 用户只跑这一条
# 用法：su 后执行
#   sh /sdcard/jcc-scan/开始扫描.sh

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/jcc-scan"

echo ""
echo "======== JCC 扫描 ========"
echo "目录: $DIR"
echo ""

if [ ! -x "$BIN" ]; then
  if [ -f "$BIN" ]; then
    chmod 755 "$BIN"
  else
    echo "[错误] 找不到 jcc-scan 可执行文件"
    echo "请确认解压完整：jcc-scan / libJCC.so / JCC.sh / 开始扫描.sh 在同一目录"
    exit 1
  fi
fi

# root 检查
ID=$(id)
echo "$ID" | grep -q uid=0 || {
  echo "[错误] 需要 root。请先执行 su，再："
  echo "  sh $DIR/开始扫描.sh"
  exit 1
}

# 同目录文件 chmod
chmod 755 "$DIR/jcc-scan" "$DIR/JCC.sh" 2>/dev/null
chmod 755 "$DIR/libJCC.so" 2>/dev/null

echo "[提示] 请先打开《金铲铲之战》，停在登录页/大厅均可。"
echo "[提示] 注入后可继续对局；完成后会提示「已完成」。"
echo ""
sleep 1

# 运行可执行文件（自身目录即资源目录）
cd "$DIR" || exit 1
"$BIN"
RC=$?

echo ""
if [ "$RC" -eq 0 ]; then
  echo "============================================"
  echo "  已完成。请把下面文件夹发回电脑："
  echo "  /sdcard/Download/jcc-scan/"
  echo "============================================"
else
  echo "退出码=$RC ，若失败请把 status.txt / inject_log.txt 一并发送"
fi
exit $RC
