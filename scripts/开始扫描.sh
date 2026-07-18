#!/system/bin/sh
# 閲戦摬閾叉暟鎹壂鎻?鈥?鍙窇杩欎竴鏉★紙鏃?UI锛岀粓绔繘搴︼級
#   su
#   sh /sdcard/jcc-scan/寮€濮嬫壂鎻?sh

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/jcc-scan"

echo ""
echo "============================================"
echo "  JCC Scan  寮€濮?
echo "  鐩綍: $DIR"
echo "============================================"
echo ""

if [ ! -f "$BIN" ]; then
  echo "[閿欒] 鎵句笉鍒?jcc-scan"
  echo "闇€瑕佸悓鐩綍: jcc-scan  libJCC.so  JCC.sh  寮€濮嬫壂鎻?sh"
  exit 1
fi
chmod 755 "$DIR/jcc-scan" "$DIR/JCC.sh" 2>/dev/null
chmod 755 "$DIR/libJCC.so" 2>/dev/null

id | grep -q "uid=0" || {
  echo "[閿欒] 闇€瑕?root銆傝鍏?su锛屽啀鎵ц鏈剼鏈€?
  exit 1
}

if [ ! -f "$DIR/libJCC.so" ] || [ ! -f "$DIR/JCC.sh" ]; then
  echo "[閿欒] 缂哄皯 libJCC.so 鎴?JCC.sh"
  exit 1
fi

echo "[璇存槑] 鑴氭湰浼氾細寮哄埗鍋滄娓告垙 鈫?鑷鎷夎捣 鈫?绛夊紩鎿?鈫?娉ㄥ叆 鈫?鎵〃"
echo "[璇存槑] 璇蜂笉瑕佹墜鍔ㄦ帓闃熻繘灞€锛涘仠鍦ㄧ櫥褰曢〉/澶у巺鍗冲彲"
echo "[璇存槑] 缁堢浼氭墦鍗版瘡涓€姝ョ姸鎬?
echo ""
sleep 1

cd "$DIR" || exit 1
"$BIN" "$@"
RC=$?

echo ""
case "$RC" in
  0)
    echo "============================================"
    echo "  宸插畬鎴愩€傝鎶婃枃浠跺す鍙戝洖鐢佃剳锛?
    echo "  /sdcard/Download/jcc-scan/"
    echo "============================================"
    ;;
  5)
    echo "娉ㄥ叆澶辫触锛歮aps 鏃?libJCC锛圝CC.sh 鐨勩€屾垚鍔熴€嶄笉鍙俊锛夈€?
    echo "璇锋妸 host_progress.txt + inject_log.txt 鍙戝洖銆?
    ;;
  6)
    echo "鎵〃瓒呮椂銆傝鎶?status.txt / host_progress.txt 鍙戝洖銆?
    ;;
  *)
    echo "澶辫触锛岄€€鍑虹爜=$RC銆傝鎶婅鐩綍涓嬫棩蹇楀彂鍥烇細"
    echo "  /sdcard/Download/jcc-scan/"
    ;;
esac
exit $RC
