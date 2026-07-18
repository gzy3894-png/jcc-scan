# jcc-scan — 金铲铲 IL2CPP 数据扫描（纯 C / 真机可执行文件）

**不用 Zygisk，不用重启。** 成品是 arm64 可执行文件 + 注入 SO，和参考「纯C开源」同一形态。

## 你怎么用（手机）

1. 从 [Releases](../../releases) 下载 `jcc-scan-phone-arm64.zip`
2. 解压到手机：`/sdcard/jcc-scan/`
3. Root 终端（**不要先开游戏**，脚本会自己拉起）：

```sh
su
sh /sdcard/jcc-scan/开始扫描.sh
```

4. 终端会打印：冷启动 → 等引擎 → 注入校验 → 扫表进度  
5. 看到 **已完成** 后，把 `/sdcard/Download/jcc-scan/` 整夹发回电脑  
   （或 `scripts/pull-to-pc.ps1`）

**请停在登录页/大厅**，不要在排队加载时注入（脚本默认 force-stop 冷启动，对齐 2.5.0）。

## 结果文件

| 文件 | 内容 |
|------|------|
| `DONE` | 完成标记 |
| `offsets.h` | 类字段偏移（C 头） |
| `scan_report.json` | 结构化结果 |
| `SCAN_REPORT.txt` | 人读报告 |
| `status.txt` | 过程日志 |

## 源码结构

```text
jni/
  Android.mk / Application.mk
  src/main.c           # 可执行文件 jcc-scan
  src/scan_payload.c   # libJCC.so 注入后扫表
  include/ xdl/        # IL2CPP API + xdl
bin/JCC.sh             # 真机 ptrace 注入器
scripts/开始扫描.sh
```

## 本地编译（可选）

```bash
ndk-build -C jni NDK_PROJECT_PATH=.. 
# 或在仓库根：ndk-build
```

CI：push 到 `main` 自动编 arm64 并上传 Release。
