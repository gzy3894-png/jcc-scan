/*
 * jcc-scan — arm64 可执行文件（纯 C）
 *
 * 对齐 JCC Controller 2.5.0 注入时序：
 *   force-stop → 清残留 → am start 拉起 → pidof
 *   → maps 等 libil2cpp → 再等 3s → ptrace 注入
 *   → 校验 maps/status → 等扫描 DONE
 *
 * 终端输出全程进度，无 UI。
 */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PKG "com.tencent.jkchess"
#define GAME_ACT "com.tencent.jkchess/com.tencent.gcloud.msdk.core.policy.ZGamePolicyActivity"
#define OUT_DIR "/sdcard/Download/jcc-scan"
#define OUT_DIR2 "/storage/emulated/0/Download/jcc-scan"
#define GAME_FILES "/data/user/0/com.tencent.jkchess/files"
#define TMP_DIR "/data/local/tmp"
#define INJ_NAME "JCC.sh"
#define SO_NAME "libJCC.so"

/* 注入后 SO 应尽快写出这些关键字之一 */
#define ALIVE_HINT "constructor"
#define ALIVE_HINT2 "boot"
#define ALIVE_HINT3 "waiting libil2cpp"
#define ALIVE_HINT4 "SCAN_OK"
#define ALIVE_HINT5 "found libil2cpp"

static char g_self_dir[512];
static char g_out[256] = OUT_DIR;
static int g_no_kill = 0; /* --no-kill: 危险，默认关闭 */

static void say(const char *s) {
    printf("[jcc-scan] %s\n", s);
    fflush(stdout);
}

static void step(int n, int total, const char *s) {
    printf("\n======== [%d/%d] %s ========\n", n, total, s);
    fflush(stdout);
}

static void host_log(const char *msg) {
    char path[320];
    FILE *f;
    snprintf(path, sizeof(path), "%s/host_progress.txt", g_out);
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "[%ld] %s\n", (long)time(0), msg);
        fflush(f);
        fclose(f);
    }
    say(msg);
}

static int is_root(void) { return geteuid() == 0; }

static void ensure_dir(const char *p) {
    char cmd[700];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' 2>/dev/null; chmod 777 '%s' 2>/dev/null", p, p);
    system(cmd);
}

static int file_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int path_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

static void resolve_self_dir(const char *argv0) {
    char link[512];
    ssize_t n = readlink("/proc/self/exe", link, sizeof(link) - 1);
    if (n > 0) {
        char *slash;
        link[n] = 0;
        slash = strrchr(link, '/');
        if (slash) {
            *slash = 0;
            snprintf(g_self_dir, sizeof(g_self_dir), "%s", link);
            return;
        }
    }
    if (argv0 && argv0[0] == '/') {
        char tmp[512];
        char *slash;
        snprintf(tmp, sizeof(tmp), "%s", argv0);
        slash = strrchr(tmp, '/');
        if (slash) {
            *slash = 0;
            snprintf(g_self_dir, sizeof(g_self_dir), "%s", tmp);
            return;
        }
    }
    snprintf(g_self_dir, sizeof(g_self_dir), ".");
}

static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

static int pidof_pkg(void) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    if (!d) return -1;
    while ((e = readdir(d)) != 0) {
        char path[64], buf[256];
        FILE *f;
        int pid;
        char *end = 0;
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid = (int)strtol(e->d_name, &end, 10);
        if (!end || *end) continue;
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        f = fopen(path, "r");
        if (!f) continue;
        if (fgets(buf, sizeof(buf), f)) {
            if (strcmp(buf, PKG) == 0) {
                fclose(f);
                closedir(d);
                return pid;
            }
        }
        fclose(f);
    }
    closedir(d);
    return -1;
}

static int maps_has_substr(int pid, const char *sub) {
    char path[64], line[768];
    FILE *f;
    if (pid <= 0) return 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, sub)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int read_last_line(const char *path, char *out, size_t outsz) {
    FILE *f;
    char line[512];
    int any = 0;
    if (outsz == 0) return 0;
    out[0] = 0;
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (n == 0) continue;
        snprintf(out, outsz, "%s", line);
        any = 1;
    }
    fclose(f);
    return any;
}

static int file_contains(const char *path, const char *needle) {
    FILE *f;
    char line[512];
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* 双路径读 SO 状态：sdcard + 游戏 files */
static int so_status_alive(char *last, size_t lastsz) {
    char p1[320], p2[320], p3[320];
    snprintf(p1, sizeof(p1), "%s/status.txt", g_out);
    snprintf(p2, sizeof(p2), "%s/jcc_scan_status.txt", GAME_FILES);
    snprintf(p3, sizeof(p3), "%s/jcc-scan/status.txt", GAME_FILES);

    if (read_last_line(p1, last, lastsz) || read_last_line(p2, last, lastsz) ||
        read_last_line(p3, last, lastsz)) {
        if (file_contains(p1, ALIVE_HINT) || file_contains(p1, ALIVE_HINT2) ||
            file_contains(p1, ALIVE_HINT3) || file_contains(p1, ALIVE_HINT4) ||
            file_contains(p1, ALIVE_HINT5) || file_contains(p2, ALIVE_HINT) ||
            file_contains(p2, ALIVE_HINT2) || file_contains(p2, ALIVE_HINT3) ||
            file_contains(p2, ALIVE_HINT4) || file_contains(p2, ALIVE_HINT5) ||
            file_contains(p3, ALIVE_HINT) || file_contains(p3, ALIVE_HINT2) ||
            file_contains(p3, ALIVE_HINT3) || file_contains(p3, ALIVE_HINT4) ||
            file_contains(p3, ALIVE_HINT5))
            return 1;
        /* 有任意 status 内容也算活过 */
        if (last[0]) return 1;
    }
    return 0;
}

static int done_exists(void) {
    char p[320];
    snprintf(p, sizeof(p), "%s/DONE", g_out);
    if (file_exists(p)) return 1;
    snprintf(p, sizeof(p), "%s/jcc-scan/DONE", GAME_FILES);
    if (file_exists(p)) return 1;
    snprintf(p, sizeof(p), "%s/jcc_scan_status.txt", GAME_FILES);
    if (file_contains(p, "SCAN_OK")) return 1;
    return 0;
}

static void pick_out_dir(void) {
    const char *cands[] = {OUT_DIR, OUT_DIR2, "/data/local/tmp/jcc-scan-out", 0};
    char t[300];
    int i;
    for (i = 0; cands[i]; i++) {
        ensure_dir(cands[i]);
        snprintf(t, sizeof(t), "%s/.w", cands[i]);
        {
            FILE *f = fopen(t, "w");
            if (f) {
                fputc('1', f);
                fclose(f);
                unlink(t);
                snprintf(g_out, sizeof(g_out), "%s", cands[i]);
                return;
            }
        }
    }
    snprintf(g_out, sizeof(g_out), "%s", "/data/local/tmp/jcc-scan-out");
    ensure_dir(g_out);
}

static void clear_old_results(void) {
    char cmd[900];
    snprintf(cmd, sizeof(cmd),
             "rm -f '%s/DONE' '%s/status.txt' '%s/inject_log.txt' '%s/host_progress.txt' "
             "'%s/offsets.h' '%s/scan_report.json' '%s/SCAN_REPORT.txt' 2>/dev/null; "
             "rm -f '%s/jcc_scan_status.txt' '%s/jcc-scan/DONE' '%s/jcc-scan/status.txt' 2>/dev/null",
             g_out, g_out, g_out, g_out, g_out, g_out, g_out, GAME_FILES, GAME_FILES, GAME_FILES);
    run_cmd(cmd);
}

static int deploy(void) {
    char src_inj[600], src_so[600], cmd[1600];
    snprintf(src_inj, sizeof(src_inj), "%s/%s", g_self_dir, INJ_NAME);
    snprintf(src_so, sizeof(src_so), "%s/%s", g_self_dir, SO_NAME);
    if (!file_exists(src_inj)) snprintf(src_inj, sizeof(src_inj), "%s/bin/%s", g_self_dir, INJ_NAME);
    if (!file_exists(src_so)) snprintf(src_so, sizeof(src_so), "%s/bin/%s", g_self_dir, SO_NAME);

    if (!file_exists(src_inj)) {
        host_log("ERROR: 找不到 JCC.sh（须与 jcc-scan 同目录）");
        return -1;
    }
    if (!file_exists(src_so)) {
        host_log("ERROR: 找不到 libJCC.so（须与 jcc-scan 同目录）");
        return -1;
    }

    /* 校验 so 非空 */
    {
        struct stat st;
        if (stat(src_so, &st) != 0 || st.st_size < 4096) {
            host_log("ERROR: libJCC.so 过小或不可读");
            return -1;
        }
        printf("[jcc-scan] libJCC.so size=%ld\n", (long)st.st_size);
        fflush(stdout);
    }

    snprintf(cmd, sizeof(cmd),
             "cp -f '%s' '%s/%s' && chmod 755 '%s/%s' && "
             "cp -f '%s' '%s/%s' && chmod 755 '%s/%s' && "
             "chown root:root '%s/%s' '%s/%s' 2>/dev/null; true",
             src_inj, TMP_DIR, INJ_NAME, TMP_DIR, INJ_NAME, src_so, TMP_DIR, SO_NAME, TMP_DIR,
             SO_NAME, TMP_DIR, INJ_NAME, TMP_DIR, SO_NAME);
    if (run_cmd(cmd) != 0) {
        host_log("ERROR: 部署到 /data/local/tmp 失败");
        return -1;
    }
    /* 确认落盘 */
    if (!file_exists(TMP_DIR "/" INJ_NAME) || !file_exists(TMP_DIR "/" SO_NAME)) {
        host_log("ERROR: /data/local/tmp 部署校验失败");
        return -1;
    }
    host_log("部署完成: /data/local/tmp/JCC.sh + libJCC.so");
    return 0;
}

/* 2.5.0 风格：强停 + 清残留 */
static void cold_kill_game(void) {
    char cmd[512];
    host_log("强制停止游戏与残留注入器...");
    snprintf(cmd, sizeof(cmd), "am force-stop %s 2>/dev/null", PKG);
    run_cmd(cmd);
    run_cmd("kill -9 $(pidof JCC.sh) 2>/dev/null");
    /* 只杀注入器，绝不 kill 自己 */
    run_cmd("pkill -9 -f '/data/local/tmp/JCC.sh' 2>/dev/null");
    sleep(2);
    if (pidof_pkg() > 0) {
        host_log("警告: force-stop 后进程仍在，再 kill...");
        snprintf(cmd, sizeof(cmd), "kill -9 $(pidof %s) 2>/dev/null", PKG);
        run_cmd(cmd);
        sleep(1);
    }
}

static int start_game(void) {
    char cmd[640];
    int i, pid;

    /* Android 12+ 悬浮/注入友好（2.5.0 也有） */
    run_cmd("settings put global block_untrusted_touches 0 2>/dev/null");

    host_log("由脚本拉起游戏进程...");
    snprintf(cmd, sizeof(cmd), "am start -n %s 2>/dev/null", GAME_ACT);
    if (run_cmd(cmd) != 0) {
        snprintf(cmd, sizeof(cmd),
                 "monkey -p %s -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1", PKG);
        run_cmd(cmd);
    }

    for (i = 0; i < 45; i++) {
        pid = pidof_pkg();
        if (pid > 0) {
            printf("[jcc-scan] 游戏已启动 PID=%d (+%ds)\n", pid, i + 1);
            fflush(stdout);
            host_log("游戏进程就绪");
            return pid;
        }
        if ((i + 1) % 5 == 0) {
            printf("[jcc-scan] 等待游戏进程... %ds\n", i + 1);
            fflush(stdout);
        }
        sleep(1);
    }
    host_log("ERROR: 超时未能 pidof 到游戏");
    return -1;
}

static int wait_il2cpp(int pid, int max_sec) {
    int i;
    host_log("等待 libil2cpp.so 映射进进程...");
    for (i = 0; i < max_sec; i++) {
        int cur = pidof_pkg();
        if (cur > 0) pid = cur;
        if (pid > 0 && maps_has_substr(pid, "libil2cpp.so")) {
            printf("[jcc-scan] Unity 引擎已加载 (+%ds) PID=%d\n", i + 1, pid);
            fflush(stdout);
            host_log("libil2cpp 已就绪，稳定等待 3 秒（对齐 2.5.0）...");
            sleep(3);
            /* 再确认进程没死 */
            cur = pidof_pkg();
            if (cur <= 0) {
                host_log("ERROR: 等引擎后进程消失");
                return -1;
            }
            if (!maps_has_substr(cur, "libil2cpp.so")) {
                host_log("ERROR: libil2cpp 映射又消失了");
                return -1;
            }
            return cur;
        }
        if ((i + 1) % 10 == 0) {
            printf("[jcc-scan] 等待引擎... %d/%ds  PID=%d\n", i + 1, max_sec, pid);
            fflush(stdout);
        }
        sleep(1);
    }
    host_log("警告: 等 libil2cpp 超时，仍尝试注入（可能失败）");
    return pidof_pkg();
}

static int do_inject(int pid) {
    char cmd[700];
    char logpath[320];
    FILE *lf;
    snprintf(logpath, sizeof(logpath), "%s/inject_log.txt", g_out);

    printf("[jcc-scan] 目标 PID=%d，开始 ptrace 注入...\n", pid);
    fflush(stdout);
    host_log("执行注入: nsenter + JCC.sh → dlopen libJCC.so");

    /* 优先 nsenter 进 init 的 mount ns（2.5.0） */
    snprintf(cmd, sizeof(cmd),
             "nsenter -t 1 -m -- %s/%s >'%s' 2>&1; echo EXIT:$? >>'%s'", TMP_DIR, INJ_NAME,
             logpath, logpath);
    if (run_cmd(cmd) != 0) {
        host_log("nsenter 路径返回非 0，尝试直接执行 JCC.sh...");
    }

    /* 若日志无成功关键字，再直跑 */
    if (!file_contains(logpath, "成功") && !file_contains(logpath, "SUCCEED") &&
        !file_contains(logpath, "dlopen") && !file_contains(logpath, "OK")) {
        snprintf(cmd, sizeof(cmd), "%s/%s >'%s' 2>&1; echo EXIT:$? >>'%s'", TMP_DIR, INJ_NAME,
                 logpath, logpath);
        run_cmd(cmd);
    }

    /* 打印注入日志摘要 */
    lf = fopen(logpath, "r");
    if (lf) {
        char line[512];
        int n = 0;
        say("--- inject_log 摘要 ---");
        while (fgets(line, sizeof(line), lf) && n < 40) {
            fputs(line, stdout);
            n++;
        }
        fclose(lf);
        fflush(stdout);
        say("--- end ---");
    } else {
        host_log("警告: 无 inject_log.txt");
    }
    return 0;
}

/*
 * 注入成功判定（防御性，多重）：
 *  A) maps 出现 libJCC
 *  B) SO status 写出 alive 关键字
 *  超时则失败，绝不假装成功
 */
static int verify_inject(int max_sec) {
    int i;
    char last[256];
    host_log("校验注入是否成功...");
    for (i = 0; i < max_sec; i++) {
        int pid = pidof_pkg();
        int maps_ok = 0, status_ok = 0;

        if (pid <= 0) {
            if (i >= 3) {
                host_log("ERROR: 注入后游戏进程已消失（疑似崩溃）");
                return -1;
            }
            sleep(1);
            continue;
        }

        maps_ok = maps_has_substr(pid, "libJCC.so") || maps_has_substr(pid, "libJCC") ||
                  maps_has_substr(pid, "/data/local/tmp/libJCC");
        last[0] = 0;
        status_ok = so_status_alive(last, sizeof(last));

        if (maps_ok || status_ok) {
            printf("[jcc-scan] 注入确认成功 (+%ds)\n", i + 1);
            printf("[jcc-scan]   maps_libJCC=%d  so_status=%d\n", maps_ok, status_ok);
            if (last[0]) printf("[jcc-scan]   so_status_last: %s\n", last);
            fflush(stdout);
            host_log("注入校验通过");
            return pid;
        }

        if ((i + 1) % 3 == 0) {
            printf("[jcc-scan] 校验中... %ds  PID=%d maps=0 status=0 last=%s\n", i + 1, pid,
                   last[0] ? last : "(无)");
            fflush(stdout);
        }
        sleep(1);
    }
    host_log("ERROR: 注入校验失败 — maps 无 libJCC 且无 SO 状态文件");
    return -1;
}

static int wait_scan_done(int max_sec) {
    int i;
    char last[256] = {0};
    char prev[256] = {0};
    host_log("等待扫描完成（请停在登录/大厅，不要排队进局）...");
    for (i = 0; i < max_sec; i++) {
        int pid;

        if (done_exists()) {
            host_log("检测到 DONE / SCAN_OK");
            return 1;
        }

        pid = pidof_pkg();
        if (pid <= 0 && i > 5) {
            host_log("ERROR: 扫描过程中游戏退出");
            return 0;
        }

        last[0] = 0;
        so_status_alive(last, sizeof(last));
        if (last[0] && strcmp(last, prev) != 0) {
            printf("[jcc-scan] 进度: %s\n", last);
            fflush(stdout);
            snprintf(prev, sizeof(prev), "%s", last);
        } else if ((i + 1) % 15 == 0) {
            printf("[jcc-scan] ... %ds  last=%s  PID=%d\n", i + 1, last[0] ? last : "(等待 SO 输出)",
                   pid);
            fflush(stdout);
        }

        /* 若 maps 丢了 libJCC 且一直无 status，提前失败 */
        if (i == 45 && pid > 0) {
            int maps_ok = maps_has_substr(pid, "libJCC");
            if (!maps_ok && !last[0]) {
                host_log("ERROR: 45s 仍无 libJCC 映射且无状态，中止等待");
                return 0;
            }
        }
        sleep(1);
    }
    return done_exists();
}

static void dump_diagnostics(void) {
    char cmd[512];
    say("======== 诊断信息 ========");
    printf("out_dir=%s\n", g_out);
    system("echo '--- host_progress ---'; tail -30 '" OUT_DIR
           "/host_progress.txt' 2>/dev/null; "
           "tail -30 /data/local/tmp/jcc-scan-out/host_progress.txt 2>/dev/null");
    snprintf(cmd, sizeof(cmd), "echo '--- status sdcard ---'; cat '%s/status.txt' 2>/dev/null",
             g_out);
    system(cmd);
    system("echo '--- status game files ---'; cat '" GAME_FILES
           "/jcc_scan_status.txt' 2>/dev/null | tail -40");
    snprintf(cmd, sizeof(cmd), "echo '--- inject_log ---'; cat '%s/inject_log.txt' 2>/dev/null | tail -40",
             g_out);
    system(cmd);
    system("echo '--- maps libJCC/il2cpp ---'; "
           "P=$(pidof " PKG "); echo PID=$P; "
           "grep -E 'libil2cpp|libJCC' /proc/$P/maps 2>/dev/null | head -20");
    say("======== 诊断结束 ========");
}

static void print_banner(void) {
    printf("\n");
    printf("============================================\n");
    printf("  JCC Scan  金铲铲数据扫描 (纯C / 无UI)\n");
    printf("  包名: %s\n", PKG);
    printf("============================================\n");
    printf("策略 (对齐 Controller 2.5.0):\n");
    printf("  1) 强制停止游戏并清理残留\n");
    printf("  2) 由本程序 am start 拉起进程\n");
    printf("  3) 等待 libil2cpp 映射 + 稳定 3 秒\n");
    printf("  4) ptrace 注入并校验 libJCC\n");
    printf("  5) 等待扫表 DONE（请停在登录/大厅）\n");
    printf("结果目录: %s\n", g_out);
    if (g_no_kill) printf("模式: --no-kill (危险，不推荐)\n");
    printf("============================================\n\n");
    fflush(stdout);
}

static void usage(void) {
    printf("用法: jcc-scan [--no-kill]\n");
    printf("  默认: 强停游戏后由脚本拉起再注入（安全）\n");
    printf("  --no-kill: 不杀已有进程（易闪退，仅调试）\n");
}

int main(int argc, char **argv) {
    int i, pid, vpid;
    const int STEPS = 6;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-kill") == 0) g_no_kill = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
    }

    resolve_self_dir(argc > 0 ? argv[0] : 0);
    if (!is_root()) {
        say("请用 root: su -c 'sh /sdcard/jcc-scan/开始扫描.sh'");
        return 1;
    }

    pick_out_dir();
    print_banner();
    ensure_dir(g_out);
    clear_old_results();
    host_log("启动 jcc-scan");

    /* [1] 部署 */
    step(1, STEPS, "部署注入器与扫描 SO");
    if (deploy() != 0) {
        dump_diagnostics();
        return 2;
    }

    /* [2] 冷启动 */
    step(2, STEPS, "冷启动游戏进程");
    if (!g_no_kill) {
        cold_kill_game();
    } else {
        host_log("跳过 force-stop (--no-kill)");
    }
    pid = start_game();
    if (pid <= 0) {
        dump_diagnostics();
        return 3;
    }

    /* [3] 等引擎 */
    step(3, STEPS, "等待 Unity/IL2CPP 引擎");
    pid = wait_il2cpp(pid, 90);
    if (pid <= 0) {
        host_log("ERROR: 引擎等待失败");
        dump_diagnostics();
        return 4;
    }

    /* 防御：注入前再确认不在异常状态 */
    if (!maps_has_substr(pid, "libil2cpp.so")) {
        host_log("ERROR: 注入前 libil2cpp 不在 maps");
        dump_diagnostics();
        return 4;
    }

    /* [4] 注入 */
    step(4, STEPS, "ptrace 注入 libJCC.so");
    do_inject(pid);
    sleep(1); /* 给 constructor 一点时间 */

    /* [5] 校验 */
    step(5, STEPS, "校验注入状态");
    vpid = verify_inject(25);
    if (vpid <= 0) {
        host_log("注入失败。请把诊断信息发回。");
        dump_diagnostics();
        return 5;
    }

    /* [6] 等扫描 */
    step(6, STEPS, "等待扫表结果");
    say("请保持在【登录页或大厅】，不要排队进对局。");
    say("结构扫描通常 30~90 秒；成功会显示「已完成」。");

    if (wait_scan_done(180)) {
        /* 把游戏 files 结果再同步到 sdcard */
        run_cmd("cp -f '" GAME_FILES
                "/jcc-scan/'* '" OUT_DIR "/' 2>/dev/null; "
                "cp -f '" GAME_FILES "/jcc_scan_status.txt' '" OUT_DIR
                "/jcc_scan_status.txt' 2>/dev/null; true");
        /* 若 DONE 只在 game files */
        if (!file_exists(OUT_DIR "/DONE") && path_exists(GAME_FILES "/jcc-scan/DONE"))
            run_cmd("cp -f '" GAME_FILES "/jcc-scan/DONE' '" OUT_DIR "/DONE'");

        printf("\n");
        printf("############################################\n");
        printf("#                                          #\n");
        printf("#   已完成！扫描成功                       #\n");
        printf("#                                          #\n");
        printf("############################################\n\n");
        printf("请把整个文件夹发回电脑:\n\n");
        printf("  %s\n\n", g_out);
        printf("需要包含: DONE  offsets.h  scan_report.json  SCAN_REPORT.txt  status.txt\n\n");
        {
            char ls[400];
            snprintf(ls, sizeof(ls), "ls -la '%s' 2>/dev/null", g_out);
            system(ls);
        }
        printf("\nadb pull %s\n", g_out);
        host_log("SUCCESS");
        return 0;
    }

    host_log("扫描超时或失败");
    dump_diagnostics();
    return 6;
}
