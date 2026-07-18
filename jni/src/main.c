/*
 * jcc-scan — 真机 arm64 可执行文件（纯 C）
 * root 下运行：部署注入器 → 等游戏 → ptrace 注入 libJCC.so → 等 DONE → 提示完成
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
#define TMP_DIR "/data/local/tmp"
#define INJ_NAME "JCC.sh"
#define SO_NAME "libJCC.so"

static char g_self_dir[512];

static void say(const char *s) {
    printf("[jcc-scan] %s\n", s);
    fflush(stdout);
}

static int is_root(void) {
    return geteuid() == 0;
}

static void ensure_dir(const char *p) {
    char cmd[640];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' 2>/dev/null; chmod 777 '%s' 2>/dev/null", p, p);
    system(cmd);
}

static int file_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
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

static int maps_has_il2cpp(int pid) {
    char path[64], line[512];
    FILE *f;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libil2cpp.so")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int deploy(void) {
    char src_inj[600], src_so[600], cmd[1400];
    snprintf(src_inj, sizeof(src_inj), "%s/%s", g_self_dir, INJ_NAME);
    snprintf(src_so, sizeof(src_so), "%s/%s", g_self_dir, SO_NAME);
    if (!file_exists(src_inj)) {
        snprintf(src_inj, sizeof(src_inj), "%s/bin/%s", g_self_dir, INJ_NAME);
    }
    if (!file_exists(src_so)) {
        snprintf(src_so, sizeof(src_so), "%s/bin/%s", g_self_dir, SO_NAME);
    }
    if (!file_exists(src_inj)) {
        say("ERROR: 找不到 JCC.sh（与 jcc-scan 同目录）");
        return -1;
    }
    if (!file_exists(src_so)) {
        say("ERROR: 找不到 libJCC.so（与 jcc-scan 同目录）");
        return -1;
    }
    snprintf(cmd, sizeof(cmd),
             "cp -f '%s' '%s/%s' && chmod 755 '%s/%s' && "
             "cp -f '%s' '%s/%s' && chmod 755 '%s/%s'",
             src_inj, TMP_DIR, INJ_NAME, TMP_DIR, INJ_NAME, src_so, TMP_DIR, SO_NAME, TMP_DIR,
             SO_NAME);
    if (run_cmd(cmd) != 0) {
        say("ERROR: 部署到 /data/local/tmp 失败");
        return -1;
    }
    say("已部署注入器 + 扫描 SO → /data/local/tmp/");
    return 0;
}

static int inject(void) {
    char cmd[512];
    /* 与 JCC Controller 相同：优先 nsenter */
    snprintf(cmd, sizeof(cmd),
             "if command -v nsenter >/dev/null 2>&1; then "
             "nsenter -t 1 -m -- %s/%s > %s/inject_log.txt 2>&1; "
             "else %s/%s > %s/inject_log.txt 2>&1; fi",
             TMP_DIR, INJ_NAME, OUT_DIR, TMP_DIR, INJ_NAME, OUT_DIR);
    say("正在 ptrace 注入...");
    run_cmd(cmd);
    return 0;
}

static int wait_done(int max_sec) {
    char done_path[320], status_path[320];
    int i;
    snprintf(done_path, sizeof(done_path), "%s/DONE", OUT_DIR);
    snprintf(status_path, sizeof(status_path), "%s/status.txt", OUT_DIR);
    for (i = 0; i < max_sec; i++) {
        if (file_exists(done_path)) return 1;
        if (i > 0 && (i % 20) == 0) {
            char line[256] = {0};
            FILE *f = fopen(status_path, "r");
            if (f) {
                /* 读最后一行：简单扫到末尾 */
                while (fgets(line, sizeof(line), f)) {
                }
                fclose(f);
            }
            printf("[jcc-scan] ... %ds  status: %s", i, line[0] ? line : "(暂无)\n");
            fflush(stdout);
            say("请继续游戏/对局，扫描在后台进行...");
        }
        sleep(1);
    }
    return file_exists(done_path);
}

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf("  JCC Scan  金铲铲数据扫描 (纯C)\n");
    printf("  包名: %s\n", PKG);
    printf("========================================\n");
    printf("流程:\n");
    printf("  1) 本程序注入扫描模块\n");
    printf("  2) 你正常进大厅 / 打一局均可\n");
    printf("  3) 看到「已完成」后，把结果目录发回电脑\n");
    printf("结果目录: %s\n", OUT_DIR);
    printf("========================================\n\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    int pid, i;
    char cmd[512];

    resolve_self_dir(argc > 0 ? argv[0] : 0);

    if (!is_root()) {
        say("请用 root 执行: su -c /data/local/tmp/jcc-scan");
        return 1;
    }

    print_banner();
    ensure_dir(OUT_DIR);
    /* 清旧 DONE */
    unlink(OUT_DIR "/DONE");
    {
        char p[320];
        snprintf(p, sizeof(p), "%s/status.txt", OUT_DIR);
        unlink(p);
    }

    if (deploy() != 0) return 2;

    say("[1/4] 检查游戏进程...");
    pid = pidof_pkg();
    if (pid <= 0) {
        say("游戏未运行，正在启动...");
        snprintf(cmd, sizeof(cmd), "am start -n %s >/dev/null 2>&1", GAME_ACT);
        run_cmd(cmd);
        for (i = 0; i < 40; i++) {
            sleep(1);
            pid = pidof_pkg();
            if (pid > 0) break;
        }
    }
    if (pid <= 0) {
        say("ERROR: 无法启动/找到游戏，请手动打开金铲铲后再运行");
        return 3;
    }
    printf("[jcc-scan] PID=%d\n", pid);
    fflush(stdout);

    say("[2/4] 等待 libil2cpp.so ...");
    for (i = 0; i < 90; i++) {
        if (maps_has_il2cpp(pid)) {
            printf("[jcc-scan] 引擎就绪 +%ds\n", i);
            fflush(stdout);
            sleep(2);
            break;
        }
        /* 进程可能重启 */
        pid = pidof_pkg();
        if (pid <= 0) {
            sleep(1);
            continue;
        }
        sleep(1);
    }

    say("[3/4] 注入扫描模块...");
    inject();

    say("[4/4] 等待扫描完成（最长约 6 分钟）...");
    say(">>> 现在可以进大厅或开一局，扫表会自动进行 <<<");

    if (wait_done(360)) {
        printf("\n");
        printf("########################################\n");
        printf("#                                      #\n");
        printf("#   已完成！扫描成功                   #\n");
        printf("#                                      #\n");
        printf("########################################\n");
        printf("\n请把下面整个文件夹发到电脑（MT管理器 / adb pull）：\n\n");
        printf("  %s\n\n", OUT_DIR);
        printf("至少包含:\n");
        printf("  DONE\n");
        printf("  offsets.h\n");
        printf("  scan_report.json\n");
        printf("  SCAN_REPORT.txt\n");
        printf("  status.txt\n\n");
        system("ls -la " OUT_DIR " 2>/dev/null");
        printf("\n电脑端一键拉取示例:\n");
        printf("  adb pull %s\n", OUT_DIR);
        return 0;
    }

    say("超时未看到 DONE。请查看:");
    printf("  %s/status.txt\n", OUT_DIR);
    printf("  %s/inject_log.txt\n", OUT_DIR);
    system("tail -30 " OUT_DIR "/status.txt 2>/dev/null");
    system("tail -20 " OUT_DIR "/inject_log.txt 2>/dev/null");
    return 4;
}
