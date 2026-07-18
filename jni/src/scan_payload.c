/*
 * libJCC.so v0.1.6
 * 注入后扫表。优先保证「能写文件」再扫。
 *
 * v0.1.4/5 现象：注入成功、校验过，但 sdcard 无结果 →
 *  1) app 写 sdcard 失败；2) constructor/线程未跑或秒崩；3) 找类过慢。
 * 本版：多路径 canary + 默认可见导出 + 同步/线程双保险 + 只扫字段。
 */
#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"
#include "log.h"
#include "scan_targets.h"
#include "xdl.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DO_API(r, n, p) r (*n) p;
#include "il2cpp-api-functions.h"
#undef DO_API

#define VIS __attribute__((visibility("default")))

static uint64_t g_base;
static char g_out[256];
static volatile int g_started;
static char g_files_roots[8][128];
static int g_nroots;

static void ensure_dir(const char *p) {
    mkdir(p, 0777);
    chmod(p, 0777);
}

/* 纯 open/write，不依赖 stdio 缓冲、不依赖 g_out */
static void raw_append(const char *path, const char *msg) {
    int fd;
    char line[384];
    int n;
    if (!path || !msg) return;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) return;
    n = snprintf(line, sizeof(line), "[%ld] %s\n", (long)time(0), msg);
    if (n > 0) {
        if (n >= (int)sizeof(line)) n = (int)sizeof(line) - 1;
        write(fd, line, (size_t)n);
    }
    close(fd);
}

static void discover_roots(void) {
    /* 常见数据目录；主机也会 chmod 777 准备好 */
    static const char *cands[] = {
        "/data/user/0/com.tencent.jkchess/files",
        "/data/data/com.tencent.jkchess/files",
        "/data/user/10/com.tencent.jkchess/files",
        "/data/user/11/com.tencent.jkchess/files",
        "/data/local/tmp/jcc-scan-out",
        "/sdcard/Android/data/com.tencent.jkchess/files",
        0,
    };
    int i;
    g_nroots = 0;
    for (i = 0; cands[i] && g_nroots < 8; i++) {
        ensure_dir(cands[i]);
        snprintf(g_files_roots[g_nroots], sizeof(g_files_roots[0]), "%s", cands[i]);
        g_nroots++;
    }
}

static void canary_all(const char *msg) {
    char path[320];
    int i;
    LOGI("%s", msg);
    for (i = 0; i < g_nroots; i++) {
        snprintf(path, sizeof(path), "%s/jcc_scan_status.txt", g_files_roots[i]);
        raw_append(path, msg);
        snprintf(path, sizeof(path), "%s/jcc-scan/status.txt", g_files_roots[i]);
        ensure_dir(g_files_roots[i]);
        {
            char dir[300];
            snprintf(dir, sizeof(dir), "%s/jcc-scan", g_files_roots[i]);
            ensure_dir(dir);
            snprintf(path, sizeof(path), "%s/status.txt", dir);
            raw_append(path, msg);
        }
    }
    raw_append("/data/local/tmp/jcc-scan-out/status.txt", msg);
    raw_append("/data/local/tmp/jcc_scan_alive.txt", msg);
}

static void pick_out(void) {
    char t[300];
    int i, fd;
    /* 优先能真正 create 文件的根 */
    for (i = 0; i < g_nroots; i++) {
        char dir[300];
        snprintf(dir, sizeof(dir), "%s/jcc-scan", g_files_roots[i]);
        ensure_dir(dir);
        snprintf(t, sizeof(t), "%s/.w", dir);
        fd = open(t, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd >= 0) {
            write(fd, "1", 1);
            close(fd);
            unlink(t);
            snprintf(g_out, sizeof(g_out), "%s", dir);
            return;
        }
    }
    snprintf(g_out, sizeof(g_out), "/data/local/tmp/jcc-scan-out");
    ensure_dir(g_out);
}

static void status(const char *msg) {
    char path[320];
    canary_all(msg);
    if (g_out[0]) {
        snprintf(path, sizeof(path), "%s/status.txt", g_out);
        raw_append(path, msg);
    }
}

static void init_api(void *handle) {
#define DO_API(r, n, p)                     \
    do {                                    \
        n = (r(*) p)xdl_sym(handle, #n, 0); \
    } while (0)
#include "il2cpp-api-functions.h"
#undef DO_API
    if (il2cpp_domain_get_assemblies) {
        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (dladdr((void *)il2cpp_domain_get_assemblies, &info) && info.dli_fbase)
            g_base = (uint64_t)(uintptr_t)info.dli_fbase;
    }
}

static Il2CppClass *find_class_ns(const char *ns, const char *name) {
    size_t n = 0, i;
    const Il2CppAssembly **asms;
    Il2CppDomain *domain;
    if (!il2cpp_domain_get || !il2cpp_domain_get_assemblies || !il2cpp_assembly_get_image ||
        !il2cpp_class_from_name)
        return 0;
    domain = il2cpp_domain_get();
    if (!domain) return 0;
    asms = il2cpp_domain_get_assemblies(domain, &n);
    if (!asms) return 0;
    for (i = 0; i < n; i++) {
        const Il2CppImage *img = il2cpp_assembly_get_image(asms[i]);
        Il2CppClass *k;
        if (!img) continue;
        if (ns && ns[0]) {
            k = il2cpp_class_from_name(img, ns, name);
            if (k) return k;
        }
        k = il2cpp_class_from_name(img, "", name);
        if (k) return k;
    }
    return 0;
}

static Il2CppClass *find_class(const char *ns, const char *name) {
    static const char *try_ns[] = {"ZGameClient", "ZGame", "ZGameChess", "", 0};
    Il2CppClass *k;
    int i;
    if (ns && ns[0]) {
        k = find_class_ns(ns, name);
        if (k) return k;
    }
    for (i = 0; try_ns[i]; i++) {
        k = find_class_ns(try_ns[i], name);
        if (k) return k;
    }
    return 0;
}

static void dump_fields_only(FILE *rep, FILE *offh, FILE *json, Il2CppClass *klass,
                             const char *name) {
    void *iter = 0;
    FieldInfo *field;
    const char *ns = "";
    int nfield = 0, first = 1;
    if (!klass) return;
    if (il2cpp_class_get_namespace) ns = il2cpp_class_get_namespace(klass);
    if (!ns) ns = "";

    fprintf(rep, "### %s ns=%s\n", name, ns);
    fprintf(offh, "/* %s ns=%s */\nenum jcc_off_%s {\n", name, ns, name);
    fprintf(json, "  \"%s\":{\"ns\":\"%s\",\"found\":true,\"fields\":[", name, ns);

    while ((field = il2cpp_class_get_fields(klass, &iter)) != 0) {
        const char *fn = il2cpp_field_get_name(field);
        size_t foff;
        if (!fn) continue;
        foff = il2cpp_field_get_offset(field);
        fprintf(rep, "| 0x%zx | %s |\n", foff, fn);
        fprintf(offh, "    JCC_%s_%s = %u, /* 0x%zx */\n", name, fn, (unsigned)foff, foff);
        if (!first) fputc(',', json);
        first = 0;
        fprintf(json, "{\"name\":\"%s\",\"offset\":%u}", fn, (unsigned)foff);
        nfield++;
        if (nfield >= 300) break;
    }
    fprintf(offh, "};\n\n");
    fprintf(json, "],\"field_count\":%d},\n", nfield);
    fprintf(rep, "fields=%d\n\n", nfield);
    fflush(rep);
    fflush(offh);
    fflush(json);
}

static void write_aliases(FILE *offh) {
    Il2CppClass *hero = find_class("ZGameClient", "TACG_Hero_Client");
    static const char *keys[] = {"iID", "sName", "iCost", "sHeroPaintSmall", "iSetNum", 0};
    static const char *macros[] = {"JCC_HERO_IID", "JCC_HERO_SNAME", "JCC_HERO_ICOST",
                                   "JCC_HERO_PAINT_SMALL", "JCC_HERO_SETNUM", 0};
    int i;
    fprintf(offh, "/* aliases */\n");
    if (!hero || !il2cpp_class_get_field_from_name) return;
    for (i = 0; keys[i]; i++) {
        FieldInfo *f = il2cpp_class_get_field_from_name(hero, keys[i]);
        if (f)
            fprintf(offh, "#define %s 0x%x\n", macros[i], (unsigned)il2cpp_field_get_offset(f));
    }
}

static int write_done(int found) {
    char path[320];
    int fd;
    char line[128];
    int n;
    snprintf(path, sizeof(path), "%s/DONE", g_out);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        status("FAIL open DONE");
        return 0;
    }
    n = snprintf(line, sizeof(line), "OK found=%d out=%s\n", found, g_out);
    write(fd, line, (size_t)n);
    close(fd);
    status("SCAN_OK");
    return 1;
}

static void do_scan(void) {
    char path[320], buf[96];
    FILE *rep, *offh, *json;
    int found = 0, i;
    time_t now = time(0);

    snprintf(path, sizeof(path), "%s/SCAN_REPORT.txt", g_out);
    rep = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/offsets.h", g_out);
    offh = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/scan_report.json", g_out);
    json = fopen(path, "w");
    if (!rep || !offh || !json) {
        status("FAIL fopen report files");
        if (rep) fclose(rep);
        if (offh) fclose(offh);
        if (json) fclose(json);
        return;
    }

    fprintf(rep, "# jcc-scan v0.1.6\n# %ld\n# out=%s\n\n", (long)now, g_out);
    fprintf(offh, "/* jcc-scan v0.1.6 */\n#pragma once\n\n");
    fprintf(json, "{\n  \"generated\":%ld,\n  \"out\":\"%s\",\n  \"classes\":{\n", (long)now,
            g_out);

    for (i = 0; k_classes[i].name; i++) {
        Il2CppClass *k;
        snprintf(buf, sizeof(buf), "class %s", k_classes[i].name);
        status(buf);
        k = find_class(k_classes[i].ns, k_classes[i].name);
        if (!k) {
            fprintf(rep, "### %s MISSING\n", k_classes[i].name);
            fprintf(json, "  \"%s\":{\"found\":false},\n", k_classes[i].name);
            continue;
        }
        found++;
        dump_fields_only(rep, offh, json, k, k_classes[i].name);
        snprintf(buf, sizeof(buf), "OK %s total=%d", k_classes[i].name, found);
        status(buf);
    }
    fprintf(json, "  \"_end\":null},\n  \"classes_found\":%d\n}\n", found);
    write_aliases(offh);
    fprintf(rep, "summary found=%d\n", found);
    fclose(rep);
    fclose(offh);
    fclose(json);
    write_done(found);
}

static void *boot_thread(void *arg) {
    int i;
    char buf[80];
    (void)arg;
    status("boot_thread");
    pick_out();
    snprintf(buf, sizeof(buf), "out=%s", g_out);
    status(buf);

    for (i = 0; i < 90; i++) {
        void *h = xdl_open("libil2cpp.so", 0);
        if (!h) h = dlopen("libil2cpp.so", RTLD_NOW);
        if (h) {
            snprintf(buf, sizeof(buf), "il2cpp +%ds", i);
            status(buf);
            init_api(h);
            if (!il2cpp_domain_get) {
                status("FAIL no domain_get");
                return 0;
            }
            if (il2cpp_is_vm_thread) {
                int w = 0;
                while (!il2cpp_is_vm_thread(0) && w < 45) {
                    sleep(1);
                    w++;
                    if ((w % 5) == 0) {
                        snprintf(buf, sizeof(buf), "vm_thread wait %d", w);
                        status(buf);
                    }
                }
            }
            if (il2cpp_thread_attach && il2cpp_domain_get) {
                il2cpp_thread_attach(il2cpp_domain_get());
                status("attached");
            }
            sleep(2);
            status("scan start");
            do_scan();
            status("scan end");
            return 0;
        }
        if ((i % 5) == 0) {
            snprintf(buf, sizeof(buf), "wait il2cpp %d", i);
            status(buf);
        }
        sleep(1);
    }
    status("FAIL no il2cpp");
    return 0;
}

static void start_once(void) {
    pthread_t t;
    pthread_attr_t attr;
    if (g_started) return;
    g_started = 1;

    discover_roots();
    canary_all("constructor_entered");
    canary_all("ALIVE");

    /* 线程失败则同步跑，保证至少有进度 */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, boot_thread, 0) != 0) {
        canary_all("pthread_fail_sync_boot");
        boot_thread(0);
    }
    pthread_attr_destroy(&attr);
}

/* dlopen 时执行 */
VIS void jcc_scan_entry(void) { start_once(); }

__attribute__((constructor)) static void on_load(void) {
    start_once();
}

/* 部分注入器会调 JNI_OnLoad */
typedef struct JavaVM_ JavaVM;
#define JNI_VERSION_1_6 0x00010006
VIS int JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    canary_all("JNI_OnLoad");
    start_once();
    return JNI_VERSION_1_6;
}
