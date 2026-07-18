/*
 * libJCC.so — 注入游戏进程后跑（纯 C）
 *
 * 关键修复（对照 v0.1.4 日志）：
 *  - 注入其实成功了，但扫表在 app uid 下写 /sdcard 常失败
 *  - 结果主目录改为游戏私有 files/jcc-scan/
 *  - 禁止全程序集暴力扫类（过慢，180s 超时）
 *  - 字段优先，方法限量；进度高频写 status
 */
#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"
#include "log.h"
#include "scan_targets.h"
#include "xdl.h"

#include <dlfcn.h>
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

static const char *k_pkg_files = "/data/user/0/com.tencent.jkchess/files";
static uint64_t g_base;
static char g_out[256];

static void ensure_dir(const char *p) {
    mkdir(p, 0777);
    chmod(p, 0777);
}

/* 游戏进程只能稳定写自己的 files；sdcard 仅作尝试 */
static int pick_out(void) {
    char t[300];
    FILE *f;

    snprintf(g_out, sizeof(g_out), "%s/jcc-scan", k_pkg_files);
    ensure_dir(g_out);
    snprintf(t, sizeof(t), "%s/.w", g_out);
    f = fopen(t, "w");
    if (f) {
        fputc('1', f);
        fclose(f);
        unlink(t);
        return 1;
    }

    /* 极端：files 也写不了时退 tmp（一般 root 注入后仍是 app uid） */
    snprintf(g_out, sizeof(g_out), "/data/local/tmp/jcc-scan-out");
    ensure_dir(g_out);
    return 1;
}

static void status_to(const char *path, const char *msg) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "[%ld] %s\n", (long)time(0), msg);
    fflush(f);
    fclose(f);
}

static void status(const char *msg) {
    char path[320];
    LOGI("%s", msg);
    if (g_out[0]) {
        snprintf(path, sizeof(path), "%s/status.txt", g_out);
        status_to(path, msg);
    }
    /* 主机优先读这个（app 可写） */
    snprintf(path, sizeof(path), "%s/jcc_scan_status.txt", k_pkg_files);
    status_to(path, msg);
}

static void init_api(void *handle) {
#define DO_API(r, n, p)                     \
    do {                                    \
        n = (r(*) p)xdl_sym(handle, #n, 0); \
        if (!n) LOGW("missing api %s", #n); \
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

/* 只 class_from_name，不扫全量类表 */
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
    static const char *k_try_ns[] = {
        "ZGameClient", "ZGame", "ZGameChess", "", "TableCore", "CSharpJce", 0,
    };
    Il2CppClass *k;
    int i;

    if (ns && ns[0]) {
        k = find_class_ns(ns, name);
        if (k) return k;
    }
    for (i = 0; k_try_ns[i]; i++) {
        if (ns && ns[0] && strcmp(ns, k_try_ns[i]) == 0) continue;
        k = find_class_ns(k_try_ns[i], name);
        if (k) return k;
    }
    return 0;
}

/* dump_methods=0 只字段（快、稳） */
static void dump_class(FILE *rep, FILE *offh, FILE *json, Il2CppClass *klass, const char *name,
                       int dump_methods) {
    void *iter = 0;
    FieldInfo *field;
    const char *ns = "";
    int nfield = 0, nmeth = 0, first;
    if (!klass) return;
    if (il2cpp_class_get_namespace) ns = il2cpp_class_get_namespace(klass);
    if (!ns) ns = "";

    fprintf(rep, "### %s  ns=%s\n", name, ns);
    fprintf(rep, "| offset | type | name |\n|--------|------|------|\n");
    fprintf(offh, "/* class %s ns=%s */\nenum jcc_off_%s {\n", name, ns, name);
    fprintf(json, "  \"%s\":{\"ns\":\"%s\",\"found\":true,\"fields\":[", name, ns);

    first = 1;
    iter = 0;
    while ((field = il2cpp_class_get_fields(klass, &iter)) != 0) {
        const char *fn = il2cpp_field_get_name(field);
        size_t foff;
        const char *tn = "?";
        if (!fn) continue;
        foff = il2cpp_field_get_offset(field);
        /* 类型解析可能触发未初始化 class，失败则跳过类型名 */
        if (il2cpp_field_get_type && il2cpp_class_from_type && il2cpp_class_get_name) {
            const Il2CppType *ft = il2cpp_field_get_type(field);
            if (ft) {
                Il2CppClass *fc = il2cpp_class_from_type(ft);
                if (fc) {
                    const char *x = il2cpp_class_get_name(fc);
                    if (x) tn = x;
                }
            }
        }
        fprintf(rep, "| 0x%zx | %s | %s |\n", foff, tn, fn);
        fprintf(offh, "    JCC_%s_%s = %u, /* %s 0x%zx */\n", name, fn, (unsigned)foff, tn, foff);
        if (!first) fputc(',', json);
        first = 0;
        fprintf(json, "{\"name\":\"%s\",\"type\":\"%s\",\"offset\":%u}", fn, tn, (unsigned)foff);
        nfield++;
        if (nfield >= 400) break; /* 防御 */
    }
    fprintf(offh, "};\n\n");
    fprintf(json, "],\"field_count\":%d,\"methods\":[", nfield);

    if (dump_methods && il2cpp_class_get_methods && il2cpp_method_get_name) {
        const MethodInfo *method;
        iter = 0;
        first = 1;
        fprintf(rep, "methods:\n");
        while ((method = il2cpp_class_get_methods(klass, &iter)) != 0) {
            const char *mn = il2cpp_method_get_name(method);
            uint64_t rva = 0;
            int argc = -1;
            if (!mn) continue;
            if (method->methodPointer && g_base)
                rva = (uint64_t)(uintptr_t)method->methodPointer - g_base;
            if (il2cpp_method_get_param_count) argc = (int)il2cpp_method_get_param_count(method);
            fprintf(rep, "  - %s argc=%d RVA=0x%llx\n", mn, argc, (unsigned long long)rva);
            if (!first) fputc(',', json);
            first = 0;
            fprintf(json, "{\"name\":\"%s\",\"argc\":%d,\"rva\":%llu}", mn, argc,
                    (unsigned long long)rva);
            nmeth++;
            if (nmeth >= 60) break; /* 限量 */
        }
    }
    fprintf(json, "],\"method_count\":%d},\n", nmeth);
    fprintf(rep, "fields=%d methods=%d\n\n", nfield, nmeth);
    fflush(rep);
    fflush(offh);
    fflush(json);
}

static void resolve_methods_light(FILE *rep, FILE *json) {
    /* 只在已找到的关键类上解析少量方法 */
    static const struct {
        const char *ns;
        const char *cls;
        const char *m;
    } hits[] = {
        {"ZGame", "DataBaseManager", "SearchACGHero2"},
        {"ZGame", "DataBaseManager", "SearchACGHero"},
        {"ZGame", "DataBaseManager", "get_Instance"},
        {"", "ChessBattleStage", "HandleRefreshBuyHero"},
        {"", "ChessBattleStage", "HandleBuyHero"},
        {"", "BuyHeroView", "OnRefreshHeroRet"},
        {"", "BuyHeroView", "ReqBuyHero"},
        {0, 0, 0},
    };
    int i, argc, first = 1;
    fprintf(rep, "## method resolve (light)\n");
    fprintf(json, "  \"method_resolve\":[");
    for (i = 0; hits[i].cls; i++) {
        Il2CppClass *klass = find_class(hits[i].ns, hits[i].cls);
        if (!klass || !il2cpp_class_get_method_from_name) continue;
        for (argc = 0; argc <= 3; argc++) {
            const MethodInfo *m = il2cpp_class_get_method_from_name(klass, hits[i].m, argc);
            uint64_t rva = 0;
            if (!m) continue;
            if (m->methodPointer && g_base)
                rva = (uint64_t)(uintptr_t)m->methodPointer - g_base;
            fprintf(rep, "OK %s.%s argc=%d RVA=0x%llx\n", hits[i].cls, hits[i].m, argc,
                    (unsigned long long)rva);
            if (!first) fputc(',', json);
            first = 0;
            fprintf(json, "{\"class\":\"%s\",\"method\":\"%s\",\"argc\":%d,\"rva\":%llu}",
                    hits[i].cls, hits[i].m, argc, (unsigned long long)rva);
            break;
        }
    }
    fprintf(json, "],\n");
    fprintf(rep, "\n");
}

static void write_aliases(FILE *offh) {
    Il2CppClass *hero = find_class("ZGameClient", "TACG_Hero_Client");
    static const char *keys[] = {"iID", "sName", "iCost", "sHeroPaintSmall", "iSetNum", "iStar",
                                 "iQuality", 0};
    static const char *macros[] = {"JCC_HERO_IID", "JCC_HERO_SNAME", "JCC_HERO_ICOST",
                                   "JCC_HERO_PAINT_SMALL", "JCC_HERO_SETNUM", "JCC_HERO_ISTAR",
                                   "JCC_HERO_IQUALITY", 0};
    int i;
    fprintf(offh, "/* cardpool aliases */\n");
    if (!hero || !il2cpp_class_get_field_from_name || !il2cpp_field_get_offset) return;
    for (i = 0; keys[i]; i++) {
        FieldInfo *f = il2cpp_class_get_field_from_name(hero, keys[i]);
        if (f)
            fprintf(offh, "#define %s 0x%x\n", macros[i], (unsigned)il2cpp_field_get_offset(f));
    }
}

/* 少量抽样，证明能 invoke */
static void sample_heroes(FILE *rep) {
    Il2CppClass *db;
    const MethodInfo *m = 0, *gi;
    Il2CppObject *inst = 0;
    Il2CppException *exc = 0;
    int id, hit = 0;
    if (!il2cpp_runtime_invoke || !il2cpp_class_get_method_from_name) return;

    db = find_class("ZGame", "DataBaseManager");
    if (!db) {
        fprintf(rep, "## sample_heroes: DataBaseManager missing\n");
        return;
    }
    m = il2cpp_class_get_method_from_name(db, "SearchACGHero2", 1);
    if (!m) m = il2cpp_class_get_method_from_name(db, "SearchACGHero", 1);
    if (!m) {
        fprintf(rep, "## sample_heroes: Search method missing\n");
        return;
    }
    gi = il2cpp_class_get_method_from_name(db, "get_Instance", 0);
    if (gi) inst = il2cpp_runtime_invoke(gi, 0, 0, &exc);
    if (!inst) {
        fprintf(rep, "## sample_heroes: get_Instance null（大厅后再扫更好）\n");
        return;
    }
    fprintf(rep, "## sample_heroes\n");
    for (id = 1; id <= 3000 && hit < 15; id++) {
        void *params[1];
        int32_t hid = id;
        Il2CppObject *hero;
        exc = 0;
        params[0] = &hid;
        hero = il2cpp_runtime_invoke(m, inst, params, &exc);
        if (exc || !hero) continue;
        {
            char *base = (char *)hero;
            int32_t cost = *(int32_t *)(base + 0x60);
            int32_t iid = *(int32_t *)(base + 0x10);
            if (cost >= 1 && cost <= 5) {
                fprintf(rep, "  id=%d iid=%d cost=%d\n", id, iid, cost);
                hit++;
            }
        }
    }
    fprintf(rep, "sample_hit=%d\n\n", hit);
    fflush(rep);
}

static int write_done(int found) {
    char path[320];
    FILE *d;
    time_t now = time(0);
    snprintf(path, sizeof(path), "%s/DONE", g_out);
    d = fopen(path, "w");
    if (!d) return 0;
    fprintf(d, "OK time=%ld found=%d out=%s\n", (long)now, found, g_out);
    fclose(d);
    /* 额外标记给主机 */
    status_to("/data/user/0/com.tencent.jkchess/files/jcc_scan_status.txt", "SCAN_OK");
    return 1;
}

static void do_scan(void) {
    char path[320];
    FILE *rep, *offh, *json;
    int found = 0, i;
    time_t now = time(0);
    char buf[128];

    snprintf(path, sizeof(path), "%s/SCAN_REPORT.txt", g_out);
    rep = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/offsets.h", g_out);
    offh = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/scan_report.json", g_out);
    json = fopen(path, "w");
    if (!rep || !offh || !json) {
        status("FAIL open out files in app files dir");
        if (rep) fclose(rep);
        if (offh) fclose(offh);
        if (json) fclose(json);
        return;
    }

    fprintf(rep, "# JCC on-device scan v0.1.5\n# time=%ld\n# out=%s\n# base=0x%llx\n\n", (long)now,
            g_out, (unsigned long long)g_base);
    fprintf(offh, "/* auto-generated libJCC.so v0.1.5 */\n#pragma once\n/* %ld */\n\n", (long)now);
    fprintf(json,
            "{\n  \"generated\":%ld,\n  \"out\":\"%s\",\n  \"il2cpp_base\":%llu,\n  \"classes\":{\n",
            (long)now, g_out, (unsigned long long)g_base);

    for (i = 0; k_classes[i].name; i++) {
        Il2CppClass *k;
        snprintf(buf, sizeof(buf), "scan class %s ...", k_classes[i].name);
        status(buf);

        k = find_class(k_classes[i].ns, k_classes[i].name);
        if (!k) {
            fprintf(rep, "### %s  MISSING\n\n", k_classes[i].name);
            fprintf(json, "  \"%s\":{\"found\":false},\n", k_classes[i].name);
            continue;
        }
        found++;
        /* 只对小表/关键类倒方法，避免卡死 */
        {
            int want_m = (strcmp(k_classes[i].name, "DataBaseManager") == 0 ||
                          strcmp(k_classes[i].name, "BuyHeroView") == 0 ||
                          strcmp(k_classes[i].name, "ChessBattleStage") == 0);
            dump_class(rep, offh, json, k, k_classes[i].name, want_m);
        }
        snprintf(buf, sizeof(buf), "OK %s (found=%d)", k_classes[i].name, found);
        status(buf);
    }
    fprintf(json, "  \"_end\":null},\n");

    status("resolve methods light...");
    resolve_methods_light(rep, json);
    write_aliases(offh);

    status("sample heroes...");
    sample_heroes(rep);

    fprintf(json, "  \"classes_found\":%d\n}\n", found);
    fprintf(rep, "## summary classes_found=%d\n", found);
    fclose(rep);
    fclose(offh);
    fclose(json);

    if (write_done(found)) {
        snprintf(buf, sizeof(buf), "SCAN_OK found=%d -> %s", found, g_out);
        status(buf);
    } else {
        status("FAIL write DONE");
    }
}

static void *boot_thread(void *arg) {
    int i;
    char buf[96];
    (void)arg;

    status("constructor_thread_start");
    pick_out();
    snprintf(buf, sizeof(buf), "boot out=%s", g_out);
    status(buf);
    status("waiting libil2cpp.so");

    for (i = 0; i < 120; i++) {
        void *h = xdl_open("libil2cpp.so", 0);
        if (h) {
            snprintf(buf, sizeof(buf), "found libil2cpp +%ds", i);
            status(buf);
            init_api(h);
            if (!il2cpp_domain_get) {
                status("FAIL il2cpp api null");
                return 0;
            }
            if (il2cpp_is_vm_thread) {
                int w = 0;
                while (!il2cpp_is_vm_thread(0) && w < 60) {
                    if ((w % 5) == 0) {
                        snprintf(buf, sizeof(buf), "wait il2cpp_init %ds", w);
                        status(buf);
                    }
                    sleep(1);
                    w++;
                }
            }
            if (il2cpp_thread_attach && il2cpp_domain_get) {
                il2cpp_thread_attach(il2cpp_domain_get());
                status("il2cpp_thread_attach ok");
            }

            status("delay 3s then scan...");
            sleep(3);
            status("scanning structures...");
            do_scan();
            status("scan finished");
            return 0;
        }
        if ((i % 5) == 0) {
            snprintf(buf, sizeof(buf), "wait libil2cpp %d/120", i);
            status(buf);
        }
        sleep(1);
    }
    status("FAIL libil2cpp not found");
    return 0;
}

__attribute__((constructor)) static void on_load(void) {
    pthread_t t;
    /* 同步打点：主机 verify 用 */
    status_to("/data/user/0/com.tencent.jkchess/files/jcc_scan_status.txt", "constructor_entered");
    LOGI("libJCC.so constructor v0.1.5");
    pthread_create(&t, 0, boot_thread, 0);
    pthread_detach(t);
}
