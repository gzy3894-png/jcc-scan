/*
 * libJCC.so — 注入游戏进程后跑（纯 C）
 * 扫 IL2CPP 类字段/方法 RVA → /sdcard/Download/jcc-scan/
 */
#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"
#include "log.h"
#include "scan_targets.h"
#include "xdl.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

static const char *k_pkg_files = "/data/user/0/com.tencent.jkchess/files";
static uint64_t g_base;
static char g_out[256];

static void ensure_dir(const char *p) {
    mkdir(p, 0777);
    chmod(p, 0777);
}

static int pick_out(void) {
    const char *cands[] = {
        "/sdcard/Download/jcc-scan",
        "/storage/emulated/0/Download/jcc-scan",
        "/data/local/tmp/jcc-scan-out",
        0,
    };
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
                return 1;
            }
        }
    }
    snprintf(g_out, sizeof(g_out), "%s/jcc-scan", k_pkg_files);
    ensure_dir(g_out);
    return 1;
}

static void status(const char *msg) {
    char path[320];
    FILE *f;
    LOGI("%s", msg);
    snprintf(path, sizeof(path), "%s/status.txt", g_out);
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "[%ld] %s\n", (long)time(0), msg);
        fclose(f);
    }
    snprintf(path, sizeof(path), "%s/jcc_scan_status.txt", k_pkg_files);
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "[%ld] %s\n", (long)time(0), msg);
        fclose(f);
    }
}

static void init_api(void *handle) {
#define DO_API(r, n, p)                       \
    n = (r(*) p)xdl_sym(handle, #n, 0);       \
    if (!n) LOGW("missing api %s", #n);
#include "il2cpp-api-functions.h"
#undef DO_API
    if (il2cpp_domain_get_assemblies) {
        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (dladdr((void *)il2cpp_domain_get_assemblies, &info) && info.dli_fbase)
            g_base = (uint64_t)(uintptr_t)info.dli_fbase;
    }
}

static Il2CppClass *find_class(const char *ns, const char *name) {
    size_t n = 0, i, j, cnt;
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
    if (!il2cpp_image_get_class || !il2cpp_image_get_class_count || !il2cpp_class_get_name)
        return 0;
    for (i = 0; i < n; i++) {
        const Il2CppImage *img = il2cpp_assembly_get_image(asms[i]);
        if (!img) continue;
        cnt = il2cpp_image_get_class_count(img);
        for (j = 0; j < cnt; j++) {
            Il2CppClass *k = (Il2CppClass *)il2cpp_image_get_class(img, j);
            const char *cn;
            if (!k) continue;
            cn = il2cpp_class_get_name(k);
            if (cn && strcmp(cn, name) == 0) return k;
        }
    }
    return 0;
}

static void dump_class(FILE *rep, FILE *offh, FILE *json, Il2CppClass *klass, const char *name) {
    void *iter = 0;
    FieldInfo *field;
    const MethodInfo *method;
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
        size_t foff = il2cpp_field_get_offset(field);
        const char *tn = "?";
        if (!fn) continue;
        if (il2cpp_field_get_type && il2cpp_class_from_type && il2cpp_class_get_name) {
            const Il2CppType *ft = il2cpp_field_get_type(field);
            Il2CppClass *fc = il2cpp_class_from_type(ft);
            if (fc) {
                const char *x = il2cpp_class_get_name(fc);
                if (x) tn = x;
            }
        }
        fprintf(rep, "| 0x%zx | %s | %s |\n", foff, tn, fn);
        fprintf(offh, "    JCC_%s_%s = %u, /* %s 0x%zx */\n", name, fn, (unsigned)foff, tn, foff);
        if (!first) fputc(',', json);
        first = 0;
        fprintf(json, "{\"name\":\"%s\",\"type\":\"%s\",\"offset\":%u}", fn, tn, (unsigned)foff);
        nfield++;
    }
    fprintf(offh, "};\n\n");
    fprintf(json, "],\"field_count\":%d,\"methods\":[", nfield);

    first = 1;
    iter = 0;
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
    }
    fprintf(json, "],\"method_count\":%d},\n", nmeth);
    fprintf(rep, "fields=%d methods=%d\n\n", nfield, nmeth);
}

static void resolve_methods(FILE *rep, FILE *json) {
    int ci, mi, argc, first = 1;
    fprintf(rep, "## method resolve\n");
    fprintf(json, "  \"method_resolve\":[");
    for (ci = 0; k_classes[ci].name; ci++) {
        Il2CppClass *klass = find_class(k_classes[ci].ns, k_classes[ci].name);
        if (!klass || !il2cpp_class_get_method_from_name) continue;
        for (mi = 0; k_methods[mi]; mi++) {
            for (argc = 0; argc <= 4; argc++) {
                const MethodInfo *m =
                    il2cpp_class_get_method_from_name(klass, k_methods[mi], argc);
                uint64_t rva = 0;
                if (!m) continue;
                if (m->methodPointer && g_base)
                    rva = (uint64_t)(uintptr_t)m->methodPointer - g_base;
                fprintf(rep, "OK %s.%s argc=%d RVA=0x%llx\n", k_classes[ci].name, k_methods[mi],
                        argc, (unsigned long long)rva);
                if (!first) fputc(',', json);
                first = 0;
                fprintf(json,
                        "{\"class\":\"%s\",\"method\":\"%s\",\"argc\":%d,\"rva\":%llu}",
                        k_classes[ci].name, k_methods[mi], argc, (unsigned long long)rva);
                break;
            }
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
            fprintf(offh, "#define %s 0x%x\n", macros[i],
                    (unsigned)il2cpp_field_get_offset(f));
    }
}

/* 尝试轻量调用 SearchACGHero2 采样几条，验证表可读（对局/大厅均可） */
static void sample_heroes(FILE *rep) {
    Il2CppClass *db;
    const MethodInfo *m = 0;
    Il2CppObject *inst = 0;
    int id, hit = 0;
    if (!il2cpp_runtime_invoke || !il2cpp_class_get_method_from_name) return;
    db = find_class("ZGame", "DataBaseManager");
    if (!db) db = find_class("", "DataBaseManager");
    if (!db) {
        fprintf(rep, "## sample_heroes: DataBaseManager missing\n");
        return;
    }
    m = il2cpp_class_get_method_from_name(db, "SearchACGHero2", 1);
    if (!m) m = il2cpp_class_get_method_from_name(db, "SearchACGHero", 1);
    if (!m) {
        fprintf(rep, "## sample_heroes: SearchACGHero* missing\n");
        return;
    }
    {
        const MethodInfo *gi = il2cpp_class_get_method_from_name(db, "get_Instance", 0);
        Il2CppException *exc = 0;
        if (gi) inst = il2cpp_runtime_invoke(gi, 0, 0, &exc);
    }
    if (!inst) {
        fprintf(rep, "## sample_heroes: get_Instance null (进大厅/对局后再扫更好)\n");
        return;
    }
    fprintf(rep, "## sample_heroes (probe id 1..8000)\n");
    for (id = 1; id <= 8000 && hit < 30; id++) {
        void *params[1];
        int32_t hid = id;
        Il2CppException *exc = 0;
        Il2CppObject *hero;
        params[0] = &hid;
        hero = il2cpp_runtime_invoke(m, inst, params, &exc);
        if (exc || !hero) continue;
        {
            /* 读 iID@0x10 iCost@0x60 粗验证 */
            char *base = (char *)hero;
            int32_t iid = *(int32_t *)(base + 0x10);
            int32_t cost = *(int32_t *)(base + 0x60);
            if (cost >= 1 && cost <= 5) {
                fprintf(rep, "  id=%d iid=%d cost=%d ptr=%p\n", id, iid, cost, (void *)hero);
                hit++;
            }
        }
    }
    fprintf(rep, "sample_hit=%d\n\n", hit);
}

static void do_scan(void) {
    char path[320];
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
        status("FAIL open out files");
        if (rep) fclose(rep);
        if (offh) fclose(offh);
        if (json) fclose(json);
        return;
    }

    fprintf(rep, "# JCC on-device scan (pure C)\n# time=%ld\n# out=%s\n# il2cpp_base=0x%llx\n\n",
            (long)now, g_out, (unsigned long long)g_base);
    fprintf(offh, "/* auto-generated by libJCC.so (jcc-scan) */\n#pragma once\n/* %ld */\n\n",
            (long)now);
    fprintf(json, "{\n  \"generated\":%ld,\n  \"out\":\"%s\",\n  \"il2cpp_base\":%llu,\n  \"classes\":{\n",
            (long)now, g_out, (unsigned long long)g_base);

    for (i = 0; k_classes[i].name; i++) {
        Il2CppClass *k = find_class(k_classes[i].ns, k_classes[i].name);
        if (!k) {
            fprintf(rep, "### %s  MISSING\n\n", k_classes[i].name);
            fprintf(json, "  \"%s\":{\"found\":false},\n", k_classes[i].name);
            continue;
        }
        found++;
        dump_class(rep, offh, json, k, k_classes[i].name);
    }
    fprintf(json, "  \"_end\":null},\n");

    resolve_methods(rep, json);
    write_aliases(offh);
    sample_heroes(rep);

    fprintf(json, "  \"classes_found\":%d\n}\n", found);
    fprintf(rep, "## summary classes_found=%d\n", found);

    fclose(rep);
    fclose(offh);
    fclose(json);

    snprintf(path, sizeof(path), "%s/DONE", g_out);
    {
        FILE *d = fopen(path, "w");
        if (d) {
            fprintf(d, "OK time=%ld found=%d out=%s\n", (long)now, found, g_out);
            fclose(d);
        }
    }
    {
        char msg[160];
        snprintf(msg, sizeof(msg), "SCAN_OK found=%d -> %s", found, g_out);
        status(msg);
    }
}

static void *boot_thread(void *arg) {
    int i;
    char buf[80];
    (void)arg;
    pick_out();
    {
        char path[320];
        FILE *f;
        snprintf(path, sizeof(path), "%s/status.txt", g_out);
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "boot\n");
            fclose(f);
        }
    }
    status("waiting libil2cpp.so (可在大厅/对局中等待)");

    for (i = 0; i < 240; i++) {
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
                    status("wait il2cpp_init...");
                    sleep(1);
                    w++;
                }
            }
            if (il2cpp_thread_attach && il2cpp_domain_get)
                il2cpp_thread_attach(il2cpp_domain_get());

            /* 多等一会让表/对局对象加载：先扫结构，再重试采样 */
            status("delay 8s for tables...");
            sleep(8);
            status("scanning structures...");
            do_scan();

            /* 若 sample 可能空，对局中再扫一次 */
            status("second pass in 45s (对局中数据更全)...");
            sleep(45);
            status("second scan...");
            do_scan();
            status("all passes done");
            return 0;
        }
        if (i % 15 == 0) {
            snprintf(buf, sizeof(buf), "wait il2cpp %d/240", i);
            status(buf);
        }
        sleep(1);
    }
    status("FAIL libil2cpp not found");
    return 0;
}

__attribute__((constructor)) static void on_load(void) {
    pthread_t t;
    LOGI("libJCC.so constructor (jcc-scan pure C)");
    pthread_create(&t, 0, boot_thread, 0);
    pthread_detach(t);
}
