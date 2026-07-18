/*
 * arm64 ptrace 远程 dlopen — 以 maps 是否出现 so 为准，不信任 JCC.sh 文案
 */
#define _GNU_SOURCE
#include "inject_dlopen.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __aarch64__

int jcc_inject_dlopen(int pid, const char *so_path, char *err, size_t errlen) {
    (void)pid;
    (void)so_path;
    if (err && errlen) snprintf(err, errlen, "need aarch64 device build");
    return -1;
}

#else

#include <linux/elf.h>

struct user_pt_regs_arm64 {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#define RTLD_NOW_V 2

static void set_err(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg ? msg : "err");
}

static int get_regs(int pid, struct user_pt_regs_arm64 *r) {
    struct iovec iv = {.iov_base = r, .iov_len = sizeof(*r)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)(unsigned long)NT_PRSTATUS, &iv);
}

static int set_regs(int pid, struct user_pt_regs_arm64 *r) {
    struct iovec iv = {.iov_base = r, .iov_len = sizeof(*r)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)(unsigned long)NT_PRSTATUS, &iv);
}

static int write_mem(int pid, unsigned long long addr, const void *buf, size_t len) {
    struct iovec local = {.iov_base = (void *)buf, .iov_len = len};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)addr, .iov_len = len};
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == (ssize_t)len) return 0;
    {
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            long word = 0;
            if (chunk > sizeof(long)) chunk = sizeof(long);
            memcpy(&word, (const char *)buf + off, chunk);
            if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)(addr + off), (void *)word) < 0)
                return -1;
            off += sizeof(long);
        }
    }
    return 0;
}

static int maps_has(int pid, const char *sub) {
    char path[64], line[768];
    FILE *f;
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

static unsigned long long module_base_pid(int pid, const char *mod) {
    char path[64], line[768];
    FILE *f;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0;
        if (!strstr(line, mod)) continue;
        if (!strstr(line, "r-xp") && !strstr(line, "r--p") && !strstr(line, "r-x")) continue;
        if (sscanf(line, "%llx-", &start) == 1) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

static unsigned long long module_base_self(const char *mod) {
    char line[768];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0;
        if (!strstr(line, mod)) continue;
        if (!strstr(line, "r-xp") && !strstr(line, "r--p") && !strstr(line, "r-x")) continue;
        if (sscanf(line, "%llx-", &start) == 1) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

static void *dlopen_try(const char *mod) {
    void *h = dlopen(mod, RTLD_NOW);
    char full[256];
    if (h) return h;
    snprintf(full, sizeof(full), "/system/lib64/%s", mod);
    h = dlopen(full, RTLD_NOW);
    if (h) return h;
    snprintf(full, sizeof(full), "/apex/com.android.runtime/lib64/bionic/%s", mod);
    return dlopen(full, RTLD_NOW);
}

static unsigned long long remote_sym(int pid, const char *mod, const char *sym) {
    void *local = dlopen_try(mod);
    void *p;
    unsigned long long lb, rb, ls;
    if (!local) return 0;
    p = dlsym(local, sym);
    if (!p) {
        dlclose(local);
        return 0;
    }
    lb = module_base_self(mod);
    rb = module_base_pid(pid, mod);
    ls = (unsigned long long)(uintptr_t)p;
    dlclose(local);
    if (!lb || !rb || ls < lb) return 0;
    return rb + (ls - lb);
}

/* 远程调用，x0..x5 参数，返回 x0 */
static int remote_call6(int pid, unsigned long long fn, unsigned long long a0,
                        unsigned long long a1, unsigned long long a2, unsigned long long a3,
                        unsigned long long a4, unsigned long long a5, unsigned long long *ret) {
    struct user_pt_regs_arm64 old, regs;
    int st = 0;

    if (get_regs(pid, &old) < 0) return -1;
    regs = old;
    regs.regs[0] = a0;
    regs.regs[1] = a1;
    regs.regs[2] = a2;
    regs.regs[3] = a3;
    regs.regs[4] = a4;
    regs.regs[5] = a5;
    regs.pc = fn;
    regs.regs[30] = 0; /* LR=0 → 返回时崩停 */

    if (set_regs(pid, &regs) < 0) return -1;
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) return -1;
    if (waitpid(pid, &st, WUNTRACED) < 0) return -1;
    if (get_regs(pid, &regs) < 0) return -1;
    if (ret) *ret = regs.regs[0];
    if (set_regs(pid, &old) < 0) return -1;
    return 0;
}

int jcc_inject_dlopen(int pid, const char *so_path, char *err, size_t errlen) {
    unsigned long long mmap_fn, dlopen_fn, remote_buf = 0, handle = 0;
    size_t plen;
    long page;

    if (!so_path || !so_path[0]) {
        set_err(err, errlen, "empty path");
        return -1;
    }
    plen = strlen(so_path) + 1;
    page = sysconf(_SC_PAGESIZE);
    if (page < 4096) page = 4096;

    if (maps_has(pid, "libJCC.so") || maps_has(pid, so_path)) {
        set_err(err, errlen, "already in maps");
        return 0;
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        set_err(err, errlen, "PTRACE_ATTACH failed");
        return -1;
    }
    {
        int st = 0;
        if (waitpid(pid, &st, WUNTRACED) < 0) {
            set_err(err, errlen, "waitpid attach");
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return -1;
        }
    }

    mmap_fn = remote_sym(pid, "libc.so", "mmap");
    if (!mmap_fn) mmap_fn = remote_sym(pid, "libc.so", "mmap64");
    dlopen_fn = remote_sym(pid, "libdl.so", "dlopen");
    if (!dlopen_fn) dlopen_fn = remote_sym(pid, "libdl.so", "__loader_dlopen");
    if (!dlopen_fn) dlopen_fn = remote_sym(pid, "libc.so", "dlopen");

    if (!mmap_fn || !dlopen_fn) {
        char b[128];
        snprintf(b, sizeof(b), "sym fail mmap=%llx dlopen=%llx", mmap_fn, dlopen_fn);
        set_err(err, errlen, b);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    /* mmap(0, page, RW, PRIVATE|ANON, -1, 0) */
    if (remote_call6(pid, mmap_fn, 0, (unsigned long long)page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long long)-1, 0, &remote_buf) < 0 ||
        !remote_buf || remote_buf == (unsigned long long)-1) {
        set_err(err, errlen, "remote mmap failed");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    if (write_mem(pid, remote_buf, so_path, plen) < 0) {
        set_err(err, errlen, "write so path failed");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    if (remote_call6(pid, dlopen_fn, remote_buf, RTLD_NOW_V, 0, 0, 0, 0, &handle) < 0) {
        set_err(err, errlen, "remote dlopen call failed");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    ptrace(PTRACE_DETACH, pid, 0, 0);
    usleep(300000);

    if (!handle) {
        set_err(err, errlen, "dlopen returned NULL (so load failed)");
        return -1;
    }
    if (!maps_has(pid, "libJCC") && !maps_has(pid, so_path)) {
        set_err(err, errlen, "handle!=0 but maps no libJCC");
        return -1;
    }

    {
        char b[160];
        snprintf(b, sizeof(b), "ok handle=0x%llx", (unsigned long long)handle);
        set_err(err, errlen, b);
    }
    return 0;
}

#endif
