#ifndef JCC_INJECT_DLOPEN_H
#define JCC_INJECT_DLOPEN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 向 pid 远程 dlopen(so_path)。成功返回 0，失败 -1 并写 err。 */
int jcc_inject_dlopen(int pid, const char *so_path, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif
