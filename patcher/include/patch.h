#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

#include <stdint.h>
#include <unistd.h>

int patch_process(pid_t pid, size_t mmap_size, const char *patchfile);

#endif /* __PATCHER_PATCH_H__ */
