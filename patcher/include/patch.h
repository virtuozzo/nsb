#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

struct patch_ops_s;
int check_patch_mode(const char *how);

int patch_process(pid_t pid, const char *patchfile, const char *how);
int check_process(pid_t pid, const char *patchfile);

#endif /* __PATCHER_PATCH_H__ */
