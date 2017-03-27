#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

#include <stdint.h>

struct backtrace_s;
struct process_ctx_s;
struct patch_ops_s {
	int (*apply_patch)(struct process_ctx_s *ctx);
	int (*check_backtrace)(const struct process_ctx_s *ctx,
			       const struct backtrace_s *bt,
			       uint64_t target_base);
	int (*revert_patch)(struct process_ctx_s *ctx);
};

int patch_process(pid_t pid, const char *patchfile, int dry_run);
int check_process(pid_t pid, const char *patchfile);

#endif /* __PATCHER_PATCH_H__ */
