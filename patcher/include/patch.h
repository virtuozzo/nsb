#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

#include <stdint.h>

#define VZPATCH_SECTION		"vzpatch"

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

struct dl_map;
struct patch_s;
int create_patch_by_dlm(struct process_ctx_s *ctx, const struct dl_map *dlm,
			struct patch_s **patch);

#endif /* __PATCHER_PATCH_H__ */
