#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

#include <stdint.h>

#define VZPATCH_SECTION		"vzpatch"

struct backtrace_s;
struct process_ctx_s;

int patch_process(pid_t pid, const char *patchfile, int dry_run);
int check_process(pid_t pid, const char *patchfile);

struct dl_map;
struct patch_s;
int create_patch_by_dlm(struct process_ctx_s *ctx, const struct dl_map *dlm,
			struct patch_s **patch);

struct patch_s *find_patch_by_bid(struct process_ctx_s *ctx, const char *bid);

#endif /* __PATCHER_PATCH_H__ */
