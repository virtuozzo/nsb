#ifndef __PATCHER_PATCH_H__
#define __PATCHER_PATCH_H__

struct backtrace_s;
struct process_ctx_s;
struct patch_ops_s {
	char *name;
	int (*collect_deps)(struct process_ctx_s *ctx);
	int (*apply_patch)(struct process_ctx_s *ctx);
	int (*set_jumps)(struct process_ctx_s *ctx);
	int (*check_backtrace)(const struct process_ctx_s *ctx,
			       const struct backtrace_s *bt);
	int (*copy_data)(struct process_ctx_s *ctx);
	int (*fix_references)(struct process_ctx_s *ctx);
	int (*cleanup_target)(struct process_ctx_s *ctx);
};

#ifdef SWAP_PATCHiNG
int check_patch_mode(const char *how);
int patch_process(pid_t pid, const char *patchfile, const char *how);
#else
int patch_process(pid_t pid, const char *patchfile);
#endif
int check_process(pid_t pid, const char *patchfile);

#endif /* __PATCHER_PATCH_H__ */
