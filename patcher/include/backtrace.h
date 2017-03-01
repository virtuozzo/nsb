#ifndef __PATCHER_BACKTRACE_H__
#define __PATCHER_BACKTRACE_H__

struct backtrace_s;
int pid_backtrace(pid_t pid, struct backtrace_s **backtrace);

struct process_ctx_s;
struct func_jump_s;
int backtrace_check_func(const struct process_ctx_s *ctx,
			 const struct func_jump_s *fj,
			 const void *data);

struct vma_area;
int backtrace_check_vma(const struct backtrace_s *bt,
			const struct vma_area *vma);

#endif
