#ifndef __PATCHER_BACKTRACE_H__
#define __PATCHER_BACKTRACE_H__

struct backtrace_s;
int pid_backtrace(pid_t pid, struct backtrace_s **backtrace);
void destroy_backtrace(struct backtrace_s *bt);

struct func_jump_s;
struct vma_area;
int backtrace_check_func(const struct func_jump_s *fj,
			 const struct backtrace_s *bt,
			 const struct vma_area *vma);

int backtrace_check_vma(const struct backtrace_s *bt,
			const struct vma_area *vma);

#endif
