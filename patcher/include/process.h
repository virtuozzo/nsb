#ifndef __PATCHER_PROCESS_H__
#define __PATCHER_PROCESS_H__

#include <stdint.h>
#include <fcntl.h>

struct process_ctx_s;

int process_write_data(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size);
int process_read_data(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size);
long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size);
int process_unlink(struct process_ctx_s *ctx);
int process_cure(struct process_ctx_s *ctx);
int process_link(struct process_ctx_s *ctx);
int process_infect(struct process_ctx_s *ctx);

int process_unmap(struct process_ctx_s *ctx, off_t addr, size_t size);
int64_t process_map(struct process_ctx_s *ctx, int fd, off_t offset,
		    unsigned long addr, size_t size, int flags, int prot);

int process_open_file(struct process_ctx_s *ctx, const char *path,
			int flags, mode_t mode);
int process_close_file(struct process_ctx_s *ctx, int fd);

int process_suspend(struct process_ctx_s *ctx);

struct list_head;
int process_mmap_file(struct process_ctx_s *ctx, const char *path,
		      const struct list_head *mmaps);
int process_munmap(struct process_ctx_s *ctx,
		   const struct list_head *mmaps);

int64_t process_exec_code(struct process_ctx_s *ctx, uint64_t addr,
			  void *code, size_t code_size);

int process_release_at(struct process_ctx_s *ctx, uint64_t addr,
		       void *code, size_t code_size);
int process_acquire(struct process_ctx_s *ctx);

ssize_t process_emergency_sigframe(struct process_ctx_s *ctx, void *data,
				   void *where);

int process_inject_service(struct process_ctx_s *ctx);
int process_shutdown_service(struct process_ctx_s *ctx);

int process_collect_needed(struct process_ctx_s *ctx);

int process_collect_vmas(struct process_ctx_s *ctx);
int process_find_target_dlm(struct process_ctx_s *ctx);
int process_find_patch(struct process_ctx_s *ctx);

#endif
