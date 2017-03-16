#ifndef __PATCHER_PROCESS_H__
#define __PATCHER_PROCESS_H__

#include <stdint.h>
#include <fcntl.h>

struct process_ctx_s;

int process_write_data(pid_t pid, uint64_t addr, const void *data, size_t size);
int process_read_data(pid_t pid, uint64_t addr, void *data, size_t size);
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

#endif
