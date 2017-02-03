#ifndef __PATCHER_PROCESS_H__
#define __PATCHER_PROCESS_H__

#include "protobuf.h"
#include "list.h"

struct funcpatch_s {
	struct list_head	list;
	FuncPatch		 *fp;
	unsigned long		 addr;
};

struct binpatch_s {
	BinPatch		 *bp;
	unsigned long		 addr;
	struct list_head	functions;
	struct list_head	places;
};

struct process_ctx_s {
	pid_t			pid;
	int			(*apply)(struct process_ctx_s *ctx);
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
	struct binpatch_s	binpatch;
	int64_t			remote_map;
	unsigned long		old_base;
	unsigned long		new_base;
	const struct vma_area	*pvma;
};

int process_write_data(pid_t pid, uint64_t addr, const void *data, size_t size);
int process_read_data(pid_t pid, uint64_t addr, void *data, size_t size);
long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size);
int process_cure(struct process_ctx_s *ctx);
int process_link(struct process_ctx_s *ctx);
int process_infect(struct process_ctx_s *ctx);

int64_t process_create_map(struct process_ctx_s *ctx, int fd, off_t offset,
			unsigned long addr, size_t size, int flags, int prot);

int process_open_file(struct process_ctx_s *ctx, const char *path,
			int flags, mode_t mode);
int process_close_file(struct process_ctx_s *ctx, int fd);

#endif
