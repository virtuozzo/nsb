#ifndef __PATCHER_WAITSIG_H__
#define __PATCHER_WAITSIG_H__

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
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
	struct binpatch_s	binpatch;
};

int process_write_data(pid_t pid, void *addr, void *data, size_t size);
int process_read_data(pid_t pid, void *addr, void *data, size_t size);
long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size);
int process_cure(struct process_ctx_s *ctx);
int process_infect(struct process_ctx_s *ctx);

#endif
