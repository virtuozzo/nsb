#ifndef __PATCHER_PROCESS_H__
#define __PATCHER_PROCESS_H__

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "list.h"

struct static_sym_s {
	int32_t			idx;
	int64_t			addr;
};

struct func_jump_s {
	char			*name;
	uint64_t		func_value;
	uint32_t		func_size;
	uint64_t		patch_value;
	uint32_t		shndx;
	uint8_t			code[8];
	uint8_t			applied;
	uint64_t		func_addr;
	uint8_t			func_jump[8];
};

struct patch_info_s {
	char			*old_bid;
	char			*new_bid;
	char			*path;

	size_t			n_func_jumps;
	struct func_jump_s	**func_jumps;

	size_t			n_static_syms;
	struct static_sym_s	**static_syms;
};

struct patch_s {
	struct patch_info_s	pi;
	const struct vma_area	*vma;
	int64_t			load_addr;
	struct list_head	rela_plt;
	struct list_head	rela_dyn;
	struct elf_info_s	*ei;
	struct list_head	objdeps;
	struct list_head	segments;
};

struct ctx_dep {
	struct list_head	list;
	const struct vma_area	*vma;
};

struct process_ctx_s {
	pid_t			pid;
	const char		*patchfile;
	const struct patch_ops_s *ops;
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
	int64_t			remote_map;
	size_t			remote_map_size;
	struct list_head	objdeps;
	struct list_head	threads;
	struct patch_s		p;
};

#define P(ctx)			(&ctx->p)
#define PI(ctx)			(&ctx->p.pi)
#define PLA(ctx)		(ctx->p.load_addr)
#define PVMA(ctx)		(ctx->p.vma)

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
