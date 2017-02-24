#ifndef __PATCHER_PROCESS_H__
#define __PATCHER_PROCESS_H__

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "list.h"

#ifdef STATIC_PATCHING
struct objinfo_s {
	char			*name;
	int32_t			op_size;
	int32_t			addr_size;
	int32_t			offset;
	int32_t			ref_addr;
};
#endif
struct funcpatch_s {
	char			*name;
	int64_t			addr;
	int32_t			size;
	int			new_:1;
	int			dyn:1;
	int			plt:1;
	int32_t			old_addr;

#ifdef STATIC_PATCHING
	size_t			n_objinfos;
	struct objinfo_s	**objinfos;
	void			*code;
#endif
};

struct relocation_s {
	char			*name;
	char			*info_type;
	int32_t			offset;
	int32_t			addend;
	int64_t			hint;
	char			*path;
};

struct local_var_s {
	char			*name;
	int32_t			size;
	int32_t			offset;
	int32_t			ref;
};

struct segment_s {
	char			*type;
	int32_t			offset;
	int32_t			vaddr;
	int32_t			paddr;
	int32_t			mem_sz;
	int32_t			flags;
	int32_t			align;
	int32_t			file_sz;
};

struct patch_info_s {
	char			*object_type;
	char			*old_bid;
	char			*new_bid;
	char			*new_path;
	struct list_head	places;

	size_t			n_relocations;
	struct relocation_s	**relocations;

	size_t			n_funcpatches;
	struct funcpatch_s	**funcpatches;

	size_t			n_local_vars;
	struct local_var_s	**local_vars;

	size_t			n_segments;
	struct segment_s	**segments;
};

struct patch_s {
	struct patch_info_s	pi;
	int64_t			load_addr;
};

struct process_ctx_s {
	pid_t			pid;
	const struct patch_ops_s *ops;
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
	int64_t			remote_map;
	const struct vma_area	*pvma;
	struct list_head	objdeps;
	struct list_head	threads;
	struct patch_s		p;
};

#define PI(ctx)			(&ctx->p.pi)
#define PLA(ctx)		(ctx->p.load_addr)

int process_write_data(pid_t pid, uint64_t addr, const void *data, size_t size);
int process_read_data(pid_t pid, uint64_t addr, void *data, size_t size);
long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size);
int process_cure(struct process_ctx_s *ctx);
int process_link(struct process_ctx_s *ctx);
int process_infect(struct process_ctx_s *ctx);

int process_unmap(struct process_ctx_s *ctx, off_t addr, size_t size);
int64_t process_create_map(struct process_ctx_s *ctx, int fd, off_t offset,
			unsigned long addr, size_t size, int flags, int prot);

int process_open_file(struct process_ctx_s *ctx, const char *path,
			int flags, mode_t mode);
int process_close_file(struct process_ctx_s *ctx, int fd);

struct backtrace_s;
int process_check_stack(const struct process_ctx_s *ctx,
			int (*check)(const struct process_ctx_s *ctx,
				      const struct backtrace_s *bt));

#endif
