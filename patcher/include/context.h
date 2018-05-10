#ifndef __PATCHER_CONTEXT_H__
#define __PATCHER_CONTEXT_H__

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "list.h"
#include "service.h"
#include "vma.h"

struct arch_cb
{
	uint64_t(*jump_min_address)(uint64_t address);
	uint64_t(*jump_max_address)(uint64_t address);
	ssize_t (*call)(uint64_t call, uint64_t where,
			uint64_t arg0, uint64_t arg1, uint64_t arg2,
			uint64_t arg3, uint64_t arg4, uint64_t arg5,
			void **code);
	ssize_t (*dlopen)(uint64_t dlopen_addr, uint64_t name_addr,
			  uint64_t where,
			  void **code);
	ssize_t (*dlclose)(uint64_t dlopen_addr, uint64_t handle,
			   uint64_t where,
			   void **code);
	int (*process_write_data)(const struct process_ctx_s *ctx,
				 uint64_t addr, const void *data, size_t size);
	int (*process_read_data)(const struct process_ctx_s *ctx,
				uint64_t addr, void *data, size_t size);
	int (*rtld_needed_array)(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
				     uint64_t **needed_array);
	int (*process_unmap_vma)(struct process_ctx_s *ctx, const struct vma_area *vma);
	int64_t (*process_map_vma)(struct process_ctx_s *ctx, int fd,
		const struct vma_area *vma);
	int (*process_close_file)(struct process_ctx_s *ctx, int fd);
	int (*process_do_open_file)(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode);

};

struct static_sym_s {
	uint32_t		patch_size;
	uint64_t		patch_address;
	uint64_t		target_value;
};

struct marked_sym_s {
	int32_t			idx;
	int64_t			addr;
};

struct func_jump_s {
	char			*name;
	uint64_t		func_value;
	uint32_t		func_size;
	uint64_t		patch_value;
	uint32_t		shndx;
	uint64_t		func_addr;
	uint8_t			code[8];
	uint8_t			func_jump[8];
};

struct patch_info_s {
	char			*target_bid;
	char			*patch_bid;

	size_t			n_func_jumps;
	struct func_jump_s	**func_jumps;

	size_t			n_manual_syms;
	struct marked_sym_s	**manual_syms;

	size_t			n_global_syms;
	struct marked_sym_s	**global_syms;

	size_t			n_static_syms;
	struct static_sym_s	**static_syms;

	char			*patch_arch_type;
};

struct patch_s {
	struct patch_info_s	pi;
	const struct dl_map	*target_dlm;
	struct list_head	rela_plt;
	struct list_head	rela_dyn;
	const struct dl_map	*patch_dlm;
	struct list_head	list;
};

struct ctx_dep {
	struct list_head	list;
	const struct dl_map	*dlm;
};

struct backtrace_s;
typedef	int (*check_backtrace_t)(const struct process_ctx_s *ctx,
				 const struct backtrace_s *bt,
				 uint64_t start, uint64_t end);

struct process_ctx_s {
	pid_t			pid;
	const char		*patchfile;
	int			dry_run;

	struct elf_info_s	*patch_ei;
	check_backtrace_t	check_backtrace;

	struct parasite_ctl	*ctl;
	struct service		service;
	struct list_head	vmas;
	struct list_head	dl_maps;
	struct list_head	applied_patches;
	struct vma_area		remote_vma;
	struct list_head	needed_list;
	struct list_head	threads;
	struct patch_s		*patch;
	const struct arch_cb        *arch_callback;
};

#define P(ctx)			ctx->patch
#define PI(ctx)			(&P(ctx)->pi)
#define PDLM(ctx)		P(ctx)->patch_dlm
#define TDLM(ctx)		P(ctx)->target_dlm

#endif
