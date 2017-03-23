#ifndef __PATCHER_CONTEXT_H__
#define __PATCHER_CONTEXT_H__

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "list.h"
#include "service.h"
#include "vma.h"

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
	uint64_t		func_addr;
	uint8_t			code[8];
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
	const struct dl_map	*target_dlm;
	struct list_head	rela_plt;
	struct list_head	rela_dyn;
	struct list_head	objdeps;
	struct dl_map		*patch_dlm;
};

struct ctx_dep {
	struct list_head	list;
	const struct dl_map	*dlm;
};

struct process_ctx_s {
	pid_t			pid;
	const char		*patchfile;
	const struct patch_ops_s *ops;
	struct parasite_ctl	*ctl;
	struct service		service;
	struct list_head	vmas;
	struct list_head	dl_maps;
	struct vma_area		remote_vma;
	struct list_head	objdeps;
	struct list_head	threads;
	struct patch_s		p;
};

#define P(ctx)			(&ctx->p)
#define PI(ctx)			(&ctx->p.pi)
#define PDLM(ctx)		(ctx->p.patch_dlm)
#define TDLM(ctx)		(ctx->p.target_dlm)

#endif
