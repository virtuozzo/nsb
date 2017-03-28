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
	char			*target_bid;
	char			*patch_bid;

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
	const struct dl_map	*patch_dlm;
	struct list_head	list;
};

struct ctx_dep {
	struct list_head	list;
	const struct dl_map	*dlm;
};

struct process_ctx_s {
	pid_t			pid;
	const char		*patchfile;
	struct elf_info_s	*patch_ei;
	int			dry_run;
	const struct patch_ops_s *ops;
	struct parasite_ctl	*ctl;
	struct service		service;
	struct list_head	vmas;
	struct list_head	dl_maps;
	struct list_head	applied_patches;
	struct vma_area		remote_vma;
	struct list_head	needed_list;
	struct list_head	threads;
	struct patch_s		*patch;
};

#define P(ctx)			ctx->patch
#define PI(ctx)			(&P(ctx)->pi)
#define PDLM(ctx)		P(ctx)->patch_dlm
#define TDLM(ctx)		P(ctx)->target_dlm

#endif
