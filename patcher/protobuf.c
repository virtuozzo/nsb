#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "include/context.h"
#include "include/protobuf.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/util.h"
#include <protobuf/binpatch.pb-c.h>
#include <protobuf/funcjump.pb-c.h>

static struct func_jump_s *create_funcjump(const FuncJump *fj)
{
	struct func_jump_s *func_jump;

	func_jump = xzalloc(sizeof(struct func_jump_s));
	if (!func_jump)
		return NULL;

	func_jump->name = strdup(fj->name);
	if (!func_jump->name)
		return NULL;

	func_jump->func_value = fj->func_value;
	func_jump->func_size = fj->func_size;
	func_jump->patch_value = fj->patch_value;
	func_jump->shndx = fj->shndx;
	return func_jump;
}

static int set_patch_func_jumps(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct func_jump_s **func_jumps;

	func_jumps = xmalloc(sizeof(struct func_jump_s *) * bp->n_func_jumps);
	if (!func_jumps)
		return -ENOMEM;

	for (i = 0; i < bp->n_func_jumps; i++) {
		func_jumps[i] = create_funcjump(bp->func_jumps[i]);
		if (!func_jumps[i])
			return -ENOMEM;
	}
	patch_info->n_func_jumps = bp->n_func_jumps;
	patch_info->func_jumps = func_jumps;
	return 0;
}

static struct marked_sym_s *create_manual_sym(const MarkedSym *ms)
{
	struct marked_sym_s *manual_sym;

	manual_sym = xmalloc(sizeof(struct marked_sym_s));
	if (!manual_sym)
		return NULL;

	manual_sym->idx = ms->idx;
	manual_sym->addr = ms->addr;
	return manual_sym;
}

static int set_patch_manual_syms(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct marked_sym_s **manual_syms;

	manual_syms = xmalloc(sizeof(struct marked_sym_s *) * bp->n_manual_symbols);
	if (!manual_syms)
		return -ENOMEM;

	for (i = 0; i < bp->n_manual_symbols; i++) {
		manual_syms[i] = create_manual_sym(bp->manual_symbols[i]);
		if (!manual_syms[i])
			return -ENOMEM;
	}
	patch_info->n_manual_syms = bp->n_manual_symbols;
	patch_info->manual_syms = manual_syms;
	return 0;
}

static struct marked_sym_s *create_global_sym(const MarkedSym *ms)
{
	struct marked_sym_s *global_sym;

	global_sym = xmalloc(sizeof(struct marked_sym_s));
	if (!global_sym)
		return NULL;

	global_sym->idx = ms->idx;
	global_sym->addr = ms->addr;
	return global_sym;
}

static int set_patch_global_syms(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct marked_sym_s **global_syms;

	global_syms = xmalloc(sizeof(struct marked_sym_s *) * bp->n_global_symbols);
	if (!global_syms)
		return -ENOMEM;

	for (i = 0; i < bp->n_global_symbols; i++) {
		global_syms[i] = create_global_sym(bp->global_symbols[i]);
		if (!global_syms[i])
			return -ENOMEM;
	}
	patch_info->n_global_syms = bp->n_global_symbols;
	patch_info->global_syms = global_syms;
	return 0;
}

static struct static_sym_s *create_static_sym(const StaticSym *ss)
{
	struct static_sym_s *static_sym;

	static_sym = xmalloc(sizeof(struct static_sym_s));
	if (!static_sym)
		return NULL;

	static_sym->patch_size = ss->patch_size;
	static_sym->patch_address = ss->patch_address;
	static_sym->target_value = ss->target_value;
	return static_sym;
}

static int set_patch_static_syms(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct static_sym_s **static_syms;

	static_syms = xmalloc(sizeof(struct static_sym_s *) * bp->n_static_symbols);
	if (!static_syms)
		return -ENOMEM;

	for (i = 0; i < bp->n_static_symbols; i++) {
		static_syms[i] = create_static_sym(bp->static_symbols[i]);
		if (!static_syms[i])
			return -ENOMEM;
	}
	patch_info->n_static_syms = bp->n_static_symbols;
	patch_info->static_syms = static_syms;
	return 0;
}

int unpack_protobuf_binpatch(struct patch_info_s *patch_info, const void *data, size_t size)
{
	int err = -ENOMEM;
	BinPatch *bp;

	bp = bin_patch__unpack(NULL, size, data);
	if (!bp) {
		pr_err("failed to unpack patch info\n");
		return -ENOMEM;
	}

	patch_info->target_bid = strdup(bp->old_bid);
	patch_info->patch_arch_type = strdup(bp->new_arch_type);
	if (!patch_info->target_bid)
		goto free_unpacked;

	patch_info->patch_bid = strdup(bp->new_bid);
	if (!patch_info->patch_bid)
		goto free_target_bid;

	if (set_patch_func_jumps(patch_info, bp))
		goto free_patch_bid;

	if (set_patch_manual_syms(patch_info, bp))
		goto free_func_jumps;

	if (set_patch_global_syms(patch_info, bp))
		goto free_manual_syms;

	if (set_patch_static_syms(patch_info, bp))
		goto free_global_syms;

	err = 0;

free_unpacked:
	bin_patch__free_unpacked(bp, NULL);
	return err;

free_global_syms:
	// TODO
free_manual_syms:
	// TODO
free_func_jumps:
	// TODO
free_patch_bid:
	free(patch_info->patch_bid);
free_target_bid:
	free(patch_info->target_bid);
	goto free_unpacked;
}
