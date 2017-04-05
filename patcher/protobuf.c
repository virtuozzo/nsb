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

static struct marked_sym_s *create_marked_sym(const MarkedSym *ms)
{
	struct marked_sym_s *marked_sym;

	marked_sym = xmalloc(sizeof(struct marked_sym_s));
	if (!marked_sym)
		return NULL;

	marked_sym->idx = ms->idx;
	marked_sym->addr = ms->addr;
	return marked_sym;
}

static int set_patch_marked_syms(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct marked_sym_s **marked_syms;

	marked_syms = xmalloc(sizeof(struct marked_sym_s *) * bp->n_marked_symbols);
	if (!marked_syms)
		return -ENOMEM;

	for (i = 0; i < bp->n_marked_symbols; i++) {
		marked_syms[i] = create_marked_sym(bp->marked_symbols[i]);
		if (!marked_syms[i])
			return -ENOMEM;
	}
	patch_info->n_marked_syms = bp->n_marked_symbols;
	patch_info->marked_syms = marked_syms;
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
	if (!patch_info->target_bid)
		goto free_unpacked;

	patch_info->patch_bid = strdup(bp->new_bid);
	if (!patch_info->patch_bid)
		goto free_target_bid;

	if (set_patch_func_jumps(patch_info, bp))
		goto free_patch_bid;

	if (set_patch_marked_syms(patch_info, bp))
		goto free_func_jumps;

	err = 0;

free_unpacked:
	bin_patch__free_unpacked(bp, NULL);
	return err;

free_func_jumps:
	// TODO
free_patch_bid:
	free(patch_info->patch_bid);
free_target_bid:
	free(patch_info->target_bid);
	goto free_unpacked;
}
