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

static ssize_t read_protobuf_binpatch(const char *path, void **patch)
{
	uint8_t *data;
	ssize_t res;
	struct stat st;

	if (stat(path, &st)) {
		pr_perror("failed to stat %s", path);
		return -errno;
	}

	if (!st.st_size) {
		pr_err("patch %s has zero size\n", path);
		return -EINVAL;
	}

	data = xzalloc(st.st_size);
	if (!data)
		return -ENOMEM;

	res = read_file(path, data, 0, st.st_size);
	if (res < 0)
		goto free_data;

	*patch = data;
	return res;

free_data:
	free(data);
	return res;
}

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

static struct static_sym_s *create_static_sym(const StaticSym *ss)
{
	struct static_sym_s *static_sym;

	static_sym = xmalloc(sizeof(struct static_sym_s));
	if (!static_sym)
		return NULL;

	static_sym->idx = ss->idx;
	static_sym->addr = ss->addr;
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

	patch_info->old_bid = strdup(bp->old_bid);
	if (!patch_info->old_bid)
		goto free_unpacked;

	patch_info->new_bid = strdup(bp->new_bid);
	if (!patch_info->new_bid)
		goto free_old_bid;

	if (bp->new_path) {
		patch_info->path = strdup(bp->new_path);
		if (!patch_info->path)
			goto free_new_bid;
	}

	if (set_patch_func_jumps(patch_info, bp))
		goto free_new_path;

	if (set_patch_static_syms(patch_info, bp))
		goto free_func_jumps;

	err = 0;

free_unpacked:
	bin_patch__free_unpacked(bp, NULL);
	return err;

free_func_jumps:
	// TODO
free_new_path:
	if (bp->new_path)
		free(patch_info->path);
free_new_bid:
	free(patch_info->new_bid);
free_old_bid:
	free(patch_info->old_bid);
	goto free_unpacked;
}

char *protobuf_get_bid(const char *patchfile)
{
	char *bid = NULL;
	BinPatch *bp;
	void *data = NULL;
	ssize_t res;

	res = read_protobuf_binpatch(patchfile, &data);
	if (res < 0)
		return NULL;

	bp = bin_patch__unpack(NULL, res, data);
	if (!bp) {
		pr_err("failed to unpack patch_info\n");
		goto free_data;
	}

	bid = xstrdup(bp->old_bid);

	bin_patch__free_unpacked(bp, NULL);
free_data:
	free(data);
	return bid;
}
