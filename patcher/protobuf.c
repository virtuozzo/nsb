#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "include/process.h"
#include "include/protobuf.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/util.h"

#include <protobuf/binpatch.pb-c.h>
#include <protobuf/segment.pb-c.h>
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

static struct segment_s *create_segment(const ElfSegment *seg)
{
	struct segment_s *segment;

	segment = xmalloc(sizeof(struct segment_s));
	if (!segment)
		return NULL;

	segment->type = strdup(seg->type);
	if (!segment->type)
		return NULL;

	segment->offset = seg->offset;
	segment->vaddr = seg->vaddr;
	segment->paddr = seg->paddr;
	segment->mem_sz = seg->mem_sz;
	segment->flags = seg->flags;
	segment->align = seg->align;
	segment->file_sz = seg->file_sz;
	return segment;
}

static int set_patch_info_segments(struct patch_info_s *patch_info, BinPatch *bp)
{
	int i;
	struct segment_s **segments;

	segments = xmalloc(sizeof(struct segment_s *) * bp->n_new_segments);
	if (!segments)
		return -ENOMEM;

	for (i = 0; i < bp->n_new_segments; i++) {
		segments[i] = create_segment(bp->new_segments[i]);
		if (!segments[i])
			return -ENOMEM;
	}
	patch_info->n_segments = bp->n_new_segments;
	patch_info->segments = segments;
	return 0;
}

static struct func_jump_s *create_funcjump(const FuncJump *fj)
{
	struct func_jump_s *func_jump;

	func_jump = xmalloc(sizeof(struct func_jump_s));
	if (!func_jump)
		return NULL;

	func_jump->name = strdup(fj->name);
	if (!func_jump->name)
		return NULL;

	func_jump->func_value = fj->func_value;
	func_jump->func_size = fj->func_size;
	func_jump->patch_value = fj->patch_value;
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

	if (set_patch_info_segments(patch_info, bp))
		goto free_local_vars;

	if (set_patch_func_jumps(patch_info, bp))
		goto free_info_segments;

	err = 0;

free_unpacked:
	bin_patch__free_unpacked(bp, NULL);
	return err;

free_info_segments:
	// TODO
free_local_vars:
	// TODO
	if (bp->new_path)
		free(patch_info->path);
free_new_bid:
	free(patch_info->new_bid);
free_old_bid:
	free(patch_info->old_bid);
	goto free_unpacked;
}

int parse_protobuf_binpatch(struct patch_info_s *patch_info, const char *patchfile)
{
	int err = -ENOMEM;
	void *data;
	ssize_t size;

	size = read_protobuf_binpatch(patchfile, &data);
	if (size < 0)
		return size;

	err = unpack_protobuf_binpatch(patch_info, data, size);

	free(data);
	return err;
}

char *protobuf_get_bid(const char *patchfile)
{
	char *bid = NULL;
	BinPatch *bp;
	void *data;
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
