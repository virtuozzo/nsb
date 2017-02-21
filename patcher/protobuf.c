#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "include/process.h"
#include "include/protobuf.h"
#include "include/log.h"
#include "include/xmalloc.h"

#include <protobuf/funcpatch.pb-c.h>
#include <protobuf/binpatch.pb-c.h>
#include <protobuf/objinfo.pb-c.h>
#include <protobuf/segment.pb-c.h>
#include <protobuf/relaplt.pb-c.h>

static ssize_t read_image(const char *path, uint8_t *buf, size_t max_len)
{
	int fd;
	ssize_t res;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	res = read(fd, buf, max_len);
	if (res < 0) {
		pr_perror("failed to read %s", path);
		res = -errno;
	}

	close(fd);
	return res;
}

static BinPatch *read_binpatch(const char *path)
{
	uint8_t page[4096];
	ssize_t res;
	BinPatch *patch;

	res = read_image(path, page, 4096);
	if (res < 0)
		return NULL;

	patch = bin_patch__unpack(NULL, res, page); // Deserialize the serialized input
	if (patch == NULL) {
		pr_err("failed to unpack binpatch\n");
		return NULL;
	}

	return patch;
}

static struct relocation_s *create_relocation(const RelaPlt *rp)
{
	struct relocation_s *rel;

	rel = xmalloc(sizeof(struct relocation_s));
	if (!rel)
		return rel;

	rel->name = strdup(rp->name);
	if (!rel->name)
		return NULL;
	rel->info_type = strdup(rp->info_type);
	if (!rel->info_type)
		return NULL;
	rel->path = strdup(rp->path);
	if (!rel->path)
		return NULL;
	rel->offset = rp->offset;
	rel->addend = rp->addend;
	rel->hint = rp->hint;
	return rel;
}

static int set_binpatch_relocations(struct binpatch_s *binpatch, BinPatch *bp)
{
	int i;
	struct relocation_s **relocations;

	relocations = xmalloc(sizeof(struct relocation_s *) * bp->n_relocations);
	if (!relocations)
		return -ENOMEM;

	for (i = 0; i < bp->n_relocations; i++) {
		relocations[i] = create_relocation(bp->relocations[i]);
		if (!relocations[i])
			return -ENOMEM;
	}
	binpatch->n_relocations = bp->n_relocations;
	binpatch->relocations = relocations;
	return 0;
}

static struct funcpatch_s *create_funcpatch(const FuncPatch *fp)
{
	struct funcpatch_s *funcpatch;

	funcpatch = xmalloc(sizeof(struct funcpatch_s));
	if (!funcpatch)
		return NULL;

	funcpatch->name = strdup(fp->name);
	if (!funcpatch->name)
		return NULL;

	funcpatch->addr = fp->addr;
	funcpatch->size = fp->size;
	funcpatch->new_ = fp->new_;
	funcpatch->dyn = fp->dyn;
	funcpatch->plt = fp->plt;
	funcpatch->old_addr = 0;
	if (fp->has_old_addr)
		funcpatch->old_addr = fp->old_addr;
	return funcpatch;
}

static int set_binpatch_funcpatches(struct binpatch_s *binpatch, BinPatch *bp)
{
	int i;
	struct funcpatch_s **funcpatches;

	funcpatches = xmalloc(sizeof(struct funcpatch_s *) * bp->n_patches);
	if (!funcpatches)
		return -ENOMEM;

	for (i = 0; i < bp->n_patches; i++) {
		funcpatches[i] = create_funcpatch(bp->patches[i]);
		if (!funcpatches[i])
			return -ENOMEM;
	}
	binpatch->n_funcpatches = bp->n_patches;
	binpatch->funcpatches = funcpatches;
	return 0;
}

static struct local_var_s *create_local_var(const DataSym *lv)
{
	struct local_var_s *local_var;

	local_var = xmalloc(sizeof(struct local_var_s));
	if (!local_var)
		return NULL;

	local_var->name = strdup(lv->name);
	if (!local_var->name)
		return NULL;

	local_var->size = lv->size;
	local_var->offset = lv->offset;
	local_var->ref = lv->ref;
	return local_var;
}

static int set_binpatch_local_vars(struct binpatch_s *binpatch, BinPatch *bp)
{
	int i;
	struct local_var_s **local_vars;

	local_vars = xmalloc(sizeof(struct local_var_s *) * bp->n_local_vars);
	if (!local_vars)
		return -ENOMEM;

	for (i = 0; i < bp->n_local_vars; i++) {
		local_vars[i] = create_local_var(bp->local_vars[i]);
		if (!local_vars[i])
			return -ENOMEM;
	}
	binpatch->n_local_vars = bp->n_local_vars;
	binpatch->local_vars = local_vars;
	return 0;
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

static int set_binpatch_segments(struct binpatch_s *binpatch, BinPatch *bp)
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
	binpatch->n_segments = bp->n_new_segments;
	binpatch->segments = segments;
	return 0;
}

int parse_protbuf_binpatch(struct binpatch_s *binpatch, const char *patchfile)
{
	int err = -ENOMEM;
	BinPatch *bp;

	bp = read_binpatch(patchfile);
	if (!bp)
		return -1;

	binpatch->object_type = strdup(bp->object_type);
	if (!binpatch->object_type)
		goto free_unpacked;
	binpatch->old_bid = strdup(bp->old_bid);
	if (!binpatch->old_bid)
		goto free_object_type;
	binpatch->new_path = strdup(bp->new_path);
	if (!binpatch->new_path)
		goto free_old_bid;

	if (set_binpatch_relocations(binpatch, bp))
		goto free_new_path;

	if (set_binpatch_funcpatches(binpatch, bp))
		goto free_relocations;

	if (set_binpatch_local_vars(binpatch, bp))
		goto free_funcpatches;

	if (set_binpatch_segments(binpatch, bp))
		goto free_local_vars;

	err = 0;

free_unpacked:
	bin_patch__free_unpacked(bp, NULL);
	return err;

free_local_vars:
	// TODO
free_funcpatches:
	// TODO
free_relocations:
	// TODO
free_new_path:
	free(binpatch->new_path);
free_old_bid:
	free(binpatch->old_bid);
free_object_type:
	free(binpatch->object_type);
	goto free_unpacked;
}

char *protobuf_get_bid(const char *patchfile)
{
	char *bid;
	BinPatch *bp;

	bp = read_binpatch(patchfile);
	if (!bp)
		return NULL;

	bid = xstrdup(bp->old_bid);

	bin_patch__free_unpacked(bp, NULL);
	return bid;
}
