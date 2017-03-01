#include "include/log.h"
#include "include/xmalloc.h"
#include "include/list.h"

#include "include/process.h"
#include "include/x86_64.h"

static struct patch_place_s *find_place(struct patch_info_s *pi, unsigned long hint)
{
	struct patch_place_s *place;

	list_for_each_entry(place, &pi->places, list) {
		if ((place->start & 0xffffffff00000000) == (hint & 0xffffffff00000000)) {
			pr_debug("found place for patch: %#lx (hint: %#lx)\n",
					place->start, hint);
			return place;
		}
	}
	return NULL;
}

static struct patch_place_s *alloc_place(unsigned long addr, size_t size)
{
	struct patch_place_s *place;

	place = xmalloc(sizeof(*place));
	if (!place) {
		pr_err("failed to allocate\n");
		return NULL;
	}
	place->start = addr;
	place->size = size;
	place->used = 0;

	return place;
}

static unsigned long process_find_hole(struct process_ctx_s *ctx, unsigned long hint, size_t size)
{
	unsigned long addr;

	addr = find_vma_hole(&ctx->vmas, hint, size);
	if (addr)
		return addr;
	return -ENOENT;
}

static int process_create_place(struct process_ctx_s *ctx, unsigned long hint,
				size_t size, struct patch_place_s **place)
{
	long ret;
	unsigned long addr;
	struct patch_info_s *pi = PI(ctx);
	struct patch_place_s *p;

	size = round_up(size, PAGE_SIZE);

	addr = process_find_hole(ctx, hint, size);
	if (addr < 0) {
		pr_err("failed to find address hole by hint %#lx\n", hint);
		return -EFAULT;
	}

	pr_debug("Found hole: %#lx-%#lx\n", addr, addr + size);

	p = alloc_place(addr, size);
	if (!p)
		return -ENOMEM;

	/* TODO: need drop PROT_WRITE at the end */
	ret = process_create_map(ctx, -1, 0,
				 p->start, p->size,
				 MAP_ANONYMOUS | MAP_PRIVATE,
				 PROT_READ | PROT_WRITE | PROT_EXEC);
	if ((void *)ret == MAP_FAILED) {
		pr_err("failed to create remove mem\n");
		goto destroy_place;
	}

	if (ret != p->start) {
		pr_err("mmap result doesn't match expected: %ld != %ld\n",
				ret, p->start);
		goto unmap_remote;
	}

	list_add_tail(&p->list, &pi->places);

	pr_debug("created new place for patch: %#lx-%#lx (hint: %#lx)\n",
			p->start, p->start + p->size, hint);

	*place = p;
	return 0;

unmap_remote:
	/* TODO here remote map has to be unmapped */
destroy_place:
	free(p);
	return ret;
}

static long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size)
{
	struct patch_info_s *pi = PI(ctx);
	struct patch_place_s *place;
	long addr;

	/* Aling function size by 16 bytes */
	size = round_up(size, 16);

	place = find_place(pi, hint);
	if (!place) {
		int ret;

		ret = process_create_place(ctx, hint, size, &place);
		if (ret)
			return ret;
	} else if (place->size - place->used < size) {
		pr_err("No place left for %ld bytes in vma %#lx (free: %ld)\n",
				size, place->start, place->size - place->used);
		return -ENOMEM;
	}

	addr = place->start + round_up(place->used, 16);
	place->used += size;
	return addr;
}

static const struct funcpatch_s *search_func_by_name(const struct patch_info_s *bp, const char *name)
{
	const struct funcpatch_s *funcpatch;

	list_for_each_entry(funcpatch, &bp->functions, list) {
		if (!strcmp(funcpatch->fp->name, name))
			return funcpatch;
	}
	return NULL;
}

static int apply_objinfo(struct process_ctx_s *ctx, unsigned long start, ObjInfo *oi)
{
	unsigned char code[X86_MAX_SIZE];
	ssize_t size;
	int err, i;
	unsigned long where = start + oi->offset;

	pr_debug("\t\tinfo: name     : %s\n", oi->name);
	pr_debug("\t\tinfo: op_size  : %#x\n", oi->op_size);
	pr_debug("\t\tinfo: addr_size: %#x\n", oi->addr_size);
	pr_debug("\t\tinfo: offset   : %#x\n", oi->offset);
	pr_debug("\t\tinfo: ref_addr : %#x\n", oi->ref_addr);

	if (oi->ref_addr == 0) {
		const struct funcpatch_s *funcpatch;

		/* This means, that function is a new one */
		funcpatch = search_func_by_name(&ctx->binpatch, oi->name);
		if (!funcpatch) {
			pr_err("\t\tfailed to find function by name %s\n", oi->name);
			return -EINVAL;
		}
		pr_debug("\t\tfunction address : %#lx\n", funcpatch->addr);
		oi->ref_addr = funcpatch->addr;
	}

	err = process_read_data(ctx->pid, where, code, round_up(sizeof(code), 8));
	if (err < 0) {
		pr_err("failed to read process address %ld: %d\n", where, err);
		return err;
	}

	pr_debug("\t\tinfo: old code :");
	for (i = 0; i < X86_MAX_SIZE; i++)
		pr_msg(" %02x", code[i]);
	pr_debug("\n");

	size = x86_modify_instruction(code, oi->op_size, oi->addr_size,
			where, oi->ref_addr);
	if (size < 0)
		return size;

	pr_debug("\t\tinfo: new code :");
	for (i = 0; i < X86_MAX_SIZE; i++)
		pr_msg(" %02x", code[i]);
	pr_debug("\n");

	err = process_write_data(ctx->pid, where, code, round_up(sizeof(code), 8));
	if (err < 0) {
		pr_err("failed to write process address %ld: %d\n", where, err);
		return err;
	}
	return 0;
}

static int apply_funcpatch(struct process_ctx_s *ctx, unsigned long addr, FuncPatch *fp)
{
	int i, err = 0;
	unsigned char jump[X86_MAX_SIZE];
	ssize_t size;

	pr_debug("\tpatch: name : %s\n", fp->name);
	pr_debug("\tpatch: addr : %#lx\n", fp->addr);
	pr_debug("\tpatch: size : %d\n", fp->size);
	pr_debug("\tpatch: new  : %d\n", fp->new_);
	pr_debug("\tpatch: code :");
	for (i = 0; i < fp->size; i++)
		pr_msg(" %02x", fp->code.data[i]);
	pr_debug("\n");
	pr_debug("\tplace address  : %#lx\n", addr);

	err = process_write_data(ctx->pid, addr, fp->code.data,
			round_up(fp->size, 8));
	if (err < 0) {
		pr_err("failed to patch: %d\n", err);
		return err;
	}

	for (i = 0; i < fp->n_objs; i++) {
		pr_debug("\tObject info %d:\n", i);
		err = apply_objinfo(ctx, addr, fp->objs[i]);
		if (err)
			return err;
	}

	if (!fp->new_) {
		pr_debug("\tredirect to %#lx (overwrite %#lx)\n", addr, fp->addr);
		size = x86_jmpq_instruction(jump, fp->addr, addr);
		if (size < 0)
			return size;

		err = process_write_data(ctx->pid, fp->addr, jump, round_up(size, 8));
		if (err < 0)
			pr_err("failed to patch: %d\n", err);
	}
	return err;
}

int apply_exec_binpatch(struct process_ctx_s *ctx)
{
	int i, err = 0;
	struct patch_info_s *binpatch = &ctx->binpatch;
	BinPatch *bp = binpatch->bp;
	struct funcpatch_s *funcpatch;

	for (i = 0; i < bp->n_patches; i++) {
		FuncPatch *fp = bp->patches[i];
		unsigned long addr;

		addr = process_get_place(ctx, fp->addr, fp->size);
		if (addr < 0)
			return addr;

		funcpatch = xmalloc(sizeof(*funcpatch));
		if (!funcpatch)
			return -ENOMEM;

		funcpatch->addr = addr;
		funcpatch->fp = fp;
		list_add_tail(&funcpatch->list, &binpatch->functions);
	}

	list_for_each_entry(funcpatch, &binpatch->functions, list) {
		pr_debug("Function patch \"%s\"\n", funcpatch->fp->name);

		err = apply_funcpatch(ctx, funcpatch->addr, funcpatch->fp);
		if (err)
			break;
	}

	return err;
}
