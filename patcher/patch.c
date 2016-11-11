#include <stdlib.h>
#include <errno.h>

#include "include/patch.h"
#include "include/log.h"
#include "include/xmalloc.h"

#include "include/process.h"

struct process_ctx_s process_context;

static void get_call_instr(unsigned long cmd_addr, unsigned long jmp_addr,
			   unsigned char *data)
{
	unsigned char *instr = &data[0];
	unsigned int *addr = (unsigned int *)&data[1];
	long off;
	int i;

	pr_debug("\tcall: cmd address : %#lx\n", cmd_addr);
	pr_debug("\tcall: jmp address : %#lx\n", jmp_addr);

	/* Relative callq */
	*instr = 0xe8;
	/* 5 bytes is relative jump command size */
	off = jmp_addr - cmd_addr - 5;

	pr_debug("\tcall: offset      : %#lx\n", off);

	*addr = off;

	pr_debug("\tcall :");
	for (i = 0; i < 5; i++)
		pr_msg(" %02x", data[i]);
	pr_debug("\n");
}

static void get_jump_instr(unsigned long cmd_addr, unsigned long jmp_addr,
			  unsigned char *data)
{
	unsigned char *instr = &data[0];
	unsigned int *addr = (unsigned int *)&data[1];
	long off;
	int i;

	pr_debug("\tjump: cmd address : %#lx\n", cmd_addr);
	pr_debug("\tjump: jmp address : %#lx\n", jmp_addr);

	/* Relative jump */
	*instr = 0xe9;
	/* 5 bytes is relative jump command size */
	off = jmp_addr - cmd_addr - 5;

	pr_debug("\tjump: offset      : %#lx\n", off);

	*addr = off;

	pr_debug("\tjump :");
	for (i = 0; i < 5; i++)
		pr_msg(" %02x", data[i]);
	pr_debug("\n");
}

static const struct funcpatch_s *search_func_by_name(const struct binpatch_s *bp, const char *name)
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
	unsigned char jump[8];
	int err;

	pr_debug("\t\tinfo: name    : %s\n", oi->name);
	pr_debug("\t\tinfo: offset  : %#x\n", oi->offset);
	pr_debug("\t\tinfo: ref_addr: %d\n", oi->ref_addr);
	pr_debug("\t\tinfo: external: %d\n", oi->external);
	pr_debug("\t\tinfo: reftype : %d\n", oi->reftype);

	if (oi->ref_addr == 0) {
		const struct funcpatch_s *funcpatch;

		/* This means, that function is a new one */
		funcpatch = search_func_by_name(&ctx->binpatch, oi->name);
		if (!funcpatch) {
			pr_debug("\t\tfailed to find function by name %s\n", oi->name);
			return -EINVAL;
		}
		pr_debug("\t\tfunction address : %#lx\n", funcpatch->addr);
		oi->ref_addr = funcpatch->addr;
	}

	switch (oi->reftype) {
		case OBJ_INFO__OBJ_TYPE__CALL:
			{
				int i;

				pr_debug("\t\tinfo: jmpq\n");
				err = process_read_data(ctx->pid, (void *)(long)start + oi->offset, (void *)jump, 8);
				if (err < 0)
					pr_err("failed to patch: %d\n", err);

				pr_debug("\t\told code :");
				for (i = 0; i < 8; i++)
					pr_msg(" %02x", jump[i]);
				pr_debug("\n");

				get_call_instr(start + oi->offset, oi->ref_addr, jump);

				pr_debug("\t\tnew code :");
				for (i = 0; i < 8; i++)
					pr_msg(" %02x", jump[i]);
				pr_debug("\n");

				err = process_write_data(ctx->pid, (void *)(long)start + oi->offset, (void *)jump, 8);
				if (err < 0)
					pr_err("failed to patch: %d\n", err);
			}
			break;
		case OBJ_INFO__OBJ_TYPE__JMPQ:
			{
				int i;

				pr_debug("\t\tinfo: jmpq\n");
				err = process_read_data(ctx->pid, (void *)(long)start + oi->offset, (void *)jump, 8);
				if (err < 0)
					pr_err("failed to patch: %d\n", err);

				pr_debug("\t\told code :");
				for (i = 0; i < 8; i++)
					pr_msg(" %02x", jump[i]);
				pr_debug("\n");

				get_jump_instr(start + oi->offset, oi->ref_addr, jump);

				pr_debug("\t\tnew code :");
				for (i = 0; i < 8; i++)
					pr_msg(" %02x", jump[i]);
				pr_debug("\n");

				err = process_write_data(ctx->pid, (void *)(long)start + oi->offset, (void *)jump, 8);
				if (err < 0)
					pr_err("failed to patch: %d\n", err);
			}
			break;
		default:
			pr_debug("\t\tinfo: unknown\n");
			return -1;
	}
	return 0;
}

static int apply_funcpatch(struct process_ctx_s *ctx, unsigned long addr, FuncPatch *fp)
{
	int i, err = 0;
	unsigned char jump[8];

	pr_debug("\tpatch: name : %s\n", fp->name);
	pr_debug("\tpatch: start: %#x\n", fp->start);
	pr_debug("\tpatch: size : %d\n", fp->size);
	pr_debug("\tpatch: new  : %d\n", fp->new_);
	pr_debug("\tpatch: code :");
	for (i = 0; i < fp->size; i++)
		pr_msg(" %02x", fp->code.data[i]);
	pr_debug("\n");
	pr_debug("\tplace address  : %#lx\n", addr);

	err = process_write_data(ctx->pid, (void *)addr, fp->code.data,
				 round_up(fp->size, 8));
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	for (i = 0; i < fp->n_objs; i++) {
		pr_debug("\tObject info %d:\n", i);
		err = apply_objinfo(ctx, addr, fp->objs[i]);
	}

	get_jump_instr(fp->start, addr, jump);

	err = process_write_data(ctx->pid, (void *)(long)fp->start, jump, round_up(fp->size, 8));
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	return err;
}

static int apply_binpatch(struct process_ctx_s *ctx, const char *patchfile)
{
	int i, err = 0;
	BinPatch *bp;
	struct funcpatch_s *funcpatch;
	struct binpatch_s *binpatch = &ctx->binpatch;

	INIT_LIST_HEAD(&binpatch->functions);
	INIT_LIST_HEAD(&binpatch->places);

	binpatch->bp = read_binpatch(patchfile);
	if (!binpatch->bp)
		return -1;

	bp = binpatch->bp;

	for (i = 0; i < bp->n_patches; i++) {
		FuncPatch *fp = bp->patches[i];
		unsigned long addr;

		addr = process_get_place(ctx, fp->start, fp->size);
		if (addr < 0) {
			err = addr;
			goto err;
		}

		funcpatch = xmalloc(sizeof(*funcpatch));
		if (!funcpatch) {
			pr_err("failed to allocate\n");
			err = -ENOMEM;;
			goto err;
		}
		funcpatch->addr = addr;
		funcpatch->fp = fp;
		list_add_tail(&funcpatch->list, &binpatch->functions);
	}

	list_for_each_entry(funcpatch, &binpatch->functions, list) {
		pr_debug("Function patch %d:\n", i);

		err = apply_funcpatch(ctx, funcpatch->addr, funcpatch->fp);
		if (err)
			break;
	}
err:
	bin_patch__free_unpacked(bp, NULL);
	return err;
}

int patch_process(pid_t pid, size_t mmap_size, const char *patchfile)
{
	int ret, err;
	struct process_ctx_s *ctx = &process_context;

	ctx->pid = pid;
	INIT_LIST_HEAD(&ctx->vmas),

	pr_debug("====================\n");
	pr_debug("Patching process %d\n", ctx->pid);

	err = process_infect(ctx);
	if (err)
		return err;

	ret = apply_binpatch(ctx, patchfile);

	/* TODO all the work has to be rolled out, if an error occured */

	err = process_cure(ctx);

	return ret ? ret : err;
}
