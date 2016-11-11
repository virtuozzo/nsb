#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include "compel/compel/compel.h"
#include "compel/compel/ptrace.h"

#include "include/patch.h"
#include "include/list.h"
#include "include/log.h"
#include "include/xmalloc.h"

#include "protobuf.h"

struct funcpatch_s {
	struct list_head	list;
	FuncPatch		 *fp;
	unsigned long		 addr;
};

struct patch_place_s {
	struct list_head	list;
	unsigned long		start;
	unsigned long		size;
	unsigned long		used;
};

struct binpatch_s {
	BinPatch		 *bp;
	unsigned long		 addr;
	struct list_head	functions;
	struct list_head	places;
};

struct process_ctx_s {
	pid_t			pid;
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
	struct binpatch_s	binpatch;
} process_context;

static const struct funcpatch_s *search_func_by_name(const struct binpatch_s *bp, const char *name)
{
	const struct funcpatch_s *funcpatch;

	list_for_each_entry(funcpatch, &bp->functions, list) {
		if (!strcmp(funcpatch->fp->name, name))
			return funcpatch;
	}
	return NULL;
}

extern int compel_syscall(struct parasite_ctl *ctl,
			  int nr, unsigned long *ret,
			  unsigned long arg1,
			  unsigned long arg2,
			  unsigned long arg3,
			  unsigned long arg4,
			  unsigned long arg5,
			  unsigned long arg6);

static int collect_mappings(pid_t pid, struct list_head *head)
{
	unsigned long start, end, pgoff;
	char r, w, x, s;

	int dev_maj;
	int dev_min;
	unsigned long ino;

	int ret = -1;

	struct vma_area *vma_area = NULL;
	char buf[1024];
	char path[64];
	FILE *f;

	pr_debug("Collecting mappings for %d\n", pid);

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		int num, path_off;

		if (!vma_area) {
			vma_area = xzalloc(sizeof(*vma_area));
			if (!vma_area)
				goto err;
		}

		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
			     &start, &end, &r, &w, &x, &s, &pgoff,
			     &dev_maj, &dev_min, &ino, &path_off);
		if (num < 10) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

		vma_area->start	= start;
		vma_area->end	= end;
		vma_area->pgoff	= pgoff;
		vma_area->prot	= PROT_NONE;

		if (r == 'r')
			vma_area->prot |= PROT_READ;
		if (w == 'w')
			vma_area->prot |= PROT_WRITE;
		if (x == 'x')
			vma_area->prot |= PROT_EXEC;

		if (s == 's')
			vma_area->flags = MAP_SHARED;
		else if (s == 'p')
			vma_area->flags = MAP_PRIVATE;
		else {
			pr_err("Unexpected VMA met (%c)\n", s);
			goto err;
		}

		list_add_tail(&vma_area->list, head);
		pr_debug("VMA: %lx-%lx %c%c%c%c %lx %x:%x %lu\n",
			start, end, r, w, x, s, pgoff,
			dev_maj, dev_min, ino);
		vma_area = NULL;
	}

	ret = 0;

err:
	return ret;
}

unsigned long find_syscall_ip(struct list_head *head)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, head, list) {
		if (vma_area->prot & PROT_EXEC)
			return vma_area->start;
	}

	return 0;
}

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

static int process_write_data(pid_t pid, void *addr, void *data, size_t size)
{
	return ptrace_poke_area(pid, data, addr, size);
}

static int process_read_data(pid_t pid, void *addr, void *data, size_t size)
{
	return ptrace_peek_area(pid, data, addr, size);
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

static int process_add_map(struct process_ctx_s *ctx,
			   unsigned long addr, size_t size)
{
	int ret;
	long sret = -ENOSYS;

	/* TODO: need drop PROT_WRITE at the end */
	ret = compel_syscall(ctx->ctl, __NR(mmap, false), (unsigned long *)&sret,
			     addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", ctx->pid);
		return -1;
	}

	if (sret < 0) {
		errno = sret;
		pr_perror("Failed to create mmap with size %zu bytes\n", size);
		return -1;
	}

	pr_debug("Created anon map %#lx-%#lx in task %d\n",
		 sret, sret + size, ctx->pid);

	return 0;
}

static struct patch_place_s *find_place(struct binpatch_s *bp, unsigned long hint)
{
	struct patch_place_s *place;

	list_for_each_entry(place, &bp->places, list) {
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

static unsigned long process_find_hole(unsigned long hint, size_t size)
{
	/* TODO: address has be be found by by searching a hole in the same 4GB
	 * page, where hint belongs */
	return 0x800000;
}

static int process_create_place(struct process_ctx_s *ctx, unsigned long hint,
				size_t size, struct patch_place_s **place)
{
	int ret;
	unsigned long addr;
	struct binpatch_s *bp = &ctx->binpatch;
	struct patch_place_s *p;

	size = round_up(size, PAGE_SIZE);

	addr = process_find_hole(hint, size);
	if (addr < 0) {
		pr_err("failed to find address hole by hint %#lx\n", hint);
		return -EFAULT;
	}

	pr_debug("Found hole: %#lx-%#lx\n", addr, addr + size);

	p = alloc_place(addr, size);
	if (!p)
		return -ENOMEM;

	ret = process_add_map(ctx, p->start, p->size);
	if (ret < 0)
		goto destroy_place;

	list_add_tail(&p->list, &bp->places);

	pr_debug("created new place for patch: %#lx-%#lx (hint: %#lx)\n",
			p->start, p->start + p->size, hint);

	*place = p;
	return 0;

destroy_place:
	free(p);
	return ret;
}

static long process_get_place(struct process_ctx_s *ctx, unsigned long hint, size_t size)
{
	struct binpatch_s *bp = &ctx->binpatch;
	struct patch_place_s *place;
	long addr;

	/* Aling function size by 16 bytes */
	size = round_up(size, 16);

	place = find_place(bp, hint);
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

static int process_cure(struct process_ctx_s *ctx)
{
	pr_debug("Unseize from %d\n", ctx->pid);
	if (compel_unseize_task(ctx->pid, TASK_ALIVE, TASK_ALIVE)) {
		pr_err("Can't unseize from %d\n", ctx->pid);
		return -1;
	}
	return 0;
}

static int process_infect(struct process_ctx_s *ctx)
{
	struct infect_ctx *ictx;
	struct parasite_ctl *ctl;
	unsigned long syscall_ip;
	int ret;

	pr_debug("Stopping... %s\n",
		 (ret = compel_stop_task(ctx->pid)) ? "FAIL" : "OK");
	if (ret)
		return -1;

	ctl = compel_prepare(ctx->pid);
	if (!ctl) {
		pr_err("Can't create compel control\n");
		return -1;
	}

	ictx = compel_infect_ctx(ctl);
	ictx->loglevel = log_get_loglevel();
	ictx->log_fd = log_get_fd();

	if (collect_mappings(ctx->pid, &ctx->vmas)) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		goto err;
	}

	syscall_ip = find_syscall_ip(&ctx->vmas);
	if (!syscall_ip) {
		pr_err("Can't find suitable vma for syscall %d\n", ctx->pid);
		goto err;
	}
	pr_debug("syscall ip at %#lx\n", syscall_ip);
	ictx->syscall_ip = syscall_ip;

	ctx->ctl = ctl;

	return 0;

err:
	process_cure(ctx);
	return -1;
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
