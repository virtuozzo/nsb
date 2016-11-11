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

struct binpatch_s {
	BinPatch		 *bp;
	unsigned long		 addr;
	struct list_head	functions;
};

struct binpatch_s binpatch = { };

static struct funcpatch_s *search_func_by_name(const char *name)
{
	struct funcpatch_s *funcpatch;

	list_for_each_entry(funcpatch, &binpatch.functions, list) {
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

static int apply_objinfo(pid_t pid, unsigned long start, ObjInfo *oi)
{
	unsigned char jump[8];
	int err;

	pr_debug("\t\tinfo: name    : %s\n", oi->name);
	pr_debug("\t\tinfo: offset  : %#x\n", oi->offset);
	pr_debug("\t\tinfo: ref_addr: %d\n", oi->ref_addr);
	pr_debug("\t\tinfo: external: %d\n", oi->external);
	pr_debug("\t\tinfo: reftype : %d\n", oi->reftype);

	if (oi->ref_addr == 0) {
		struct funcpatch_s *funcpatch;

		/* This means, that function is a new one */
		funcpatch = search_func_by_name(oi->name);
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
				err = ptrace_peek_area(pid, (void *)jump, (void *)(long)start + oi->offset, 8);
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

				err = ptrace_poke_area(pid, (void *)jump, (void *)(long)start + oi->offset, 8);
				if (err < 0)
					pr_err("failed to patch: %d\n", err);
			}
			break;
		case OBJ_INFO__OBJ_TYPE__JMPQ:
			{
				int i;

				pr_debug("\t\tinfo: jmpq\n");
				err = ptrace_peek_area(pid, (void *)jump, (void *)(long)start + oi->offset, 8);
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

				err = ptrace_poke_area(pid, (void *)jump, (void *)(long)start + oi->offset, 8);
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

static int apply_funcpatch(pid_t pid, unsigned long addr, FuncPatch *fp)
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

	err = ptrace_poke_area(pid, fp->code.data, (void *)addr,
				round_up(fp->size, 8));
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	for (i = 0; i < fp->n_objs; i++) {
		pr_debug("\tObject info %d:\n", i);
		err = apply_objinfo(pid, addr, fp->objs[i]);
	}

	get_jump_instr(fp->start, addr, jump);

	err = ptrace_poke_area(pid, (void *)jump, (void *)(long)fp->start, 8);
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	return err;
}
static int apply_binpatch(pid_t pid, unsigned long addr, const char *patchfile)
{
	int i, err;
	BinPatch *bp;
	struct funcpatch_s *funcpatch;

	binpatch.addr = addr;
	INIT_LIST_HEAD(&binpatch.functions);

	binpatch.bp = read_binpatch(patchfile);
	if (!binpatch.bp)
		return -1;

	bp = binpatch.bp;

	for (i = 0; i < bp->n_patches; i++) {
		funcpatch = xmalloc(sizeof(*funcpatch));
		if (!funcpatch) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
		funcpatch->addr = addr;
		funcpatch->fp = bp->patches[i];
		list_add_tail(&funcpatch->list, &binpatch.functions);

		addr += round_up(funcpatch->fp->size, 16);
	}

	list_for_each_entry(funcpatch, &binpatch.functions, list) {
		pr_debug("Function patch %d:\n", i);

		err = apply_funcpatch(pid, funcpatch->addr, funcpatch->fp);
		if (err)
			break;
	}
	bin_patch__free_unpacked(bp, NULL);

	return err;
}

struct process_ctx_s {
	pid_t			pid;
	struct parasite_ctl	*ctl;
	struct list_head	vmas;
};

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
	struct process_ctx_s ctx = {
		.pid = pid,
		.vmas = LIST_HEAD_INIT(ctx.vmas),
	};
	int ret;
	long hint;

	unsigned long sret = -ENOSYS;

	pr_debug("Patching process %d\n", pid);
	pr_debug("====================\n");

	ret = process_infect(&ctx);
	if (ret)
		return ret;

	pr_debug("Allocating anon mapping in %d for %zu bytes\n", pid, mmap_size);

	/* TODO: Hint has to be calculated by searching a hole in 4GB page,
	 * where old address (taken from patch) belongs */
	hint = 0x800000;

	ret = compel_syscall(ctx.ctl, __NR(mmap, false), &sret,
			     hint, mmap_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", pid);
		return -1;
	}

	if ((long)sret < 0) {
		errno = (int)sret;
		pr_perror("Failed to create mmap with size %zu bytes\n",
			  mmap_size);
		return -1;
	}

	pr_debug("Created anon map %#lx-%#lx in task %d\n",
		 sret, sret + mmap_size, pid);

	/*
	 * - Use ptrace_poke_area to inject jump code into
	 *   patchee, ie
	 *
	 *   int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
	 *    @pid -- address of task we're patching
	 *    @src -- patch body
	 *    @addr -- where to put it in task space
	 *    @bytes -- size of patch, must be 8 byte aligned
	 */

	ret = apply_binpatch(pid, sret, patchfile);

	/*
	 * Patch itself
	 */
	//ptrace_poke_area(pid, patch_code, patch_address, patch_size);

	return process_cure(&ctx);
}
