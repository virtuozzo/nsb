#include "nsb_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <linux/limits.h>

#include "include/patch.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/vma.h"
#include "include/elf.h"

#include "include/process.h"
#include "include/x86_64.h"
#include "include/backtrace.h"
#include "include/protobuf.h"
#include "include/relocations.h"

struct process_ctx_s process_context = {
	.p = {
		.rela_plt = LIST_HEAD_INIT(process_context.p.rela_plt),
		.rela_dyn = LIST_HEAD_INIT(process_context.p.rela_dyn),
		.objdeps = LIST_HEAD_INIT(process_context.p.objdeps),
		.segments = LIST_HEAD_INIT(process_context.p.segments),
	}
};

static int write_func_jump(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	unsigned char jump[X86_MAX_SIZE];
	unsigned long func_addr, patch_addr;
	ssize_t size;
	int err;

	pr_info("  - Function \"%s\":\n", fj->name);

	func_addr = fj->func_value;
	if (elf_type_dyn(ctx->pvma->ei))
		func_addr += ctx->pvma->start;

	patch_addr = PLA(ctx) + fj->patch_value;

	pr_info("      old address: %#lx\n", func_addr);
	pr_info("      new address: %#lx\n", patch_addr);

	pr_info("        jump: %#lx ---> %#lx\n", func_addr, patch_addr);

	size = x86_jmpq_instruction(jump, func_addr, patch_addr);
	if (size < 0)
		return size;

	err = process_write_data(ctx->pid, func_addr, jump, round_up(size, 8));
	if (err < 0) {
		pr_err("failed to patch: %d\n", err);
		return err;
	}
	return 0;
}

static int set_func_jumps(struct process_ctx_s *ctx)
{
	int i, err;
	struct patch_info_s *pi = PI(ctx);

	pr_info("= Apply function jumps:\n");
	for (i = 0; i < pi->n_func_jumps; i++) {
		struct func_jump_s *fj = pi->func_jumps[i];

		err = write_func_jump(ctx, fj);
		if (err)
			return err;
	}
	return 0;
}

static int64_t load_patch(struct process_ctx_s *ctx)
{
	uint64_t hint;

	if (elf_type_dyn(ctx->pvma->ei))
		/*
		 * TODO: there should be bigger offset. 2 or maybe even 4 GB.
		 * But jmpq command construction fails, if map lays ouside 2g offset.
		 * This might be a bug in jmps construction
		 */
		hint = ctx->pvma->start & 0xfffffffff0000000;
	else
		hint = 0x1000000;
	return load_elf(ctx, &P(ctx)->segments, P(ctx)->ei, hint);
}

static int apply_dyn_binpatch(struct process_ctx_s *ctx)
{
	int err;

	P(ctx)->load_addr = load_patch(ctx);
	if (P(ctx)->load_addr < 0)
		return P(ctx)->load_addr;

	err = apply_relocations(ctx);
	if (err)
		return err;

	return ctx->ops->set_jumps(ctx);
}

static struct ctx_dep *ctx_create_dep(const struct vma_area *vma)
{
	struct ctx_dep *cd;

	cd = xmalloc(sizeof(*cd));
	if (!cd)
		return NULL;
	cd->vma = vma;
	return cd;
}

static int collect_lib_deps(struct process_ctx_s *ctx, const struct vma_area *vma, struct list_head *head)
{
	struct elf_needed *en;
	LIST_HEAD(needed);
	LIST_HEAD(nested);

	list_for_each_entry(en, elf_needed_list(vma->ei), list) {
		const struct vma_area *vma;
		struct ctx_dep *cd;
		int err;

		vma = find_vma_by_soname(&ctx->vmas, en->needed);
		if (!vma) {
			pr_err("failed to find VMA by soname %s\n", en->needed);
			return -ENOENT;
		}

		cd = ctx_create_dep(vma);
		if (!cd)
			return -EINVAL;
		list_add_tail(&cd->list, &needed);

		err = collect_lib_deps(ctx, vma, &nested);
		if (err)
			return err;

	}
	list_splice_tail(&needed, head);
	list_splice_tail(&nested, head);
	return 0;
}

static int collect_ctx_deplist(struct process_ctx_s *ctx)
{
	struct ctx_dep *cd;
	char path[PATH_MAX];
	char *exe_bid;
	const struct vma_area *exe_vma;

	snprintf(path, sizeof(path), "/proc/%d/exe", ctx->pid);

	exe_bid = elf_build_id(path);
	if (!exe_bid)
		return -EINVAL;

	exe_vma = find_vma_by_bid(&ctx->vmas, exe_bid);
	if (!exe_vma)
		return -EINVAL;

	cd = ctx_create_dep(exe_vma);
	if (!cd)
		return -EINVAL;
	list_add_tail(&cd->list, &ctx->objdeps);

	return collect_lib_deps(ctx, exe_vma, &ctx->objdeps);
}

static void print_deps(const struct list_head *head)
{
	struct ctx_dep *cd;

	list_for_each_entry(cd, head, list)
		pr_debug("  - %s - %s\n", vma_soname(cd->vma), cd->vma->path);
}

static int get_ctx_deplist(struct process_ctx_s *ctx)
{
	int err;

	pr_debug("= Process soname search list:\n");

	err = collect_ctx_deplist(ctx);
	if (err)
		return err;

	print_deps(&ctx->objdeps);
	return 0;
}

static int get_patch_deplist(struct process_ctx_s *ctx)
{
	int err;
	struct vma_area vma = {
		.ei = P(ctx)->ei,
	};

	pr_debug("= Process patch soname search list:\n");

	err = collect_lib_deps(ctx, &vma, &P(ctx)->objdeps);
	if (err)
		return err;

	print_deps(&ctx->objdeps);
	return 0;
}

static int process_find_patchable_vma(struct process_ctx_s *ctx, const char *bid)
{
	const struct vma_area *pvma;

	pr_info("= Searching source VMA:\n");

	pvma = find_vma_by_bid(&ctx->vmas, bid);
	if (!pvma) {
		pr_err("failed to find vma with Build ID %s in process %d\n",
				bid, ctx->pid);
		return -ENOENT;
	}
	pr_info("  - path   : %s\n", pvma->path);
	pr_info("  - address: %#lx\n", pvma->start);
	ctx->pvma = pvma;
	return 0;
}

static int process_find_patch(struct process_ctx_s *ctx, const char *bid)
{
	pr_info("= Cheking for patch is applied...\n");

	if (find_vma_by_bid(&ctx->vmas, bid)) {
		pr_err("Patch with Build ID %s is already applied\n", bid);
		return -EEXIST;
	}
	return 0;
}

static int init_patch_info(struct patch_info_s *pi, const char *patchfile)
{
	int is_elf;

	is_elf = is_elf_file(patchfile);
	if (is_elf < 0) {
		pr_err("failed to get patch information\n");
		return is_elf;
	}

	if (is_elf)
		return parse_elf_binpatch(pi, patchfile);
	else
		return parse_protobuf_binpatch(pi, patchfile);
}

static int init_patch(struct process_ctx_s *ctx)
{
	int err;
	struct patch_s *p = P(ctx);

	err = init_patch_info(PI(ctx), ctx->patchfile);
	if (err)
		return err;


	p->ei = elf_create_info(PI(ctx)->path);
	if (!p->ei)
		return -EINVAL;

	if (strcmp(elf_bid(p->ei), PI(ctx)->new_bid)) {
		pr_err("BID of %s doesn't match patch BID: %s != %s\n",
				PI(ctx)->path, elf_bid(p->ei),
				PI(ctx)->new_bid);
		return -EINVAL;
	}
	return 0;
}

static int process_resume(struct process_ctx_s *ctx)
{
	pr_info("= Resuming %d\n", ctx->pid);
	return process_cure(ctx);
}

int iterate_jumps(const struct process_ctx_s *ctx, const void *data,
		  int (*actor)(const struct process_ctx_s *ctx,
			       const struct func_jump_s *fj,
			       const void *data))
{
	const struct patch_info_s *pi = PI(ctx);
	int i, err;

	for (i = 0; i < pi->n_func_jumps; i++) {
		err = actor(ctx, pi->func_jumps[i], data);
		if (err)
			return err;
	}
	return 0;
}

static int jumps_check_backtrace(const struct process_ctx_s *ctx,
				 const struct backtrace_s *bt)
{
	return iterate_jumps(ctx, bt, backtrace_check_func);
}

struct patch_ops_s patch_jump_ops = {
	.apply_patch = apply_dyn_binpatch,
	.set_jumps = set_func_jumps,
	.check_backtrace = jumps_check_backtrace,
};

static int init_context(struct process_ctx_s *ctx, pid_t pid,
			const char *patchfile)
{
	if (elf_library_status())
		return -1;

	pr_info("Patch context:\n");
	pr_info("  Pid        : %d\n", pid);

	ctx->pid = pid;
	ctx->patchfile = patchfile;
	INIT_LIST_HEAD(&ctx->vmas);
	INIT_LIST_HEAD(&ctx->objdeps);
	INIT_LIST_HEAD(&ctx->threads);

	if (init_patch(ctx))
		return 1;

	ctx->ops = &patch_jump_ops;

	pr_info("  Target BuildId: %s\n", PI(ctx)->old_bid);
	pr_info("  Patch path    : %s\n", PI(ctx)->path);
	if (collect_vmas(ctx->pid, &ctx->vmas)) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		return 1;
	}

	if (process_find_patch(ctx, PI(ctx)->new_bid))
		return 1;

	if (process_find_patchable_vma(ctx, PI(ctx)->old_bid))
		return 1;

	if (get_ctx_deplist(ctx))
		return 1;

	if (get_patch_deplist(ctx))
		return 1;

	if (collect_relocations(ctx))
		return 1;

	return 0;
}

int patch_process(pid_t pid, const char *patchfile)
{
	int ret, err;
	struct process_ctx_s *ctx = &process_context;

	err = init_context(ctx, pid, patchfile);
	if (err)
		return err;

	err = process_suspend(ctx);
	if (err) {
		errno = -err;
		pr_perror("Failed to suspend process");
		return err;
	}

	ret = process_link(ctx);
	if (ret)
		goto resume;

	ret = resolve_relocations(ctx);
	if (ret)
		goto resume;

	ret = ctx->ops->apply_patch(ctx);
	if (ret)
		 pr_err("failed to apply binary patch\n");

	/* TODO all the work has to be rolled out, if an error occured */
resume:
	err = process_resume(ctx);

	pr_info("Done\n");
	return ret ? ret : err;
}

int check_process(pid_t pid, const char *patchfile)
{
	int err;
	LIST_HEAD(vmas);
	char *bid;

	err = collect_vmas(pid, &vmas);
	if (err) {
		pr_err("Can't collect mappings for %d\n", pid);
		return err;
	}

	bid = protobuf_get_bid(patchfile);
	if (!bid)
		return -1;

	return !find_vma_by_bid(&vmas, bid);
}

