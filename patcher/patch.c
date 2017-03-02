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
#include "include/rtld.h"
#include "include/backtrace.h"
#include "include/protobuf.h"
#include "include/relocations.h"

struct process_ctx_s process_context = {
	.p = {
		.rela_plt = LIST_HEAD_INIT(process_context.p.rela_plt),
		.rela_dyn = LIST_HEAD_INIT(process_context.p.rela_dyn),
	}
};

#ifdef SWAP_PATCHING
static const struct patch_ops_s *set_patch_ops(const char *how, const char *type);
#else
static const struct patch_ops_s *set_patch_ops(const char *type);
#endif

static int write_func_jump(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	unsigned char jump[X86_MAX_SIZE];
	unsigned long func_addr, patch_addr;
	ssize_t size;
	int err;

	pr_info("  - Function \"%s\":\n", fj->name);

	func_addr = ctx->pvma->start + fj->func_value;
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
#ifdef SWAP_PATCHING
static int process_copy_lw(pid_t pid, unsigned long dest, unsigned long src)
{
	int err;
	char buf[8];

	err = process_read_data(pid, src, buf, 8);
	if (err) {
		pr_err("failed to read from %lx\n", src);
		return err;
	}
	err = process_write_data(pid, dest, buf, 8);
	if (err) {
		pr_err("failed to write to %lx\n", dest);
		return err;
	}
	return 0;
}

static int process_copy_data(pid_t pid, unsigned long dst, unsigned long src, size_t size)
{
	int iter = size / 8;
	int remain = size % 8;
	int err, i;

	for (i = 0; i < iter; i++) {
		err = process_copy_lw(pid, src, dst);
		if (err) {
			pr_err("failed to copy from %#lx to %#lx\n", src, dst);
			return err;
		}
		src += 8;
		dst += 8;
	}
	if (remain) {
		char buf[8], tmp[8];

		err = process_read_data(pid, dst, buf, 8);
		if (err) {
			pr_err("failed to read from %lx\n", dst);
			return err;
		}

		err = process_read_data(pid, src, tmp, 8);
		if (err) {
			pr_err("failed to read from %lx\n", src);
			return err;
		}
		memcpy(buf, tmp, remain);
		err = process_write_data(pid, dst, buf, 8);
		if (err) {
			pr_err("failed to write to %lx\n", dst);
			return err;
		}
	}
	return 0;
}

static int copy_local_data(struct process_ctx_s *ctx)
{
	struct patch_info_s *pi = PI(ctx);
	int i;

	pr_info("= Copy global variables:\n");
	for (i = 0; i < pi->n_local_vars; i++) {
		struct local_var_s *ds = pi->local_vars[i];
		unsigned long from, to;
		int err;

		from = ctx->pvma->start + ds->ref;
		to = PLA(ctx) + ds->offset;

		pr_info("  - %s (size: %d): %#lx ---> %#lx\n",
				ds->name, ds->size, from, to);
		err = process_copy_data(ctx->pid, to, from, ds->size);
		if (err)
			return err;
	}
	return 0;
}
#endif
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
#ifdef SWAP_PATCHING
static int vma_fix_target_syms(struct process_ctx_s *ctx, const struct vma_area *vma)
{
	struct extern_symbol *es;
	int64_t address;
	int err;

	list_for_each_entry(es, &vma->target_syms, list) {
		unsigned long offset = es_r_offset(es);

		pr_debug("    \"%s\":\n", es->name);

		if (elf_type_dyn(vma->ei))
			offset += vma->start;

		pr_debug("       GOT address: %#lx\n", offset);

		address = elf_dsym_offset(P(ctx)->ei, es->name);

		address += PLA(ctx);
		pr_debug("       new address: %#lx\n", address);

		pr_info("          Overwrite .got.plt entry: %#lx ---> %#lx\n", address, es_r_offset(es));
		err = process_write_data(ctx->pid, es_r_offset(es), &address, sizeof(address));
		if (err < 0) {
			pr_err("failed to patch: %d\n", err);
			return err;
		}
	}

	return 0;
}

static int fix_vma_refs(struct vma_area *vma, void *data)
{
	struct process_ctx_s *ctx = data;

	if (list_empty(&vma->target_syms))
		return 0;

	pr_debug("  - %s -> %s:\n", vma->map_file, vma->path);
	return vma_fix_target_syms(ctx, vma);
}

static int fix_target_references(struct process_ctx_s *ctx)
{
	pr_info("= Fix target references:\n");
	return iterate_file_vmas(&ctx->vmas, ctx, fix_vma_refs);
}
#endif
static int apply_dyn_binpatch(struct process_ctx_s *ctx)
{
	int err;

	P(ctx)->load_addr = load_elf(ctx, ctx->pvma->start);
	if (P(ctx)->load_addr < 0)
		return P(ctx)->load_addr;

	err = apply_relocations(ctx);
	if (err)
		return err;

	if (ctx->ops->copy_data) {
		err = ctx->ops->copy_data(ctx);
		if (err)
			return err;
	}

	if (ctx->ops->set_jumps) {
		err = ctx->ops->set_jumps(ctx);
		if (err)
			return err;
	}

	if (ctx->ops->fix_references) {
		err = ctx->ops->fix_references(ctx);
		if (err)
			return err;
	}

	if (ctx->ops->cleanup_target) {
		err = ctx->ops->cleanup_target(ctx);
		if (err)
			return err;
	}

	return 0;
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

static int get_ctx_deplist(struct process_ctx_s *ctx)
{
	int err;
	struct ctx_dep *cd;

	pr_debug("= Process soname search list:\n");

	err = collect_ctx_deplist(ctx);
	if (err)
		return err;

	list_for_each_entry(cd, &ctx->objdeps, list)
		pr_debug("      - %s - %s\n", vma_soname(cd->vma), cd->vma->path);

	return 0;
}
#ifdef SWAP_PATCHING
static int ctx_bind_es(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int ret;
	const struct ctx_dep *n;

	list_for_each_entry(n, &ctx->objdeps, list) {
		const struct vma_area *vma = n->vma;

		ret = elf_contains_sym(vma->ei, es->name);
		if (ret < 0)
			return ret;
		if (ret) {
			es->vma = vma;
			return 0;
		}
	}

	if (elf_weak_sym(es))
		return 0;

	pr_err("failed to find %s symbol\n", es->name);
	return -ENOENT;
}

static int collect_dependent_vma(struct process_ctx_s *ctx,
				 struct vma_area *vma)
{
	int err;
	LIST_HEAD(plt_syms);
	struct extern_symbol *es, *tmp;

	err = elf_rela_plt(vma->ei, &plt_syms);
	if (err)
		return err;

	pr_debug("    PLT symbols to update:\n");
	list_for_each_entry_safe(es, tmp, &plt_syms, list) {
		err = ctx_bind_es(ctx, es);
		if (err)
			return err;

		if (es->vma != ctx->pvma)
			continue;

		list_move(&es->list, &vma->target_syms);

		pr_debug("      - %s:\n", es->name);
		pr_debug("          offset  : %#lx\n", es_r_offset(es));
		pr_debug("          bind    : %d\n", es_s_bind(es));
		pr_debug("          path    : %s\n", es->vma->path);
		pr_debug("          map_file: %s\n", es->vma->map_file);
	}

	return 0;
}

static int check_file_vma(struct vma_area *vma, void *data)
{
	struct process_ctx_s *ctx = data;
	int ret;

	if (!vma->path)
		return 0;

	if (!vma_is_executable(vma))
		return 0;

	pr_info("  - %#lx-%#lx -> %s\n", vma->start, vma->end, vma->path);
	ret = elf_soname_needed(vma->ei, vma_soname(ctx->pvma));
	if (ret < 0)
		pr_err("failed to find %s dependences: %d\n", vma->path, ret);
	else if (ret)
		ret = collect_dependent_vma(ctx, vma);
	return ret < 0 ? ret : 0;
}

static int process_collect_dependable_vmas(struct process_ctx_s *ctx)
{
	if (!vma_soname(ctx->pvma))
		return 0;

	pr_info("= Searching mappings, depending on \"%s\":\n", vma_soname(ctx->pvma));
	return iterate_file_vmas(&ctx->vmas, ctx, check_file_vma);
}
#endif
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

static int init_context(struct process_ctx_s *ctx, pid_t pid,
#ifdef SWAP_PATCHING
			const char *patchfile, const char *how)
#else
			const char *patchfile)
#endif
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
		goto err;

#ifdef SWAP_PATCHING
	ctx->ops = set_patch_ops(how, PI(ctx)->object_type);
#else
	ctx->ops = set_patch_ops(PI(ctx)->object_type);
#endif
	if (!ctx->ops)
		goto err;

	pr_info("  source BID : %s\n", PI(ctx)->old_bid);
	pr_info("  target path: %s\n", PI(ctx)->path);
	pr_info("  object type: %s\n", PI(ctx)->object_type);
	pr_info("  patch mode : %s\n", ctx->ops->name);

	if (collect_vmas(ctx->pid, &ctx->vmas)) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		goto err;
	}

	if (process_find_patchable_vma(ctx, PI(ctx)->old_bid))
		goto err;

	if (get_ctx_deplist(ctx))
		goto err;

	if (collect_relocations(ctx))
		goto err;

	if (ctx->ops->collect_deps) {
		if (ctx->ops->collect_deps(ctx)) {
			pr_err("failed to find dependable VMAs\n");
			goto err;
		}
	}

	return 0;

err:
	return -1;
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

#ifdef SWAP_PATCHING
int patch_process(pid_t pid, const char *patchfile, const char *how)
#else
int patch_process(pid_t pid, const char *patchfile)
#endif
{
	int ret, err;
	struct process_ctx_s *ctx = &process_context;

#ifdef SWAP_PATCHING
	err = init_context(ctx, pid, patchfile, how);
#else
	err = init_context(ctx, pid, patchfile);
#endif
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

struct patch_ops_s patch_jump_ops = {
	.name = "jump",
	.collect_deps = NULL,
	.set_jumps = set_func_jumps,
	.copy_data = NULL,
	.check_backtrace = jumps_check_backtrace,
	.fix_references = NULL,
	.cleanup_target = NULL,
};
#ifdef SWAP_PATCHING
static int unmap_file_vma(struct vma_area *vma, void *data)
{
	struct process_ctx_s *ctx = data;

	if (!vma->path)
		return 0;

	if (strcmp(vma->path, ctx->pvma->path))
		return 0;

	return process_unmap(ctx, vma->start, vma->end - vma->start);
}

static int unmap_old_lib(struct process_ctx_s *ctx)
{
	if (fixup_rtld(ctx))
		return -EINVAL;

	pr_debug("= Unmap target VMA:\n");
	return iterate_file_vmas(&ctx->vmas, ctx, unmap_file_vma);
}

static int swap_check_backtrace(const struct process_ctx_s *ctx,
				const struct backtrace_s *bt)
{
	return backtrace_check_vma(bt, ctx->pvma);
}

struct patch_ops_s patch_swap_ops = {
	.name = "swap",
	.collect_deps = process_collect_dependable_vmas,
	.set_jumps = NULL,
	.copy_data = copy_local_data,
	.check_backtrace = swap_check_backtrace,
	.fix_references = fix_target_references,
	.cleanup_target = unmap_old_lib,
};

static struct patch_ops_s *get_patch_ops(const char *how)
{
	if (!strcmp(how, "jump"))
		return &patch_jump_ops;
	if (!strcmp(how, "swap"))
		return &patch_swap_ops;
	pr_msg("Error: \"how\" option can be either \"jump\" or \"swap\"\n");
	return NULL;
}
#endif
#ifdef SWAP_PATCHING
static const struct patch_ops_s *set_patch_ops(const char *how, const char *type)
#else
static const struct patch_ops_s *set_patch_ops(const char *type)
#endif
{
	struct patch_ops_s *ops;
	int (*apply)(struct process_ctx_s *ctx);

	if (!strcmp(type, "ET_DYN"))
		apply = apply_dyn_binpatch;
	else {
		pr_err("Unknown patch type: %s\n", type);
		return NULL;
	}
#ifdef SWAP_PATCHING
	ops = get_patch_ops(how);
#else
	ops = &patch_jump_ops;
#endif
	ops->apply_patch = apply;
	return ops;
}

#ifdef SWAP_PATCHING
int check_patch_mode(const char *how)
{
	return get_patch_ops(how) ? 0 : -EINVAL;
}
#endif
