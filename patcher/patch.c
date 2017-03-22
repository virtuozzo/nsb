#include "nsb_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#include "include/patch.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/vma.h"
#include "include/elf.h"

#include "include/context.h"
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
	},
	.service = {
		.name = "libnsb_service.so",
		.sock = -1,
	},
	.vmas = LIST_HEAD_INIT(process_context.vmas),
	.objdeps = LIST_HEAD_INIT(process_context.objdeps),
	.threads = LIST_HEAD_INIT(process_context.threads),
};

static int write_func_code(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	pr_info("  - Restoring code in \"%s\":\n", fj->name);
	pr_info("      old address: %#lx\n", fj->func_addr);

	return process_write_data(ctx, fj->func_addr,
				  fj->code, sizeof(fj->code));
}

static int write_func_jump(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	uint64_t patch_addr;
	int err;

	patch_addr = PLA(ctx) + fj->patch_value;

	pr_info("  - Function \"%s\":\n", fj->name);

	err = process_write_data(ctx, fj->func_addr,
				 fj->func_jump, sizeof(fj->func_jump));
	if (err)
		return err;
	pr_info("      jump: %#lx ---> %#lx\n", fj->func_addr, patch_addr);
	return 0;
}

static int apply_func_jumps(struct process_ctx_s *ctx)
{
	int i, err;
	struct patch_info_s *pi = PI(ctx);

	pr_info("= Apply function jumps:\n");
	for (i = 0; i < pi->n_func_jumps; i++) {
		struct func_jump_s *fj = pi->func_jumps[i];

		err = write_func_jump(ctx, fj);
		if (err) {
			pr_err("failed to apply function jump\n");
			return err;
		}
	}
	return 0;
}

static int read_func_jump_code(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	return process_read_data(ctx, fj->func_addr,
				 fj->code, sizeof(fj->code));
}

static int tune_func_jump(struct process_ctx_s *ctx, struct func_jump_s *fj)
{
	uint64_t patch_addr;
	ssize_t size;

	pr_info("  - Function \"%s\":\n", fj->name);

	fj->func_addr = vma_func_addr(TVMA(ctx), fj->func_value);

	patch_addr = PLA(ctx) + fj->patch_value;

	pr_info("      original address: %#lx\n", fj->func_addr);
	pr_info("      patch address   : %#lx\n", patch_addr);

	size = x86_jmpq_instruction(fj->func_jump, sizeof(fj->func_jump),
				    fj->func_addr, patch_addr);
	if (size < 0)
		return size;

	return read_func_jump_code(ctx, fj);
}

static int tune_func_jumps(struct process_ctx_s *ctx)
{
	int i, err;
	struct patch_info_s *pi = PI(ctx);

	pr_info("= Tune function jumps:\n");
	for (i = 0; i < pi->n_func_jumps; i++) {
		struct func_jump_s *fj = pi->func_jumps[i];

		err = tune_func_jump(ctx, fj);
		if (err) {
			pr_err("failed to tune function jump\n");
			return err;
		}
	}
	return 0;
}

static int unload_patch(struct process_ctx_s *ctx)
{
	pr_info("= Unloading %s:\n", elf_path(P(ctx)->ei));

	return unload_elf(ctx, &P(ctx)->segments);
}

static int64_t load_patch(struct process_ctx_s *ctx)
{
	uint64_t hint;
	const struct vma_area *vma;
	int err;

	pr_info("= Loading %s:\n", elf_path(P(ctx)->ei));

	if (elf_type_dyn(TVMA(ctx)->ei))
		/*
		 * TODO: there should be bigger offset. 2 or maybe even 4 GB.
		 * But jmpq command construction fails, if map lays ouside 2g offset.
		 * This might be a bug in jmps construction
		 */
		hint = vma_start(TVMA(ctx)) & 0xfffffffff0000000;
	else
		hint = 0x1000000;

	err = load_elf(ctx, &P(ctx)->segments, P(ctx)->ei, hint);
	if (err)
		return err;

	vma = first_vma(&P(ctx)->segments);
	if (!vma) {
		pr_err("patch segments list is empty\n");
		return -EFAULT;
	}

	P(ctx)->load_addr = vma_start(vma);

	return 0;
}

static int apply_dyn_binpatch(struct process_ctx_s *ctx)
{
	int err;

	err = load_patch(ctx);
	if (err) {
		pr_err("failed to load patch\n");
		return err;
	}

	err = apply_relocations(ctx);
	if (err)
		goto unload_patch;

	err = tune_func_jumps(ctx);
	if (err)
		goto unload_patch;

	err = apply_func_jumps(ctx);
	if (err)
		goto unload_patch;

	return 0;

unload_patch:
	if (ctx->ops->revert_patch(ctx))
		pr_err("failed to revert patch\n");
	return err;
}

static int func_jump_applied(struct process_ctx_s *ctx,
			     const struct func_jump_s *fj)
{
	int err;
	uint8_t code[8];

	BUILD_BUG_ON(sizeof(code) != sizeof(fj->func_jump));

	if (!fj->func_addr)
		return 0;

	err = process_read_data(ctx, fj->func_addr, code, sizeof(code));
	if (err)
		return err;

	return !memcmp(code, fj->func_jump, sizeof(code));
}

static int revert_func_jumps(struct process_ctx_s *ctx)
{
	int i, err, applied;
	struct patch_info_s *pi = PI(ctx);

	pr_info("= Revert function jumps:\n");
	for (i = 0; i < pi->n_func_jumps; i++) {
		struct func_jump_s *fj = pi->func_jumps[i];

		applied = func_jump_applied(ctx, fj);
		if (applied < 0)
			return applied;

		if (!applied)
			continue;

		err = write_func_code(ctx, fj);
		if (err) {
			pr_err("failed to revert function jump\n");
			return err;
		}
	}
	return 0;
}

static int revert_dyn_binpatch(struct process_ctx_s *ctx)
{
	int err;

	err = revert_func_jumps(ctx);
	if (err)
		return err;
	return unload_patch(ctx);
}

static int process_find_patchable_vma(struct process_ctx_s *ctx, const char *bid)
{
	const struct vma_area *vma;

	pr_info("= Searching source VMA:\n");

	vma = find_vma_by_bid(&ctx->vmas, bid);
	if (!vma) {
		pr_err("failed to find vma with Build ID %s in process %d\n",
				bid, ctx->pid);
		return -ENOENT;
	}
	pr_info("  - path   : %s\n", vma->path);
	pr_info("  - address: %#lx\n", vma_start(vma));
	TVMA(ctx) = vma;
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

	err = elf_create_info(PI(ctx)->path, &p->ei);
	if (err)
		return err;

	if (strcmp(elf_bid(p->ei), PI(ctx)->new_bid)) {
		pr_err("BID of %s doesn't match patch BID: %s != %s\n",
				PI(ctx)->path, elf_bid(p->ei),
				PI(ctx)->new_bid);
		return -EINVAL;
	}
	return 0;
}

int process_resume(struct process_ctx_s *ctx)
{
	int err;

	err = process_shutdown_service(ctx);
	if (err)
		return err;

	err = process_unlink(ctx);
	if (err)
		return err;

	pr_info("= Resuming %d\n", ctx->pid);
	return process_cure(ctx);
}

static int jumps_check_backtrace(const struct process_ctx_s *ctx,
				 const struct backtrace_s *bt)
{
	const struct patch_info_s *pi = PI(ctx);
	int i, err;

	for (i = 0; i < pi->n_func_jumps; i++) {
		err = backtrace_check_func(ctx, pi->func_jumps[i], bt);
		if (err)
			return err;
	}
	return 0;
}

struct patch_ops_s patch_jump_ops = {
	.apply_patch = apply_dyn_binpatch,
	.revert_patch = revert_dyn_binpatch,
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

	if (init_patch(ctx))
		return 1;

	ctx->ops = &patch_jump_ops;

	pr_info("  Target BuildId: %s\n", PI(ctx)->old_bid);
	pr_info("  Patch path    : %s\n", PI(ctx)->path);

	if (process_collect_vmas(ctx))
		return 1;

	if (process_find_patch(ctx, PI(ctx)->new_bid))
		return 1;

	if (process_find_patchable_vma(ctx, PI(ctx)->old_bid))
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

	ret = process_inject_service(ctx);
	if (ret)
		goto resume;

	ret = process_collect_needed(ctx);
	if (ret)
		goto resume;

	ret = collect_relocations(ctx);
	if (ret)
		goto resume;

	ret = resolve_relocations(ctx);
	if (ret)
		goto resume;

	ret = ctx->ops->apply_patch(ctx);
	if (ret)
		pr_err("failed to apply binary patch\n");

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

