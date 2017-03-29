#include "nsb_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/mman.h>

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
#include "include/dl_map.h"

struct process_ctx_s process_context = {
	.service = {
		.name = "libnsb_service.so",
		.sock = -1,
	},
	.vmas = LIST_HEAD_INIT(process_context.vmas),
	.dl_maps = LIST_HEAD_INIT(process_context.dl_maps),
	.needed_list = LIST_HEAD_INIT(process_context.needed_list),
	.threads = LIST_HEAD_INIT(process_context.threads),
	.applied_patches = LIST_HEAD_INIT(process_context.applied_patches),
	.remote_vma = {
		.list = LIST_HEAD_INIT(process_context.remote_vma.list),
		.length = 4096,
		.flags = MAP_ANONYMOUS | MAP_PRIVATE,
		.prot = PROT_READ | PROT_WRITE | PROT_EXEC,
	},
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

	patch_addr = dlm_load_base(PDLM(ctx)) + fj->patch_value;

	pr_info("  - Function \"%s\":\n", fj->name);
	pr_info("      jump: %#lx ---> %#lx\n", fj->func_addr, patch_addr);

	if (ctx->dry_run)
		return 0;

	return process_write_data(ctx, fj->func_addr,
				  fj->func_jump, sizeof(fj->func_jump));
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

	fj->func_addr = dlm_load_base(TDLM(ctx)) + fj->func_value;
	patch_addr = dlm_load_base(PDLM(ctx)) + fj->patch_value;

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
	pr_info("= Unloading %s:\n", PDLM(ctx)->path);

	return unload_elf(ctx, PDLM(ctx));
}

static int load_patch(struct process_ctx_s *ctx)
{
	int err;
	struct dl_map *dlm;

	pr_info("= Loading %s:\n", ctx->patchfile);

	dlm = alloc_dl_map(ctx->patch_ei, ctx->patchfile);
	if (!dlm)
		return -ENOMEM;

	err = load_elf(ctx, dlm, dl_map_end(TDLM(ctx)));
	if (err)
		goto destroy_dlm;

	P(ctx)->patch_dlm = dlm;
	return 0;

destroy_dlm:
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
		goto revert_jumps;

	return 0;

revert_jumps:
	if (revert_func_jumps(ctx))
		pr_err("failed to revert function jumps\n");
	return err;

unload_patch:
	if (unload_patch(ctx))
		pr_err("failed to unload patch\n");
	return err;
}

int patch_set_target_dlm(struct process_ctx_s *ctx, struct patch_s *p)
{
	const struct dl_map *dlm;
	const char *bid = p->pi.target_bid;

	dlm = find_dl_map_by_bid(&ctx->dl_maps, bid);
	if (!dlm) {
		pr_err("failed to find vma with Build ID %s in process %d\n",
				bid, ctx->pid);
		return -ENOENT;
	}

	p->target_dlm = dlm;
	return 0;
}

int create_patch_by_dlm(struct process_ctx_s *ctx, const struct dl_map *dlm,
			struct patch_s **patch)
{
	struct patch_s *p;
	int err;

	pr_info("  %s: %s\n", dlm->path, elf_bid(dlm->ei));

	p = xmalloc(sizeof(*p));
	if (!p)
		return -ENOMEM;

	err = elf_info_binpatch(&p->pi, dlm->ei);
	if (err)
		goto free_patch;

	err = patch_set_target_dlm(ctx, p);
	if (err)
		goto free_patch;

	INIT_LIST_HEAD(&p->rela_plt);
	INIT_LIST_HEAD(&p->rela_dyn);
	p->patch_dlm = dlm;

	print_dl_vmas(p->patch_dlm);

	*patch = p;
	return 0;

free_patch:
	free(p);
	return err;
}

static int create_patch(struct elf_info_s *ei, struct patch_s **patch)
{
	int err;
	struct patch_s *p;

	p = xmalloc(sizeof(*p));
	if (!p)
		return -ENOMEM;

	err = elf_info_binpatch(&p->pi, ei);
	if (err)
		goto free_patch;

	INIT_LIST_HEAD(&p->rela_plt);
	INIT_LIST_HEAD(&p->rela_dyn);

	*patch = p;

	return 0;

free_patch:
	free(p);
	return err;
}

struct patch_s *find_patch_by_bid(struct process_ctx_s *ctx, const char *bid)
{
	struct patch_s *p;

	list_for_each_entry(p, &ctx->applied_patches, list) {
		if (!strcmp(p->pi.patch_bid, bid))
			return p;
	}
	return NULL;
}

static int init_patch(struct process_ctx_s *ctx)
{
	int err;
	struct elf_info_s *ei;

	err = elf_create_info(ctx->patchfile, &ei);
	if (err)
		return err;

	err = create_patch(ei, &ctx->patch);
	if (err)
		goto destroy_elf;

	ctx->patch_ei = ei;
	return 0;

destroy_elf:
	elf_destroy_info(ei);
	return err;
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
				 const struct backtrace_s *bt,
				 uint64_t start, uint64_t end)
{
	const struct patch_info_s *pi = PI(ctx);
	int i, err;

	for (i = 0; i < pi->n_func_jumps; i++) {
		err = backtrace_check_func(pi->func_jumps[i], bt, start);
		if (err)
			return err;
	}
	return 0;
}

static int init_context(struct process_ctx_s *ctx, pid_t pid,
			const char *patchfile, int dry_run)
{
	if (elf_library_status())
		return -1;

	pr_info("Patch context:\n");
	pr_info("  Pid        : %d\n", pid);

	ctx->pid = pid;
	ctx->patchfile = patchfile;
	ctx->dry_run = dry_run;

	if (init_patch(ctx))
		return 1;

	pr_info("  Patch path    : %s\n", ctx->patchfile);
	pr_info("  Target BuildId: %s\n", PI(ctx)->target_bid);

	return 0;
}

int patch_process(pid_t pid, const char *patchfile, int dry_run)
{
	int ret, err;
	struct process_ctx_s *ctx = &process_context;

	err = init_context(ctx, pid, patchfile, dry_run);
	if (err)
		return err;

	ctx->check_backtrace = jumps_check_backtrace;

	err = process_suspend(ctx, PI(ctx)->target_bid);
	if (err)
		return err;

	ret = process_link(ctx);
	if (ret)
		goto resume;

	ret = process_collect_vmas(ctx);
	if (ret)
		goto resume;

	ret = process_find_patch(ctx);
	if (ret)
		goto resume;

	ret = process_find_target_dlm(ctx);
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

	ret = apply_dyn_binpatch(ctx);
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
	struct process_ctx_s *ctx = &process_context;

	err = init_context(ctx, pid, patchfile, 0);
	if (err)
		return err;

	err = process_collect_vmas(ctx);
	if (err)
		return err;

	return !find_patch_by_bid(ctx, PI(ctx)->patch_bid);
}

static void list_patch(const struct patch_s *p)
{
	pr_msg("  %s (%s) - ", p->patch_dlm->path, p->pi.patch_bid);
	if (p->target_dlm)
		pr_msg("%s\n", p->target_dlm->path);
}

int list_process_patches(pid_t pid)
{
	int err;
	struct process_ctx_s *ctx = &process_context;
	struct patch_s *p;

	if (elf_library_status())
		return -1;

	ctx->pid = pid;

	err = process_collect_vmas(ctx);
	if (err)
		return err;

	if (list_empty(&ctx->applied_patches))
		return 0;

	list_for_each_entry(p, &ctx->applied_patches, list)
		list_patch(p);

	return 0;
}
