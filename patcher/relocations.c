#include "include/relocations.h"
#include "include/list.h"
#include "include/log.h"
#include "include/elf.h"
#include "include/process.h"
#include "include/vma.h"

int collect_relocations(struct process_ctx_s *ctx)
{
	int err;
	struct extern_symbol *es;

	pr_debug("= Collect relocations:\n");

	err = elf_rela_plt(P(ctx)->ei, &P(ctx)->rela_plt);
	if (err)
		return err;

	pr_debug("    .rela.plt:\n");
	list_for_each_entry(es, &P(ctx)->rela_plt, list) {
		pr_debug("      - %d:\n", es_r_sym(es));
		pr_debug("          name    : %s:\n", es->name);
		pr_debug("          offset  : %#lx\n", es_r_offset(es));
		pr_debug("          bind    : %d (%s)\n", es_s_bind(es), es_binding(es));
		pr_debug("          r_type  : %d (%s)\n", es_r_type(es), es_relocation(es));
	}

	err = elf_rela_dyn(P(ctx)->ei, &P(ctx)->rela_dyn);
	if (err)
		return err;

	pr_debug("    .rela.dyn:\n");
	list_for_each_entry(es, &P(ctx)->rela_dyn, list) {
		pr_debug("      - %d:\n", es_r_sym(es));
		pr_debug("          name    : %s:\n", es->name);
		pr_debug("          offset  : %#lx\n", es_r_offset(es));
		pr_debug("          bind    : %d (%s)\n", es_s_bind(es), es_binding(es));
		pr_debug("          r_type  : %d (%s)\n", es_r_type(es), es_relocation(es));
	}

	return 0;
}

static int find_global_sym(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int64_t ret;
	const struct ctx_dep *n;

	list_for_each_entry(n, &ctx->objdeps, list) {
		const struct vma_area *vma = n->vma;

		ret = elf_has_glob_sym(vma->ei, es->name);
		if (ret < 0)
			return ret;
		if (ret) {
			es->vma = vma;
			return ret;
		}
	}
	return -ENOENT;
}

static int resolve_global(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int64_t ret;

	pr_debug("      - %d:\n", es_r_sym(es));
	pr_debug("          name    : %s:\n", es->name);

	ret = find_global_sym(ctx, es);
	if (ret < 0)
		return ret;

	return elf_reloc_sym(es, es->vma->start + ret);
}

static int resolve_weak(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int ret;

	ret = resolve_global(ctx, es);
	if (ret == -ENOENT)
		return elf_reloc_sym(es, P(ctx)->load_addr + ret);
	return ret;
}

static int resolve_es(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int err;
	if (elf_glob_sym(es))
		err = resolve_global(ctx, es);
	else if (elf_weak_sym(es))
		err = resolve_weak(ctx, es);
	else {
		pr_err("Uknown symbol bind: %d\n", es_s_bind(es));
		return -EINVAL;
	}
	if (err) {
		pr_err("failed to resolve %s symbol\n", es->name);
		return -ENOENT;
	}
	return 0;
}

int resolve_relocations(struct process_ctx_s *ctx)
{
	int err;
	struct extern_symbol *es;

	pr_debug("= Resolve relocations:\n");

	pr_debug("    .rela.plt:\n");
	list_for_each_entry(es, &P(ctx)->rela_plt, list) {
		err = resolve_es(ctx, es);
		if (err)
			return err;
	}
	pr_debug("    .rela.dyn:\n");
	list_for_each_entry(es, &P(ctx)->rela_dyn, list) {
		err = resolve_es(ctx, es);
		if (err)
			return err;
	}
	return 0;
}

static int apply_es(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int err;
	uint64_t plt_addr;
	uint64_t func_addr;

	pr_debug("      - %d:\n", es_r_sym(es));

	if (!es->address) {
		pr_debug("          Skip\n");
		return 0;
	}

	pr_debug("          name     : %s:\n", es->name);
	pr_debug("          offset   : %#lx\n", es->address);
	if (es->vma)
		pr_debug("          vma      : %s\n", es->vma->path);

	plt_addr = PLA(ctx) + es_r_offset(es);
	pr_debug("          PLT addr : %#lx\n", plt_addr);

	func_addr = es->address;
	pr_debug("          Func addr: %#lx\n", func_addr);

	pr_info("        Overwrite .got.plt entry: %#lx ---> %#lx\n",
			func_addr, plt_addr);

	err = process_write_data(ctx->pid, plt_addr, &func_addr, sizeof(func_addr));
	if (err) {
		pr_err("failed to write to addr %#lx in process %d\n",
				plt_addr, ctx->pid);
		return err;
	}
	return err;
}

int apply_relocations(struct process_ctx_s *ctx)
{
	int err;
	struct extern_symbol *es;

	pr_info("= Applying patch relocations:\n");

	pr_debug("    .rela.plt:\n");
	list_for_each_entry(es, &P(ctx)->rela_plt, list) {
		err = apply_es(ctx, es);
		if (err)
			return err;
	}

	pr_debug("    .rela.dyn:\n");
	list_for_each_entry(es, &P(ctx)->rela_dyn, list) {
		err = apply_es(ctx, es);
		if (err)
			return err;
	}
	return 0;
}
