#include "include/relocations.h"
#include "include/list.h"
#include "include/log.h"
#include "include/elf.h"
#include "include/process.h"
#include "include/context.h"
#include "include/vma.h"
#include "include/dl_map.h"

static void print_relocation(const struct list_head *head, const char *name)
{
	struct extern_symbol *es;

	if (list_empty(head))
		return;

	pr_debug("  %s:\n", name);
	pr_debug("    Offset        Info          Type               "
		 "Symbol value      Name + Addend\n");
	list_for_each_entry(es, head, list)
		pr_debug("    %012lx  %012lx  %17.17s  %016lx  %s + %ld:\n",
				es_r_offset(es), es_r_info(es),
				es_relocation(es), es_s_value(es),
				es->name, es_r_addend(es));
}

int collect_relocations(struct process_ctx_s *ctx)
{
	int err;

	pr_debug("= Collect relocations:\n");

	err = elf_rela_plt(ctx->patch_ei, &P(ctx)->rela_plt);
	if (err)
		return err;

	print_relocation(&P(ctx)->rela_plt, ".rela.plt");

	err = elf_rela_dyn(ctx->patch_ei, &P(ctx)->rela_dyn);
	if (err)
		return err;

	print_relocation(&P(ctx)->rela_plt, ".rela.plt");
	return 0;
}

static int64_t __find_dym_sym(const struct list_head *deps,
			      const struct dl_map *stop_dlm,
			      struct extern_symbol *es,
			      uint64_t patch_value)
{
	int64_t value;
	const struct ctx_dep *n;

	es->dlm = NULL;
	list_for_each_entry(n, deps, list) {
		const struct dl_map *dlm = n->dlm;

		/* If symbol is defined in the patch and we reached the old
		 * library, stop and returm patch value.
		 * The reason is that with new library linked, this symbol will
		 * be found in it.
		 * Without this check we can find the symbol not in the patch,
		 * but somewhere else in soname list, which is wrong.
		 */
		if (patch_value && (dlm == stop_dlm))
			/* Note, that VMA remains NULL. It will be used is
			 * patch marker in apply_es()
			 */
			return patch_value;

		value = elf_dyn_sym_value(dlm->ei, es->name);
		if (value < 0)
			return value;
		if (value) {
			es->dlm = dlm;
			return value;
		}
	}
	return -ENOENT;
}

static int64_t check_sym_info(const struct process_ctx_s *ctx,
			      struct extern_symbol *es)
{
	int i;
	const struct patch_info_s *pi = PI(ctx);

	for (i = 0; i < pi->n_static_syms; i++) {
		const struct static_sym_s *si = pi->static_syms[i];

		if (si->idx == es_r_sym(es)) {
			es->dlm = TDLM(ctx);
			return si->addr;
		}
	}
	return 0;
}

static int64_t find_dym_sym(const struct process_ctx_s *ctx,
			    struct extern_symbol *es)
{
	int64_t value;

	value = check_sym_info(ctx, es);
	if (value)
		return value;

	value = __find_dym_sym(&ctx->needed_list, TDLM(ctx), es, es_s_value(es));
	if (value != -ENOENT)
		return value;

	return __find_dym_sym(&ctx->needed_list, NULL, es, es_s_value(es));
}

static int resolve_symbol(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int err;
	int64_t value;

	value = find_dym_sym(ctx, es);
	if (value < 0)
		return value;

	err = elf_reloc_sym(es, value);
	if (err < 0)
		return err;

	return 0;
}

static void print_resolution(struct process_ctx_s *ctx,
			     const struct list_head *head, const char *name)
{
	struct extern_symbol *es;

	if (list_empty(head))
		return;

	pr_debug("  %s:\n", name);
	pr_debug("      Nr:  Value         Size   Type    Bind    Name\n");
	list_for_each_entry(es, head, list)
		pr_debug("    %4d:  %012lx  %4ld  %7.7s  %6.6s  %s  %s\n",
				es_r_sym(es), es->address,
				es_s_size(es), es_type(es), es_binding(es),
				es->name,
				(es->address == 0) ? "" :
				((es->dlm) ? es->dlm->path : TDLM(ctx)->path));
}

static int resolve_es(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int err;

	if (elf_weak_sym(es) && (es_s_value(es) == 0)) {
		list_del(&es->list);
		return 0;
	}

	err = resolve_symbol(ctx, es);
	if (err) {
		pr_err("failed to resolve %s symbol\n", es->name);
		return -ENOENT;
	}
	return 0;
}

int resolve_relocations(struct process_ctx_s *ctx)
{
	int err;
	struct extern_symbol *es, *tmp;

	pr_debug("= Resolve relocations:\n");

	list_for_each_entry_safe(es, tmp, &P(ctx)->rela_plt, list) {
		err = resolve_es(ctx, es);
		if (err)
			return err;
	}

	list_for_each_entry_safe(es, tmp, &P(ctx)->rela_dyn, list) {
		err = resolve_es(ctx, es);
		if (err)
			return err;
	}

	print_resolution(ctx, &P(ctx)->rela_plt, ".rela.plt");
	print_resolution(ctx, &P(ctx)->rela_dyn, ".rela.dyn");
	return 0;
}

static int apply_es(const struct process_ctx_s *ctx, struct extern_symbol *es)
{
	int err;
	uint64_t plt_addr;
	uint64_t func_addr;
	const struct dl_map *dlm;

	dlm = es->dlm ? es->dlm : PDLM(ctx);

	plt_addr = dlm_load_base(PDLM(ctx)) + es_r_offset(es);
	func_addr = dlm_load_base(dlm) + es->address;

	pr_debug("    %4d:  %#012lx  %#012lx %s:  %s + %#lx\n",
			es_r_sym(es), plt_addr, func_addr, es->name,
			((es->dlm) ? es->dlm->path : TDLM(ctx)->path),
			es->address);

	err = process_write_data(ctx, plt_addr, &func_addr, sizeof(func_addr));
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

	if (!list_empty(&P(ctx)->rela_plt)) {
		pr_debug("    .rela.plt:\n");
		pr_debug("      Nr:  PLT             Address        Name: Library + Offset\n");
		list_for_each_entry(es, &P(ctx)->rela_plt, list) {
			err = apply_es(ctx, es);
			if (err)
				return err;
		}
	}

	if (!list_empty(&P(ctx)->rela_dyn)) {
		pr_debug("    .rela.dyn:\n");
		pr_debug("      Nr:  PLT             Address        Name: Library + Offset\n");
		list_for_each_entry(es, &P(ctx)->rela_dyn, list) {
			err = apply_es(ctx, es);
			if (err)
				return err;
		}
	}
	return 0;
}
