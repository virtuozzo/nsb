#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>

#include "include/patch.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/vma.h"
#include "include/elf.h"

#include "include/process.h"
#include "include/x86_64.h"
#include "include/backtrace.h"

struct process_ctx_s process_context;

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

static int apply_exec_binpatch(struct process_ctx_s *ctx)
{
	int i, err = 0;
	struct binpatch_s *binpatch = &ctx->binpatch;
	BinPatch *bp = binpatch->bp;
	struct funcpatch_s *funcpatch;

	pr_debug("Applying static binary patch:\n");

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

static int discover_plt_hints(struct process_ctx_s *ctx, const BinPatch *bp)
{
	int i, err;
	void *handle;
	LIST_HEAD(vmas);

	pr_info("= Discovering target PLT hints:\n");

	pr_debug("  - Dlopen %s\n", bp->new_path);
	handle = dlopen(bp->new_path, RTLD_NOW);
	if (!handle) {
		pr_err("failed to dlopen %s: %s\n",bp->new_path, dlerror());
		return 1;
	}

	if (collect_vmas(getpid(), &vmas)) {
		pr_err("Can't collect local mappings\n");
		goto err;
	}

	for (i = 0; i < bp->n_relocations; i++) {
		RelaPlt *rp = bp->relocations[i];
		unsigned long addr;
		const struct vma_area *vma;

		if (rp->addend) {
			// Local symbol. Skip.
			continue;
		}

		if (rp->hint) {
			// Already discovered symbol in previous version of the
			// library. Skip.
			continue;
		}

		pr_info("  - searching external symbol '%s':\n", rp->name);

		addr = (unsigned long)dlsym(handle, rp->name);
		if (!addr) {
			pr_err("failed to find symbol %s: %s\n", rp->name, dlerror());
			return 1;
		}

		vma = find_vma_by_addr(&vmas, addr);
		if (!vma) {
			pr_err("failed to find local vma with address %#lx\n", addr);
			goto err;
		}

		rp->hint = addr - vma->start;
		rp->path = vma->path;

		pr_info("     file   : %s\n", rp->path);
		pr_info("     offset : %#lx\n", rp->hint);
	}
	// TODO: need to:
	// 1) get all external symbol addresses
	// 2) get libraries by addresses.
	// 3) make sure, that all these libraries are mapped within the process by names
	// 4) make sure, that inodes of external libraries in nsb are equal to corresponding in the process.
	// 5) discover symbols offsets within mappings.
	// 6) use them to patch the new library.
	err = 0;
err:
	dlclose(handle);
	return err;
}

static int apply_rela_plt(struct process_ctx_s *ctx, const BinPatch *bp)
{
	int i;
	int err;
	int64_t load_addr = ctx->new_base;

	pr_info("= Applying destination PLT relocations:\n");

	for (i = 0; i < bp->n_relocations; i++) {
		RelaPlt *rp = bp->relocations[i];
		uint64_t plt_addr;
		uint64_t func_addr;

		pr_info("  - Entry \"%s\" (%s at %#x):\n",
			 rp->name, rp->info_type, rp->offset);

		plt_addr = load_addr + rp->offset;

		if (rp->addend) {
			pr_info("      Locality      : internal\n");
			func_addr = load_addr + rp->addend;
			pr_info("      Object address: %#lx (%#lx + %#x)\n",
					func_addr, load_addr, rp->addend);
		} else {
			const struct vma_area *vma;

			pr_info("      Locality      : external\n");

			vma = find_vma_by_path(&ctx->vmas, rp->path);
			if (!vma) {
				pr_err("failed to find %s map\n", rp->path);
				return -EINVAL;
			}
			pr_info("      Mapped file   : %s at %#lx\n", vma->path, vma->start);
			pr_debug("    %s start: %#lx\n", rp->path, vma->start);
			func_addr = vma->start + rp->hint;
			pr_info("      Object address: %#lx (%#lx + %#lx)\n",
					func_addr, vma->start, rp->hint);
		}

		pr_info("      PLT address   : %#lx\n", plt_addr);
		pr_info("        Overwrite .got.plt entry: %#lx ---> %#lx\n",
				func_addr, plt_addr);

		err = process_write_data(ctx->pid, plt_addr, &func_addr, sizeof(func_addr));
		if (err) {
			pr_err("failed to write to addr %#lx in process %d\n",
					plt_addr, ctx->pid);
			return err;
		}
	}
	return 0;
}

static RelaPlt *get_real_plt_by_name(const BinPatch *bp, const char *name)
{
	int i;

	for (i = 0; i < bp->n_relocations; i++) {
		RelaPlt *rp = bp->relocations[i];

		if (!strcmp(rp->name, name))
			return rp;
	}
	return NULL;
}

static int fix_plt_entry(struct process_ctx_s *ctx, BinPatch *bp, FuncPatch *fp)
{
	RelaPlt *rp;
	uint64_t old_plt_addr, new_plt_addr;
	uint64_t new_func_addr;
	int err;

	pr_info("  - Entry \"%s\":\n", fp->name);

	rp = get_real_plt_by_name(bp, fp->name);
	if (!rp) {
		pr_err("failed to find function %s in .rela.plt\n", fp->name);
		return 1;
	}

	old_plt_addr = ctx->old_base + rp->hint;
	new_plt_addr = ctx->new_base + rp->offset;

	pr_info("      Old PLT address     : %#lx\n", old_plt_addr);

	err = process_read_data(ctx->pid, new_plt_addr,
				&new_func_addr, sizeof(new_func_addr));
	if (err)
		return err;

	pr_info("      New Function address: %#lx\n", new_func_addr);

	pr_info("        Overwrite .got.plt entry: %#lx ---> %#lx\n",
			new_func_addr, old_plt_addr);

	err = process_write_data(ctx->pid, old_plt_addr,
				 (void *)&new_func_addr, sizeof(new_func_addr));
	if (err < 0) {
		pr_err("failed to patch: %d\n", err);
		return err;
	}
	return 0;
}

static int fix_dyn_entry(struct process_ctx_s *ctx, BinPatch *bp, FuncPatch *fp)
{
	unsigned char jump[X86_MAX_SIZE];
	unsigned long old_addr, new_addr;
	ssize_t size;
	int err;

	pr_info("  - Entry \"%s\":\n", fp->name);
	if (!fp->has_old_addr) {
		pr_debug("   New function. Skip\n");
		return 0;
	}

	old_addr = ctx->old_base + fp->old_addr;
	new_addr = ctx->new_base + fp->addr;

	pr_info("      old address: %#lx\n", old_addr);
	pr_info("      new address: %#lx\n", new_addr);

	pr_info("        jump: %#lx ---> %#lx\n", old_addr, new_addr);

	size = x86_jmpq_instruction(jump, old_addr, new_addr);
	if (size < 0)
		return size;

	err = process_write_data(ctx->pid, old_addr, jump, round_up(size, 8));
	if (err < 0) {
		pr_err("failed to patch: %d\n", err);
		return err;
	}
	return 0;
}

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

static int copy_local_data(struct process_ctx_s *ctx, BinPatch *bp)
{
	int i;

	// TODO: either all (!) functions have to be redirected from old library to new one,
	// or at least all the functions, accessing local data.
	// Otherwise some of the functions in the old library can modify old copy of the data, 
	// while some of the functions in the new library will modify new copy.
	pr_info("= Copy global variables:\n");
	for (i = 0; i < bp->n_local_vars; i++) {
		DataSym *ds = bp->local_vars[i];
		unsigned long from, to;
		int err;

		from = ctx->old_base + ds->ref;
		to = ctx->new_base + ds->offset;

		pr_info("  - %s (size: %d): %#lx ---> %#lx\n",
				ds->name, ds->size, from, to);
		err = process_copy_data(ctx->pid, to, from, ds->size);
		if (err)
			return err;
	}
	return 0;
}

static int apply_dyn_binpatch(struct process_ctx_s *ctx)
{
	struct binpatch_s *binpatch = &ctx->binpatch;
	BinPatch *bp = binpatch->bp;
	int err, i;

	pr_debug("Applying PIC binary patch:\n");

	err = discover_plt_hints(ctx, bp);
	if (err)
		return err;

	ctx->new_base = load_elf(ctx, bp, ctx->pvma->start);
	if (ctx->new_base < 0)
		return ctx->new_base;

	err = apply_rela_plt(ctx, bp);
	if (err)
		return err;

	/* There must be a check, that process doesn't reside in the library we
	 * patch, including all the calls to the current IP.
	 * IOW, there must be a stack rollback.
	 * This is required, becauce we have to fix _all_ the calls to the old
	 * library by replacing them to the new one.
	 * Why we need it? Because we can't change only one function, because
	 * this function cat access data. And if it accesses data, then
	 * data has to be updated in the new library to the current value
	 * in the old libraryr.
	 * While this means, that this data can be exported to other process (like errno) */
	pr_info("= Fix source PLT entries:\n");
	for (i = 0; i < bp->n_patches; i++) {
		FuncPatch *fp = bp->patches[i];

		if (fp->plt) {
			err = fix_plt_entry(ctx, bp, fp);
			if (err)
				return err;
		}
	}

	pr_info("= Apply jumps:\n");
	for (i = 0; i < bp->n_patches; i++) {
		FuncPatch *fp = bp->patches[i];

		if (fp->dyn) {
			err = fix_dyn_entry(ctx, bp, fp);
			if (err)
				return err;
		}
	}

	err = copy_local_data(ctx, bp);
	if (err)
		return err;

	return 0;
}

static int process_find_patchable_vma(struct process_ctx_s *ctx, BinPatch *bp)
{
	const struct vma_area *pvma;

	pr_info("= Searching source VMA:\n");

	pvma = find_vma_by_bid(&ctx->vmas, bp->old_bid);
	if (!pvma) {
		pr_err("failed to find process %d vma with Build ID %s\n",
				ctx->pid, bp->old_bid);
		return -ENOENT;
	}
	pr_info("  - path   : %s\n", pvma->path);
	pr_info("  - address: %#lx\n", pvma->start);
	ctx->pvma = pvma;
	ctx->old_base = ctx->pvma->start;
	return 0;
}

static int init_context(struct process_ctx_s *ctx, pid_t pid,
			const char *patchfile)
{
	struct binpatch_s *binpatch = &ctx->binpatch;
	BinPatch *bp;

	pr_info("Patch context:\n");
	pr_info("  Pid        : %d\n", pid);

	ctx->pid = pid;
	INIT_LIST_HEAD(&ctx->vmas),

	INIT_LIST_HEAD(&binpatch->functions);
	INIT_LIST_HEAD(&binpatch->places);

	bp = read_binpatch(patchfile);
	if (!bp)
		return -1;

	pr_info("  source BID : %s\n", bp->old_bid);
	pr_info("  target path: %s\n", bp->new_path);
	pr_info("  object type: %s\n", bp->object_type);

	if (collect_vmas(ctx->pid, &ctx->vmas)) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		goto err;
	}
	print_vmas(ctx->pid, &ctx->vmas);

	if (process_find_patchable_vma(ctx, bp))
		goto err;

	if (!strcmp(bp->object_type, "ET_EXEC"))
		ctx->apply = apply_exec_binpatch;
	else if (!strcmp(bp->object_type, "ET_DYN"))
		ctx->apply = apply_dyn_binpatch;
	else {
		pr_err("Unknown patch type: %s\n", bp->object_type);
		goto err;
	}

	binpatch->bp = bp;
	return 0;

err:
	bin_patch__free_unpacked(bp, NULL);
	return -1;
}

static int process_resume(struct process_ctx_s *ctx)
{
	pr_info("Resuming %d\n", ctx->pid);
	return process_cure(ctx);
}

static int process_call_in_map(const struct list_head *calls,
			       uint64_t map_start, uint64_t map_end)
{
	struct backtrace_function_s *bf;

	list_for_each_entry(bf, calls, list) {
		if ((map_start < bf->ip) && (bf->ip < map_end)) {
			pr_debug("Found call in stack within "
				 "patching range: %#lx (%#lx-%lx)\n",
				 bf->ip, map_start, map_end);
			return 1;
		}
	}
	return 0;
}

static int process_check_stack(struct process_ctx_s *ctx)
{
	struct binpatch_s *binpatch = &ctx->binpatch;
	BinPatch *bp = binpatch->bp;
	int err, i = 0;
	struct backtrace_s bt = {
		.calls = LIST_HEAD_INIT(bt.calls),
	};
	struct backtrace_function_s *bf;

	pr_info("Checking %d stack...\n", ctx->pid);

	err = process_backtrace(ctx->pid, &bt);
	if (err) {
		pr_err("failed to unwind process %d stack\n", ctx->pid);
		return err;
	}

	pr_debug("stack depth: %d\n", bt.depth);
	list_for_each_entry(bf, &bt.calls, list)
		pr_debug("#%d  %#lx in %s\n", i++, bf->ip, bf->name);

	for (i = 0; i < bp->n_patches; i++) {
		FuncPatch *fp = bp->patches[i];
		uint64_t start, end;

		/* Skip new functions: they are outside stack by default */
		if (fp->new_)
			continue;

		start = ctx->old_base + fp->addr;
		end = start + fp->size;

		pr_debug("Patch: %#lx - %#lx\n", start, end);
		if (process_call_in_map(&bt.calls, start, end))
			return -EAGAIN;
	}
	return 0;
}

static int process_catch(struct process_ctx_s *ctx)
{
	int ret, err;

	err = process_infect(ctx);
	if (err)
		return err;

	ret = process_check_stack(ctx);
	if (ret)
		goto err;

	return 0;

err:
	err = process_cure(ctx);
	return ret ? ret : err;
}

static int process_suspend(struct process_ctx_s *ctx)
{
	int try = 0, tries = 5;
	int timeout_msec = 100;
	int err;

	do {
		if (try) {
			pr_info("Failed to catch process in a suitable time/place.\n"
				"Retry in %d msec\n", timeout_msec);
			usleep(timeout_msec * 1000);
			timeout_msec <<= 1;
		}
		err = process_catch(ctx);
		if (err != -EAGAIN)
			break;
	} while (++try < tries);

	if (err == -EAGAIN) {
		return -ETIMEDOUT;
	}
	return err;
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

	ret = ctx->apply(ctx);
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
	BinPatch *bp;

	err = collect_vmas(pid, &vmas);
	if (err) {
		pr_err("Can't collect mappings for %d\n", pid);
		return err;
	}

	bp = read_binpatch(patchfile);
	if (!bp)
		return -1;

	return !find_vma_by_bid(&vmas, bp->old_bid);
}
