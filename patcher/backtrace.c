/* Inspired by libunwind: ./tests/test-ptrace.c */

#include <stdio.h>
#include <errno.h>
#include <libunwind-ptrace.h>

#include "include/log.h"
#include "include/list.h"
#include "include/xmalloc.h"
#include "include/backtrace.h"
#include "include/process.h"
#include "include/vma.h"

#define MAX_DEPTH	64

struct backtrace_function_s {
	struct list_head	list;
	uint64_t		ip;
	uint64_t		sp;
	int			sigframe;
	char			*name;
};

struct backtrace_s {
	int			depth;
	struct list_head	calls;
};

static struct backtrace_function_s *create_bt_func(unw_word_t ip, unw_word_t sp,
						   int sigframe, const char *name)
{
	struct backtrace_function_s *bf;

	bf = xzalloc(sizeof(*bf));

	if (!bf)
		return NULL;

	bf->ip = ip;
	bf->sp = sp;
	bf->sigframe = sigframe;
	if (strlen(name)) {
		bf->name = xstrdup(name);
		if (!bf->name)
			goto free_bf;
	}
	return bf;

free_bf:
	return NULL;
}

static int do_backtrace(unw_cursor_t *c, struct backtrace_s *bt)
{
	unw_word_t ip, sp, off;
	int ret;
	char buf[512];

	while (1) {
		struct backtrace_function_s *bf;
		int sigframe;

		*buf = '\0';

		ret = unw_get_reg(c, UNW_REG_IP, &ip);
		if (ret < 0) {
			pr_err("unw_get_reg(ip) failed: %d\n", ret);
			return ret;
		}

		ret = unw_get_reg(c, UNW_REG_SP, &sp);
		if (ret < 0) {
			pr_err("unw_get_reg(sp) failed: %d\n", ret);
			return ret;
		}

		(void)unw_get_proc_name(c, buf, sizeof (buf), &off);

		ret = unw_is_signal_frame(c);
		if (ret < 0) {
			pr_err("unw_is_signal_frame(c) failed: %d\n", ret);
			return ret;
		}

		sigframe = !!ret;

		ret = unw_step(c);
		if (ret < 0) {
			unw_get_reg(c, UNW_REG_IP, &ip);
			pr_err ("unw_step failed: %d (ip=%lx, start ip=%lx)\n",
					ret, ip, list_first_entry(&bt->calls, typeof(*bf), list)->ip);
			return ret;
		}

		/* It it the top frame? */
		if (!ret)
			break;

		if (bt->depth > MAX_DEPTH) {
			/* guard against bad unwind info in old libraries... */
			pr_err ("too deeply nested ---assuming bogus unwind (start ip=%#lx)\n",
				list_first_entry(&bt->calls, typeof(*bf), list)->ip);
			break;
		}

		bf = create_bt_func(ip, sp, sigframe, buf);
		if (!bf)
			return -ENOMEM;

		list_add_tail(&bf->list, &bt->calls);
		bt->depth++;
	}
	return ret;
}

int pid_backtrace(pid_t pid, struct backtrace_s **backtrace)
{
	int err = -EFAULT;
	void *ui;
	static unw_addr_space_t as;
	unw_cursor_t c;
	struct backtrace_s *bt;

	bt = xzalloc(sizeof(*bt));
	if (!bt)
		return -ENOMEM;

	INIT_LIST_HEAD(&bt->calls);

	as = unw_create_addr_space (&_UPT_accessors, 0);
	if (!as) {
		pr_err("unw_create_addr_space() failed\n");
		goto free_bt;
	}

	ui = _UPT_create (pid);
	if (!ui) {
		pr_err("_UPT_create() failed\n");
		goto destroy_as;
	}

	err = unw_init_remote (&c, as, ui);
	if (err < 0) {
		pr_err ("unw_init_remote() failed: ret=%d\n", err);
		goto destroy_ui;
	}


	err = do_backtrace(&c, bt);
	if (err)
		goto destroy_ui;

	*backtrace = bt;

destroy_ui:
	_UPT_destroy (ui);
destroy_as:
	unw_destroy_addr_space (as);
free_bt:
	if (err)
		free(bt);
	return err;
}

static const struct backtrace_function_s *bt_check_range(const struct backtrace_s *bt,
							 uint64_t start,
							 uint64_t end)
{
	const struct backtrace_function_s *bf;
	int i = 0;

	list_for_each_entry(bf, &bt->calls, list) {
		pr_debug("    #%d  %#lx in %s (signal frame: %d)\n", i++,
				bf->ip, bf->name, bf->sigframe);
		if (bf->sigframe)
			return bf;
		if ((start < bf->ip) && (bf->ip < end))
			return bf;
	}
	return NULL;
}

int backtrace_check_func(const struct process_ctx_s *ctx,
			 const struct func_jump_s *fj,
			 const void *data)
{
	const struct backtrace_s *bt = data;
	uint64_t func_start, func_end;
	const struct backtrace_function_s *bf;

	func_start = ctx->pvma->start + fj->func_value;
	func_end = func_start + fj->func_size;

	bf = bt_check_range(bt, func_start, func_end);
	if (!bf)
		return 0;

	if (bf->sigframe)
		pr_debug("    Found call \"%s\" within signal frame\n",
			 bf->name);
	else
		pr_debug("    Found call to \"%s\" (%#lx - %lx): %#lx\n",
			 fj->name, func_start, func_end, bf->ip);
	return -EAGAIN;
}

int backtrace_check_vma(const struct backtrace_s *bt,
			const struct vma_area *vma)
{
	const struct backtrace_function_s *bf;

	if (bt->depth == 1)
		return -EAGAIN;

	bf = bt_check_range(bt, vma->start, vma->end);
	if (!bf)
		return 0;

	if (bf->sigframe)
		pr_debug("    Found call \"%s\" within signal frame\n",
			 bf->name);
	else
		pr_debug("    Found call in stack within VMA %s range (%#lx-%lx): "
			 "%#lx \n", vma->path, vma->start, vma->end, bf->ip);
	return -EAGAIN;
}
