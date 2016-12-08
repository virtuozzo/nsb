/* Inspired by libunwind: ./tests/test-ptrace.c */

#include <stdio.h>
#include <errno.h>
#include <libunwind-ptrace.h>

#include "include/log.h"
#include "include/list.h"
#include "include/xmalloc.h"
#include "include/backtrace.h"

#define MAX_DEPTH	64
static int verbose = 1;
static int print_names = 1;

static struct backtrace_function_s *create_bt_func(unw_word_t ip, unw_word_t sp, const char *name)
{
	struct backtrace_function_s *bf;

	bf = xzalloc(sizeof(*bf));

	if (!bf)
		return NULL;

	bf->ip = ip;
	bf->sp = sp;
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

		bf = create_bt_func(ip, sp, buf);
		if (!bf)
			return -ENOMEM;

		list_add_tail(&bf->list, &bt->calls);
		bt->depth++;
	}
	return ret;
}

int process_backtrace(pid_t pid, struct backtrace_s *bt)
{
	int err = 1;
	void *ui;
	static unw_addr_space_t as;
	unw_cursor_t c;

	as = unw_create_addr_space (&_UPT_accessors, 0);
	if (!as) {
		pr_err("unw_create_addr_space() failed\n");
		return 1;
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

destroy_ui:
	_UPT_destroy (ui);
destroy_as:
	unw_destroy_addr_space (as);
	return err;
}

