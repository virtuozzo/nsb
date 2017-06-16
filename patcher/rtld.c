/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <stdint.h>
#include <link.h>
#include <gelf.h>
#include <errno.h>

#include "include/context.h"
#include "include/process.h"
#include "include/rtld.h"
#include "include/log.h"
#include "include/xmalloc.h"

static int rtld_get_dyn(struct process_ctx_s *ctx, const void *addr, GElf_Dyn *dyn)
{
	return process_read_data(ctx, (uint64_t)addr, dyn, sizeof(*dyn));
}

static int64_t rtld_dynamic_tag_val(struct process_ctx_s *ctx,
				    const GElf_Dyn *l_ld, uint32_t d_tag)
{
	GElf_Dyn dyn;
	const GElf_Dyn *d;
	int err;

	for (d = l_ld; ; d++) {
		err = rtld_get_dyn(ctx, d, &dyn);
		if (err)
			return err;

		if (dyn.d_tag == DT_NULL)
			break;

		if (dyn.d_tag == d_tag)
			return dyn.d_un.d_val;
	}
	return -ENOENT;
}

static int rtld_get_lm(struct process_ctx_s *ctx, void *addr, struct link_map *lm)
{
	return process_read_data(ctx, (uint64_t)addr, lm, sizeof(*lm));
}

int rtld_needed_array(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array)
{
	struct link_map link_map, *lm = &link_map;
	void *lm_addr;
	int err, nr = 0;
	const int step = 10;
	uint64_t *arr = NULL;

	err = process_read_data(ctx, _r_debug_addr + offsetof(struct r_debug, r_map),
				&lm_addr, sizeof(lm_addr));
	if (err)
		return err;

	do {
		int64_t dt_symtab_addr;

		err = rtld_get_lm(ctx, lm_addr, lm);
		if (err)
			return err;

		/* We rely upon presense of DT_SYMTAB, because it's mandatory */
		dt_symtab_addr = rtld_dynamic_tag_val(ctx, lm->l_ld, DT_SYMTAB);
		if (dt_symtab_addr == -ENOENT)
			return dt_symtab_addr;

		/* Check dt_symtab_addr for non-negative value.
		 * This is diferent in VDSO, which has negative addresses
		 * (offsets from base)?
		 */
		if (dt_symtab_addr >= 0) {
			if ((nr % step) == 0) {
				arr = xrealloc(arr, step * sizeof(uint64_t));
				if (!arr)
					return -ENOMEM;
			}
			arr[nr] = dt_symtab_addr;
			nr++;
		}
		lm_addr = lm->l_next;
	} while (lm_addr);

	*needed_array = arr;
	return nr;
}
