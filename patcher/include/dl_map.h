#ifndef __PATCHER_DL_MAP_H__
#define __PATCHER_DL_MAP_H__

#include <unistd.h>

#include "list.h"

struct dl_map {
	struct list_head	list;
	const char		*path;
	struct list_head	vmas;
	struct elf_info_s	*ei;
};

const struct vma_area *first_dl_vma(const struct dl_map *dlm);
const struct vma_area *last_dl_vma(const struct dl_map *dlm);

int collect_dl_maps(pid_t pid, struct list_head *head);

const struct dl_map *find_dl_map_by_bid(const struct list_head *dl_maps,
					const char *bid);
const struct dl_map *find_dl_map_by_addr(const struct list_head *dl_maps,
					 unsigned long addr);

#endif /* __PATCHER_DL_MAP_H__ */
