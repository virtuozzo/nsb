#ifndef __PATCHER_DL_MAP_H__
#define __PATCHER_DL_MAP_H__

#include <unistd.h>
#include <stdint.h>

#include "list.h"

struct dl_map {
	struct list_head	list;
	const char		*path;
	struct list_head	vmas;
	struct elf_info_s	*ei;
};

const struct vma_area *first_dl_vma(const struct dl_map *dlm);
const struct vma_area *last_dl_vma(const struct dl_map *dlm);

int collect_dl_maps(const struct list_head *vmas, struct list_head *head);
int create_dl_map(const struct list_head *vmas, struct dl_map **dl_map);

const struct dl_map *find_dl_map_by_bid(const struct list_head *dl_maps,
					const char *bid);
const struct dl_map *find_dl_map_by_addr(const struct list_head *dl_maps,
					 unsigned long addr);

int64_t dl_get_symbol_value(const struct list_head *dl_maps, const char *name);
int64_t dl_map_symbol_value(const struct dl_map *dlm, const char *name);

uint64_t dl_map_start(const struct dl_map *dlm);
uint64_t dl_map_end(const struct dl_map *dlm);

uint64_t dlm_load_base(const struct dl_map *dlm);

struct dl_map *alloc_dl_map(struct elf_info_s *ei, const char *path);

int iterate_dl_vmas(const struct dl_map *dlm, void *data,
		    int (*actor)(struct vma_area *vma, void *data));

#endif /* __PATCHER_DL_MAP_H__ */
