#ifndef __PATCHER_VMA_H__
#define __PATCHER_VMA_H__

#include <stdint.h>
#include <stdlib.h>
#include "list.h"

struct vma_area {
	struct list_head	list;

	uint64_t		start;
	uint64_t		end;
	uint64_t		pgoff;
	uint32_t		prot;
	uint32_t		flags;
	char			*path;
	int			deleted;
	char			*map_file;
	struct elf_info_s	*ei;
};

int collect_vmas(pid_t pid, struct list_head *head);

const struct vma_area *find_vma_by_addr(const struct list_head *vmas,
					unsigned long addr);
const struct vma_area *find_vma_by_prot(const struct list_head *head, int prot);
const struct vma_area *find_vma_by_path(const struct list_head *head,
					const char *path);
const struct vma_area *find_vma_by_bid(const struct list_head *head, const char *bid);
const struct vma_area *find_vma(const struct list_head *head, const void *data,
			  int (*actor)(const struct vma_area *vma, const void *data));
const struct vma_area *find_vma_by_soname(const struct list_head *vmas,
					  const char *soname);

unsigned long find_vma_hole(const struct list_head *vmas,
			    unsigned long hint, size_t size);

int iterate_file_vmas(struct list_head *head, void *data,
		      int (*actor)(struct vma_area *vma, void *data));

const char *vma_soname(const struct vma_area *vma);

int vma_is_executable(const struct vma_area *vma);

#endif /* __PATCHER_VMA_H__ */
