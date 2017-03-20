#ifndef __PATCHER_VMA_H__
#define __PATCHER_VMA_H__

#include <stdint.h>
#include <stdlib.h>
#include "list.h"

struct mmap_info_s {
	struct list_head        list;
	uint64_t                addr;
	size_t                  length;
	int                     flags;
	int                     prot;
	off_t                   offset;
};

struct vma_area {
	struct mmap_info_s	mmi;
	char			*path;
	char			*map_file;
	struct elf_info_s	*ei;
};

static inline uint64_t vma_start(const struct vma_area *vma)
{
	return vma->mmi.addr;
}

static inline uint64_t vma_end(const struct vma_area *vma)
{
	return vma->mmi.addr + vma->mmi.length;
}

static inline int vma_prot(const struct vma_area *vma)
{
	return vma->mmi.prot;
}

static inline int vma_flags(const struct vma_area *vma)
{
	return vma->mmi.flags;
}

static inline off_t vma_offset(const struct vma_area *vma)
{
	return vma->mmi.offset;
}

int collect_vmas(pid_t pid, struct list_head *head);
int collect_vmas_by_path(pid_t pid, struct list_head *head, const char *path);

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
struct stat;
const struct vma_area *find_vma_by_stat(const struct list_head *vmas,
					const struct stat *st);

unsigned long find_vma_hole(const struct list_head *vmas,
			    unsigned long hint, size_t size);

int iterate_file_vmas(struct list_head *head, void *data,
		      int (*actor)(struct vma_area *vma, void *data));

const char *vma_soname(const struct vma_area *vma);

uint64_t vma_func_addr(const struct vma_area *vma, uint64_t addr);

int64_t vma_get_symbol_value(struct list_head *vmas, const char *name);

const struct vma_area *first_vma(const struct list_head *vmas);

#endif /* __PATCHER_VMA_H__ */
