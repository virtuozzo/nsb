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
	struct list_head        dl;
	const void		*dlm;
};

static inline size_t vma_length(const struct vma_area *vma)
{
	return vma->mmi.length;
}

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

void free_vma(struct vma_area *vma);
void free_vmas(struct list_head *head);
int collect_vmas(pid_t pid, struct list_head *head);
int collect_vmas_by_path(pid_t pid, struct list_head *head, const char *path);

void free_vma(struct vma_area *vma);
int create_vma_by_bid(pid_t pid, const char *bid, struct vma_area **vma);

int iterate_vmas(const struct list_head *head, void *data,
		 int (*actor)(struct vma_area *vma, void *data));

uint64_t vma_func_addr(const struct vma_area *vma, uint64_t addr);

const struct vma_area *first_vma(const struct list_head *vmas);
const struct vma_area *last_vma(const struct list_head *vmas);
const struct vma_area *next_vma(const struct vma_area *vma);

#endif /* __PATCHER_VMA_H__ */
