/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_VMA_H__
#define __PATCHER_VMA_H__

#include <stdint.h>
#include <stdlib.h>
#include "list.h"

struct vma_area {
	struct list_head        list;

	uint64_t                addr;
	size_t                  length;
	int                     flags;
	int                     prot;
	off_t                   offset;

	char			*path;
	char			*map_file;

	struct list_head        dl;
	const void		*dlm;
};

static inline size_t vma_length(const struct vma_area *vma)
{
	return vma->length;
}

static inline uint64_t vma_start(const struct vma_area *vma)
{
	return vma->addr;
}

static inline uint64_t vma_end(const struct vma_area *vma)
{
	return vma->addr + vma->length;
}

static inline int vma_prot(const struct vma_area *vma)
{
	return vma->prot;
}

static inline int vma_flags(const struct vma_area *vma)
{
	return vma->flags;
}

static inline off_t vma_offset(const struct vma_area *vma)
{
	return vma->offset;
}

void free_vma(struct vma_area *vma);
void free_vmas(struct list_head *head);
int collect_vmas(pid_t pid, struct list_head *head);
int collect_vmas_by_path(pid_t pid, struct list_head *head, const char *path);
int add_vma_sorted(struct list_head *head, struct vma_area *vma);

int iterate_vmas(const struct list_head *head, void *data,
		 int (*actor)(struct vma_area *vma, void *data));

uint64_t vma_func_addr(const struct vma_area *vma, uint64_t addr);

const struct vma_area *first_vma(const struct list_head *vmas);
const struct vma_area *last_vma(const struct list_head *vmas);
const struct vma_area *next_vma(const struct vma_area *vma);

int iter_map_files(pid_t pid,
		   int (*actor)(pid_t pid, const struct vma_area *vma,
				void *data),
		   void *data);

int splice_vma_lists_sorted(struct list_head *from, struct list_head *to);

void print_vma(const struct vma_area *vma);

#endif /* __PATCHER_VMA_H__ */
