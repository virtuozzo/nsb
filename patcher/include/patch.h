#ifndef NSB_PATCH_H__
#define NSB_PATCH_H__

#include <stdint.h>
#include <unistd.h>

#include "list.h"

struct vma_area {
	struct list_head	list;

	uint64_t		start;
	uint64_t		end;
	uint64_t		pgoff;
	uint32_t		prot;
	uint32_t		flags;
};

int patch_process(pid_t pid, size_t mmap_size, const char *patchfile);

#endif /* NSB_PATCH_H__ */
