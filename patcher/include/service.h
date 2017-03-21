#ifndef __PATCHER_SERVICE_H__
#define __PATCHER_SERVICE_H__

#include <stdbool.h>

#include "list.h"

struct vma_area;

struct service {
	const char		*name;
	pid_t			pid;
	uint64_t		handle;
	const struct vma_area	*first_vma;
	int			sock;
	uint64_t		runner;
	bool			loaded;
	bool			released;
};

struct process_ctx_s;
int service_start(struct process_ctx_s *ctx, struct service *plugin);
int service_stop(struct process_ctx_s *ctx, struct service *plugin);

struct list_head;
int service_mmap_file(struct process_ctx_s *ctx, const struct service *service,
		      const char *path, const struct list_head *mmaps);
int service_munmap(struct process_ctx_s *ctx, const struct service *service,
		   const struct list_head *mmaps);

ssize_t service_needed_array(struct process_ctx_s *ctx, const struct service *service,
			     uint64_t **needed_array);

#endif
