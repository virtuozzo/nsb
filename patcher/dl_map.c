#include <string.h>

#include "include/dl_map.h"
#include "include/vma.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/elf.h"

struct dl_info {
	struct list_head	*head;
	struct dl_map		*dlm;
};

const struct vma_area *first_dl_vma(const struct dl_map *dlm)
{
	if (list_empty(&dlm->vmas))
		return NULL;

	return list_entry(dlm->vmas.next, typeof(struct vma_area), dl);
}

const struct vma_area *last_dl_vma(const struct dl_map *dlm)
{
	if (list_empty(&dlm->vmas))
		return NULL;

	return list_entry(dlm->vmas.prev, typeof(struct vma_area), dl);
}

static struct dl_map *create_dl_map(const struct vma_area *vma)
{
	struct dl_map *dlm;

	dlm = xmalloc(sizeof(*dlm));
	if (!dlm)
		return NULL;

	dlm->path = vma->path;
	dlm->ei = vma->ei;
	INIT_LIST_HEAD(&dlm->vmas);
	return dlm;
}

static int collect_dl_map(struct vma_area *vma, void *data)
{
	struct dl_info *dl_info = data;
	struct dl_map *dlm = dl_info->dlm;

	if (!vma->ei)
		return 0;

	if (!dlm || strcmp(dlm->path, vma->path)) {
		dlm = create_dl_map(vma);
		if (!dlm)
			return -ENOMEM;

		list_add_tail(&dlm->list, dl_info->head);
		dl_info->dlm = dlm;
	}

	list_add_tail(&vma->dl, &dlm->vmas);
	return 0;
}

int collect_dl_maps(pid_t pid, struct list_head *head)
{
	int err;
	LIST_HEAD(vmas);
	struct dl_info dl_info = {
		.head = head,
	};

	err = collect_vmas(pid, &vmas);
	if (err)
		return err;

	return iterate_file_vmas(&vmas, &dl_info, collect_dl_map);
}

static const struct dl_map *find_dl_map(const struct list_head *head, const void *data,
					int (*actor)(const struct dl_map *dlm, const void *data))
{
	struct dl_map *dlm;

	list_for_each_entry(dlm, head, list) {
		int ret;

		ret = actor(dlm, data);
		if (ret < 0)
			break;
		if (ret)
			return dlm;
	}
	return NULL;
}

static int compare_bid(const struct dl_map *dlm, const void *data)
{
	const char *bid = data;

	return !strcmp(elf_bid(dlm->ei), bid);
}

const struct dl_map *find_dl_map_by_bid(const struct list_head *dl_maps,
					const char *bid)
{
	return find_dl_map(dl_maps, bid, compare_bid);
}

static int compare_addr(const struct dl_map *dlm, const void *data)
{
	unsigned long addr = *(const unsigned long *)data;

	if (addr < vma_start(first_dl_vma(dlm)))
		return 0;
	if (addr > vma_end(last_dl_vma(dlm)))
		return 0;

	return 1;
}

const struct dl_map *find_dl_map_by_addr(const struct list_head *dl_maps,
					 unsigned long addr)
{
	return find_dl_map(dl_maps, &addr, compare_addr);
}

