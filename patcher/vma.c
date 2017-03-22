#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>

#include "include/vma.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/elf.h"

uint64_t vma_func_addr(const struct vma_area *vma, uint64_t addr)
{
        if (elf_type_dyn(vma->ei))
		addr += vma_start(vma);
	return addr;
}

static int parse_vma(char *line, struct vma_area *vma)
{
	char r, w, x, s;

	uint32_t dev_maj;
	uint32_t dev_min;
	uint64_t ino;
	uint32_t path_off;
	int num;
	struct mmap_info_s *mmi = &vma->mmi;
	int64_t end;

	memset(vma, 0, sizeof(*vma));

	num = sscanf(line, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
		     &mmi->addr, &end, &r, &w, &x, &s, &mmi->offset,
		     &dev_maj, &dev_min, &ino, &path_off);
	if (num != 10) {
		pr_err("Can't parse: %s\n", line);
		return -EINVAL;
	}

	mmi->length = end - mmi->addr;
	mmi->prot = PROT_NONE;
	if (r == 'r')
		mmi->prot |= PROT_READ;
	if (w == 'w')
		mmi->prot |= PROT_WRITE;
	if (x == 'x')
		mmi->prot |= PROT_EXEC;

	if (s == 's')
		mmi->flags = MAP_SHARED;
	else if (s == 'p')
		mmi->flags = MAP_PRIVATE;
	else {
		pr_err("Unexpected VMA met (%c)\n", s);
		return -EINVAL;
	}

	if (path_off != strlen(line))
		vma->path = line + path_off;

	return 0;
}

static inline struct vma_area *mmi_vma(struct mmap_info_s *mmi)
{
	return container_of(mmi, struct vma_area, mmi);
}

void free_vma(struct vma_area *vma)
{
	if (vma->ei)
		elf_destroy_info(vma->ei);
	free(vma->path);
	free(vma->map_file);
	free(vma);
}

static int create_vma(pid_t pid, const struct vma_area *template,
		      struct vma_area **vma_area)
{
	struct vma_area *vma;
	char map_file[PATH_MAX];
	int ret = -ENOMEM;

	vma = xmemdup(template, sizeof(*vma));
	if (!vma)
		return -ENOMEM;

	if (template->path) {
		vma->path = xstrdup(template->path);
		if (!vma->path) {
			pr_err("failed to fuplicate string\n");
			goto free_vma;
		}
	}

	snprintf(map_file, sizeof(map_file), "/proc/%d/map_files/%lx-%lx",
			pid, vma_start(vma), vma_end(vma));

	if (!access(map_file, F_OK)) {
		vma->map_file = xstrdup(map_file);
		if (!vma->map_file) {
			pr_err("failed to fuplicate string\n");
			goto free_vma_path;
		}

		if (is_elf_file(vma->map_file)) {
			ret = elf_create_info(vma->map_file, &vma->ei);
			if (ret)
				goto free_map_file;
		}
	}

	*vma_area = vma;

	return 0;

free_map_file:
	free(vma->map_file);
free_vma_path:
	free(vma->path);
free_vma:
	free(vma);
	return ret;
}

static int collect_vma(pid_t pid, struct list_head *head, const struct vma_area *template)
{
	struct vma_area *vma;
	int err;

	err = create_vma(pid, template, &vma);
	if (err)
		return err;

	list_add_tail(&vma->mmi.list, head);
	return 0;
}

static int iter_map_files(pid_t pid,
			  int (*actor)(pid_t pid, const struct vma_area *vma,
				       void *data),
			  void *data)
{
	struct vma_area tmp;
	int ret = -1;
	char buf[PATH_MAX];
	FILE *f;

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	f = fopen(buf, "r");
	if (!f) {
		pr_perror("Can't open %s", buf);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		buf[strlen(buf) - 1] = '\0';

		ret = parse_vma(buf, &tmp);
		if (ret)
			goto err;

		ret = actor(pid, &tmp, data);
		if (ret)
			goto err;
	}

err:
	fclose(f);
	return ret;
}

struct vma_collect {
	struct list_head	*head;
	const void		*data;
	struct vma_area		**vma;
};

static int __collect_vmas(pid_t pid, struct list_head *head,
			  int (*actor)(pid_t pid, const struct vma_area *vma,
				       void *data),
			  const void *data)
{
	struct vma_collect vmc = {
		.head = head,
		.data = data,
	};

	return iter_map_files(pid, actor, &vmc);
}

static int collect_one_vma(pid_t pid, const struct vma_area *vma, void *data)
{
	struct vma_collect *vmc = data;

	pr_debug("  VMA: %lx-%lx %c%c%c%c %8lx %s\n",
			vma_start(vma), vma_end(vma),
			(vma_prot(vma) & PROT_READ) ? 'r' : '-',
			(vma_prot(vma) & PROT_WRITE) ? 'w' : '-',
			(vma_prot(vma) & PROT_EXEC) ? 'x' : '-',
			(vma_flags(vma) == MAP_SHARED) ? 's' : 'p',
			vma_offset(vma),
			(vma->path) ? vma->path : "");

	return collect_vma(pid, vmc->head, vma);
}

int collect_vmas(pid_t pid, struct list_head *head)
{
	pr_debug("= Collecting mappings for %d\n", pid);

	return __collect_vmas(pid, head, collect_one_vma, NULL);
}

static int compare_vma_path(pid_t pid, const struct vma_area *vma, void *data)
{
	struct vma_collect *vmc = data;
	const char *path = vmc->data;

	if (!vma->path)
		return 0;

	if (strcmp(vma->path, path))
		return 0;

	return collect_vma(pid, vmc->head, vma);
}

int collect_vmas_by_path(pid_t pid, struct list_head *head, const char *path)
{
	return __collect_vmas(pid, head, compare_vma_path, path);
}

static int compare_vma_bid(pid_t pid, const struct vma_area *vma, void *data)
{
	struct vma_collect *vmc = data;
	const char *bid = vmc->data;
	struct vma_area *vma_area;
	int err;

	if (!vma->path)
		return 0;

	err = create_vma(pid, vma, &vma_area);
	if (err)
		return err;

	if (!vma_area->ei)
		goto free_vma;

	if (!elf_bid(vma_area->ei))
		goto free_vma;

	if (strcmp(elf_bid(vma_area->ei), bid))
		goto free_vma;

	if (vmc->head) {
		list_add_tail(&vma_area->mmi.list, vmc->head);
		return 0;
	}

	*vmc->vma = vma_area;
	return 1;

free_vma:
	free_vma(vma_area);
	return 0;
}

int create_vma_by_bid(pid_t pid, const char *bid, struct vma_area **vma)
{
	struct vma_collect vmc = {
		.data = bid,
		.vma = vma,
	};
	int ret;

	ret = iter_map_files(pid, compare_vma_bid, &vmc);
	if (ret < 0)
		return ret;
	return ret ? 0 : -ENOENT;
}

static const struct vma_area *find_vma(const struct list_head *head, const void *data,
				       int (*actor)(const struct vma_area *vma, const void *data))
{
	struct mmap_info_s *mmi;

	list_for_each_entry(mmi, head, list) {
		struct vma_area *vma = mmi_vma(mmi);
		int ret;

		ret = actor(vma, data);
		if (ret < 0)
			break;
		if (ret)
			return vma;
	}
	return NULL;
}

struct address_hole {
	uint64_t	hint;
	size_t		size;
};

static int find_hole(const struct vma_area *vma, const void *data)
{
	const struct address_hole *hole = data;
	struct mmap_info_s *next_mmi;
	const struct vma_area *next_vma;

	next_mmi = list_entry(vma->mmi.list.next, typeof(*next_mmi), list);
	next_vma = mmi_vma(next_mmi);

	if (vma_start(next_vma) < hole->hint)
		return 0;

	return vma_start(next_vma) - max(hole->hint, vma_end(vma)) > hole->size;
}

int64_t find_vma_hole(const struct list_head *vmas,
		      uint64_t hint, size_t size)
{
	const struct vma_area *vma;
	struct address_hole hole = {
		.hint = hint,
		.size = size,
	};

	vma = find_vma(vmas, &hole, find_hole);

	return vma ? max(hole.hint, vma_end(vma)) : -ENOENT;
}

int iterate_file_vmas(const struct list_head *head, void *data,
		      int (*actor)(struct vma_area *vma, void *data))
{
	struct mmap_info_s *mmi;
	int err = 0;

	list_for_each_entry(mmi, head, list) {
		struct vma_area *vma = mmi_vma(mmi);

		if (!vma->path)
			continue;

		err = actor(vma, data);
		if (err)
			break;
	}
	return err;
}

const struct vma_area *first_vma(const struct list_head *vmas)
{
	if (list_empty(vmas))
		return NULL;

	return mmi_vma(list_entry(vmas->next, typeof(struct mmap_info_s), list));
}

const struct vma_area *last_vma(const struct list_head *vmas)
{
	if (list_empty(vmas))
		return NULL;

	return mmi_vma(list_entry(vmas->prev, typeof(struct mmap_info_s), list));
}
