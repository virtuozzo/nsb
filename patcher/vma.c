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

static int create_vma(pid_t pid, const struct vma_area *template,
		      struct vma_area **vma_area)
{
	struct vma_area *vma;
	char map_file[PATH_MAX];
	int ret = -ENOMEM;

	vma = xmemdup(template, sizeof(*vma));
	if (!vma)
		return -ENOMEM;
	vma->dlm = NULL;

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
	}

	*vma_area = vma;

	return 0;

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

int iter_map_files(pid_t pid,
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

int iterate_vmas(const struct list_head *head, void *data,
		 int (*actor)(struct vma_area *vma, void *data))
{
	struct mmap_info_s *mmi;
	int err = 0;

	list_for_each_entry(mmi, head, list) {
		struct vma_area *vma = mmi_vma(mmi);

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

const struct vma_area *next_vma(const struct vma_area *vma)
{
	return mmi_vma(list_entry(vma->mmi.list.next, typeof(struct mmap_info_s), list));
}
