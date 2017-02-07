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

static int parse_vma(const char *line, struct vma_area *vma, int *path_off)
{
	char r, w, x, s;

	int dev_maj;
	int dev_min;
	unsigned long ino;
	int num;

	num = sscanf(line, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
		     &vma->start, &vma->end, &r, &w, &x, &s, &vma->pgoff,
		     &dev_maj, &dev_min, &ino, path_off);
	if (num != 10) {
		pr_err("Can't parse: %s\n", line);
		return -EINVAL;
	}

	vma->prot = PROT_NONE;
	if (r == 'r')
		vma->prot |= PROT_READ;
	if (w == 'w')
		vma->prot |= PROT_WRITE;
	if (x == 'x')
		vma->prot |= PROT_EXEC;

	if (s == 's')
		vma->flags = MAP_SHARED;
	else if (s == 'p')
		vma->flags = MAP_PRIVATE;
	else {
		pr_err("Unexpected VMA met (%c)\n", s);
		return -EINVAL;
	}

	return 0;
}

int collect_vma_by_path(pid_t pid, struct vma_area *vma, const char *path)
{
	int ret;
	char buf[PATH_MAX];
	FILE *f;

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	f = fopen(buf, "r");
	if (!f) {
		pr_perror("Can't open %s", buf);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		int path_off;

		buf[strlen(buf) - 1] = '\0';

		ret = parse_vma(buf, vma, &path_off);
		if (ret)
			return ret;

		if (!strcmp(buf + path_off, path))
			goto ret;
	}

	ret = -ENOENT;

ret:
	fclose(f);
	return ret;
}

int collect_vmas(pid_t pid, struct list_head *head)
{
	struct vma_area *vma;
	int ret = -1;
	char buf[PATH_MAX];
	char map_file[PATH_MAX];
	FILE *f;

	pr_debug("Collecting mappings for %d\n", pid);

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	f = fopen(buf, "r");
	if (!f) {
		pr_perror("Can't open %s", buf);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		int path_off;

		buf[strlen(buf) - 1] = '\0';

		vma = xzalloc(sizeof(*vma));
		if (!vma)
			goto err;

		ret = parse_vma(buf, vma, &path_off);
		if (ret)
			goto free_vma;

		pr_debug("VMA: %lx-%lx %c%c%c%c %8lx %s\n",
				vma->start, vma->end,
				(vma->prot & PROT_READ) ? 'r' : '-',
				(vma->prot & PROT_WRITE) ? 'w' : '-',
				(vma->prot & PROT_EXEC) ? 'x' : '-',
				(vma->flags == MAP_SHARED) ? 's' : 'p',
				vma->pgoff,
				(strlen(buf) == path_off) ? "" : (buf + path_off));

		if (strlen(buf) == path_off)
			goto add;

		snprintf(map_file, sizeof(buf), "/proc/%d/map_files/%lx-%lx",
				pid, vma->start, vma->end);

		if (access(map_file, F_OK))
			goto add;

		vma->path = xstrdup(buf + path_off);
		if (!vma->path) {
			pr_err("failed to fuplicate string\n");
			goto free_vma;
		}

		vma->map_file = xstrdup(map_file);
		if (!vma->map_file) {
			pr_err("failed to fuplicate string\n");
			goto free_vma_path;
		}

		vma->ei = elf_create_info(vma->map_file);
		if (!vma->ei)
			goto free_map_file;

add:
		list_add_tail(&vma->list, head);
	}

	ret = 0;

err:
	fclose(f);
	return ret;

free_map_file:
	free(vma->map_file);
free_vma_path:
	free(vma->path);
free_vma:
	free(vma);
	goto err;
}

const struct vma_area *find_vma_by_addr(const struct list_head *vmas,
					unsigned long addr)
{
	const struct vma_area *vma;

	list_for_each_entry(vma, vmas, list) {
		if (addr < vma->start)
			continue;
		if (addr > vma->end)
			continue;
		return vma;
	}
	return NULL;

}

const struct vma_area *find_vma_by_prot(const struct list_head *head, int prot)
{
	const struct vma_area *vma;

	list_for_each_entry(vma, head, list) {
		if (vma->prot & prot)
			return vma;
	}
	return NULL;
}

const struct vma_area *find_vma_by_path(const struct list_head *head,
					const char *path)
{
	const struct vma_area *vma;

	list_for_each_entry(vma, head, list) {
		if (!vma->path)
			continue;
		if (!strcmp(vma->path, path))
			return vma;
	}
	return NULL;
}

unsigned long find_vma_hole(const struct list_head *vmas,
			    unsigned long hint, size_t size)
{
	const struct vma_area *vma, *next_vma;

	list_for_each_entry(vma, vmas, list) {
		next_vma = list_entry(vma->list.next, typeof(*vma), list);
		if (next_vma->start - vma->end > size)
			return vma->end;
	}
	return 0;
}

const struct vma_area *find_vma_by_bid(const struct list_head *head, const char *bid)
{
	const struct vma_area *vma;
	char *vma_bid = NULL;

	list_for_each_entry(vma, head, list) {
		if (!vma->path)
			continue;

		vma_bid = elf_build_id(vma->path);
		if (!vma_bid)
			continue;

		if (!strcmp(bid, vma_bid)) {
			free(vma_bid);
			return vma;
		}
		free(vma_bid);
	}
	return NULL;
}

int iterate_file_vmas(struct list_head *head, void *data,
		int (*actor)(struct vma_area *vma, void *data))
{
	struct vma_area *vma;
	int err = 0;

	list_for_each_entry(vma, head, list) {
		if (!vma->path)
			continue;

		err = actor(vma, data);
		if (err)
			break;
	}
	return err;
}

struct vma_area *find_vma(const struct list_head *head, void *data,
			  int (*actor)(const struct vma_area *vma, void *data))
{
	struct vma_area *vma;

	list_for_each_entry(vma, head, list) {
		int ret;

		if (!vma->path)
			continue;

		ret = actor(vma, data);
		if (ret < 0)
			break;
		if (ret)
			return vma;
	}
	return NULL;
}

const char *vma_soname(const struct vma_area *vma)
{
	return elf_get_soname(vma->ei);
}
