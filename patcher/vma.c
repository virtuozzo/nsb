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

void print_vmas(pid_t pid, struct list_head *head)
{
	struct vma_area *vma;

	pr_debug("Process %d mappings:\n", pid);

	list_for_each_entry(vma, head, list) {
		pr_debug("VMA: %lx-%lx %c%c%c%c %lx %s\n",
				vma->start, vma->end,
				(vma->prot & PROT_READ) ? 'r' : '-',
				(vma->prot & PROT_WRITE) ? 'w' : '-',
				(vma->prot & PROT_EXEC) ? 'x' : '-',
				(vma->flags == MAP_SHARED) ? 's' : 'p',
				vma->pgoff, vma->path);
	}
}

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

		vma->path = xstrdup(buf + path_off);
		if (!vma->path) {
			pr_err("failed to fuplicate string\n");
			goto free_vma;
		}

		list_add_tail(&vma->list, head);
	}

	ret = 0;

err:
	fclose(f);
	return ret;

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

const struct vma_area *find_vma_by_prot(struct list_head *head, int prot)
{
	const struct vma_area *vma;

	list_for_each_entry(vma, head, list) {
		if (vma->prot & prot)
			return vma;
	}
	return NULL;
}

const struct vma_area *find_vma_by_path(struct list_head *head,
					const char *path)
{
	const struct vma_area *vma;

	list_for_each_entry(vma, head, list) {
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

