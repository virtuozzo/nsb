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
		addr += vma->start;
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

	memset(vma, 0, sizeof(*vma));

	num = sscanf(line, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
		     &vma->start, &vma->end, &r, &w, &x, &s, &vma->pgoff,
		     &dev_maj, &dev_min, &ino, &path_off);
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

	if (path_off != strlen(line))
		vma->path = line + path_off;

	return 0;
}

static int collect_vma(pid_t pid, struct list_head *head, const struct vma_area *template)
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
			pid, vma->start, vma->end);

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

	list_add_tail(&vma->list, head);

	return 0;

free_map_file:
	free(vma->map_file);
free_vma_path:
	free(vma->path);
free_vma:
	free(vma);
	return ret;
}

int collect_vmas(pid_t pid, struct list_head *head)
{
	struct vma_area tmp;
	int ret = -1;
	char buf[PATH_MAX];
	FILE *f;

	pr_debug("= Collecting mappings for %d\n", pid);

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

		pr_debug("  VMA: %lx-%lx %c%c%c%c %8lx %s\n",
				tmp.start, tmp.end,
				(tmp.prot & PROT_READ) ? 'r' : '-',
				(tmp.prot & PROT_WRITE) ? 'w' : '-',
				(tmp.prot & PROT_EXEC) ? 'x' : '-',
				(tmp.flags == MAP_SHARED) ? 's' : 'p',
				tmp.pgoff,
				(tmp.path) ? tmp.path : "");

		ret = collect_vma(pid, head, &tmp);
		if (ret)
			goto err;
	}

err:
	fclose(f);
	return ret;
}

const struct vma_area *find_vma(const struct list_head *head, const void *data,
			  int (*actor)(const struct vma_area *vma, const void *data))
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

static int compare_addr(const struct vma_area *vma, const void *data)
{
	unsigned long addr = *(const unsigned long *)data;

	if (addr < vma->start)
		return 0;
	if (addr > vma->end)
		return 0;

	return 1;
}

const struct vma_area *find_vma_by_addr(const struct list_head *vmas,
					unsigned long addr)
{
	return find_vma(vmas, &addr, compare_addr);
}

static int compare_prot(const struct vma_area *vma, const void *data)
{
	int prot = *(const int *)data;

	return vma->prot & prot;
}

const struct vma_area *find_vma_by_prot(const struct list_head *vmas, int prot)
{
	return find_vma(vmas, &prot, compare_prot);
}

static int compare_path(const struct vma_area *vma, const void *data)
{
	const char *path = data;

	if (!vma->path)
		return 0;
	return !strcmp(vma->path, path);
}

const struct vma_area *find_vma_by_path(const struct list_head *vmas,
					const char *path)
{
	return find_vma(vmas, path, compare_path);
}

static int find_hole(const struct vma_area *vma, const void *data)
{
	size_t size = *(const size_t *)data;
	const struct vma_area *next_vma;

	next_vma = list_entry(vma->list.next, typeof(*vma), list);
	return next_vma->start - vma->end > size;
}

unsigned long find_vma_hole(const struct list_head *vmas,
			    unsigned long hint, size_t size)
{
	const struct vma_area *vma;

	vma = find_vma(vmas, &size, find_hole);

	return vma ? vma->end : 0;
}

static const char *vma_elf_bid(const struct vma_area *vma)
{
	if (vma->ei)
		return elf_bid(vma->ei);
	return NULL;
}


static int compare_bid(const struct vma_area *vma, const void *data)
{
	const char *bid = data;
	const char *vma_bid;

	vma_bid = vma_elf_bid(vma);

	if (!vma_bid)
		return 0;

	return !strcmp(vma_bid, bid);
}

const struct vma_area *find_vma_by_bid(const struct list_head *vmas, const char *bid)
{
	return find_vma(vmas, bid, compare_bid);
}

static int compare_stat(const struct vma_area *vma, const void *data)
{
	const struct stat *st = data;
	struct stat vma_st;

	if (!vma->map_file)
		return 0;

	if (stat(vma->map_file, &vma_st)) {
		pr_perror("failed to stat %s", vma->map_file);
		return -errno;
	}

	return  (vma_st.st_dev == st->st_dev) &&
		(vma_st.st_ino == st->st_ino);
}

const struct vma_area *find_vma_by_stat(const struct list_head *vmas,
					const struct stat *st)
{
	return find_vma(vmas, st, compare_stat);
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

const char *vma_soname(const struct vma_area *vma)
{
	if (vma->ei)
		return elf_get_soname(vma->ei);
	return NULL;
}

static int compare_soname(const struct vma_area *vma, const void *data)
{
	const char *soname = data;

	if (!vma_soname(vma))
		return 0;

	return !strcmp(vma_soname(vma), soname);
}

const struct vma_area *find_vma_by_soname(const struct list_head *vmas, const char *soname)
{
	return find_vma(vmas, soname, compare_soname);
}

int vma_is_executable(const struct vma_area *vma)
{
	return vma->prot & PROT_EXEC;
}
