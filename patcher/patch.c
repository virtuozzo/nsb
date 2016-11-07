#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include "compel/compel/compel.h"
#include "compel/compel/ptrace.h"

#include "include/patch.h"
#include "include/list.h"
#include "include/log.h"
#include "include/xmalloc.h"

#include "protobuf.h"

extern int compel_syscall(struct parasite_ctl *ctl,
			  int nr, unsigned long *ret,
			  unsigned long arg1,
			  unsigned long arg2,
			  unsigned long arg3,
			  unsigned long arg4,
			  unsigned long arg5,
			  unsigned long arg6);

static int collect_mappings(pid_t pid, struct list_head *head)
{
	unsigned long start, end, pgoff;
	char r, w, x, s;

	int dev_maj;
	int dev_min;
	unsigned long ino;

	int ret = -1;

	struct vma_area *vma_area = NULL;
	char buf[1024];
	char path[64];
	FILE *f;

	pr_debug("Collecting mappings for %d\n", pid);

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		int num, path_off;

		if (!vma_area) {
			vma_area = xzalloc(sizeof(*vma_area));
			if (!vma_area)
				goto err;
		}

		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %x:%x %lu %n",
			     &start, &end, &r, &w, &x, &s, &pgoff,
			     &dev_maj, &dev_min, &ino, &path_off);
		if (num < 10) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

		vma_area->start	= start;
		vma_area->end	= end;
		vma_area->pgoff	= pgoff;
		vma_area->prot	= PROT_NONE;

		if (r == 'r')
			vma_area->prot |= PROT_READ;
		if (w == 'w')
			vma_area->prot |= PROT_WRITE;
		if (x == 'x')
			vma_area->prot |= PROT_EXEC;

		if (s == 's')
			vma_area->flags = MAP_SHARED;
		else if (s == 'p')
			vma_area->flags = MAP_PRIVATE;
		else {
			pr_err("Unexpected VMA met (%c)\n", s);
			goto err;
		}

		list_add_tail(&vma_area->list, head);
		pr_debug("VMA: %lx-%lx %c%c%c%c %lx %x:%x %lu\n",
			start, end, r, w, x, s, pgoff,
			dev_maj, dev_min, ino);
		vma_area = NULL;
	}

	ret = 0;

err:
	return ret;
}

unsigned long find_syscall_ip(struct list_head *head)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, head, list) {
		if (vma_area->prot & PROT_EXEC)
			return vma_area->start;
	}

	return 0;
}

static void get_jump_instr(unsigned long old_addr, unsigned long new_addr,
			  unsigned char *data)
{
	unsigned char *instr = &data[0];
	unsigned int *addr = (unsigned int *)&data[1];
	long off;
	int i;

	pr_debug("jump: old address : %#lx\n", old_addr);
	pr_debug("jump: new address : %#lx\n", new_addr);

	/* Relative jump */
	*instr = 0xe9;
	/* 5 bytes is relative jump command size */
	off = new_addr - old_addr - 5;

	pr_debug("jump: offset      : %#lx\n", off);

	*addr = off;

	pr_debug("jump :");
	for (i = 0; i < 5; i++)
		pr_msg(" %02x", data[i]);
	pr_debug("\n");
}

static int apply_patch(pid_t pid, unsigned long addr, const char *patchfile)
{
	FuncPatch *fp;
	int i, err;
	unsigned char jump[8];

	fp = read_funcpatch(patchfile);
	if (!fp)
		return -1;

	pr_debug("patch: name : %s\n", fp->name);
	pr_debug("patch: start: %#x\n", fp->start);
	pr_debug("patch: size : %d\n", fp->size);
	pr_debug("patch: new  : %d\n", fp->new_);
	pr_debug("patch: code :");
	for (i = 0; i < fp->size; i++)
		pr_msg(" %02x", fp->code.data[i]);
	pr_debug("\n");

	err = ptrace_poke_area(pid, fp->code.data, (void *)addr,
				round_up(fp->size, 8));
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	get_jump_instr(fp->start, addr, jump);

	err = ptrace_poke_area(pid, (void *)jump, (void *)(long)fp->start, 8);
	if (err < 0)
		pr_err("failed to patch: %d\n", err);

	func_patch__free_unpacked(fp, NULL);

	return err;
}

int patch_process(pid_t pid, size_t mmap_size, const char *patchfile)
{
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	LIST_HEAD(vma_list_head);
	unsigned long syscall_ip;
	int ret;
	long hint;

	unsigned long sret = -ENOSYS;

	pr_debug("Patching process %d\n", pid);
	pr_debug("====================\n");

	pr_debug("Stopping... %s\n",
		 (ret = compel_stop_task(pid)) ? "FAIL" : "OK");
	if (ret)
		return -1;

	ctl = compel_prepare(pid);
	if (!ctl) {
		pr_err("Can't create compel control\n");
		return -1;
	}

	ictx = compel_infect_ctx(ctl);
	ictx->loglevel = log_get_loglevel();
	ictx->log_fd = log_get_fd();

	if (collect_mappings(pid, &vma_list_head)) {
		pr_err("Can't collect mappings for %d\n", pid);
		return -1;
	}

	syscall_ip = find_syscall_ip(&vma_list_head);
	if (!syscall_ip) {
		pr_err("Can't find suitable vma for syscall %d\n", pid);
		return -1;
	}
	pr_debug("syscall ip at %#lx\n", syscall_ip);
	ictx->syscall_ip = syscall_ip;

	pr_debug("Allocating anon mapping in %d for %zu bytes\n", pid, mmap_size);

	/* TODO: Hint has to be calculated by searching a hole in 4GB page,
	 * where old address (taken from patch) belongs */
	hint = 0x800000;
	ret = compel_syscall(ctl, __NR(mmap, false), &sret,
			     hint, mmap_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", pid);
		return -1;
	}

	if ((long)sret < 0) {
		errno = (int)sret;
		pr_perror("Failed to create mmap with size %zu bytes\n",
			  mmap_size);
		return -1;
	}

	pr_debug("Created anon map %#lx-%#lx in task %d\n",
		 sret, sret + mmap_size, pid);

	/*
	 * - Use ptrace_poke_area to inject jump code into
	 *   patchee, ie
	 *
	 *   int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
	 *    @pid -- address of task we're patching
	 *    @src -- patch body
	 *    @addr -- where to put it in task space
	 *    @bytes -- size of patch, must be 8 byte aligned
	 */

	ret = apply_patch(pid, sret, patchfile);

	/*
	 * Patch itself
	 */
	//ptrace_poke_area(pid, patch_code, patch_address, patch_size);

	pr_debug("Unseize from %d\n", pid);
	if (compel_unseize_task(pid, TASK_ALIVE, TASK_ALIVE)) {
		pr_err("Can't unseize from %d\n", pid);
		return -1;
	}

	return 0;
}
