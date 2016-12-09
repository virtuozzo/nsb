#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <linux/elf.h>

#include "include/elf.h"
#include "include/process.h"
#include "include/log.h"

#include <protobuf/segment.pb-c.h>

#define ELF_MIN_ALIGN		PAGE_SIZE

#define TASK_SIZE		((1UL << 47) - PAGE_SIZE)
#define ELF_ET_DYN_BASE		(TASK_SIZE / 3 * 2)

#define ELF_PAGESTART(_v)	((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v)	((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v)	(((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

static int64_t elf_map(struct process_ctx_s *ctx, int fd, uint64_t addr, ElfSegment *es, int flags)
{
	unsigned long size = es->file_sz + ELF_PAGEOFFSET(es->vaddr);
	unsigned long off = es->offset - ELF_PAGEOFFSET(es->vaddr);
	int prot = 0;

	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

	if (!size)
		return addr;

	if (es->flags & PF_R)
		prot = PROT_READ;
	if (es->flags & PF_W)
		prot |= PROT_WRITE;
	if (es->flags & PF_X)
		prot |= PROT_EXEC;
	pr_debug("mmap on addr %#lx, prot: %#x, flags: %#x, off: %#lx, size: %#lx\n", addr, prot, flags, off, size);
	return process_create_map(ctx, fd, off, addr, size, flags, prot);
}

int64_t load_elf_segments(struct process_ctx_s *ctx, const BinPatch *bp, uint64_t hint)
{
	int i, fd;
	int load_addr_set = 0;
	uint64_t load_bias = 0;

	fd = open(bp->new_path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s for read", bp->new_path);
		return -1;
	}

	fd = process_open_file(ctx, bp->new_path, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	pr_debug("Opened %s as fd %d\n", bp->new_path, fd);
	for (i = 0; i < bp->n_new_segments; i++) {
		ElfSegment *es = bp->new_segments[i];
		int flags = MAP_PRIVATE;
		int64_t addr;

		if (strcmp(es->type, "PT_LOAD"))
			continue;

		pr_debug("  %s: offset: %#x, vaddr: %#x, paddr: %#x, mem_sz: %#x, flags: %#x, align: %#x, file_sz: %#x\n",
			 es->type, es->offset, es->vaddr, es->paddr, es->mem_sz, es->flags, es->align, es->file_sz);

		if (!load_addr_set) {
			if (hint)
				// TODO: there should be bigger offset. 2 or maybe even 4 GB.
				// But jmpq command construction fails, if map lays ouside 2g offset.
				// This might be a bug in jmps construction
				load_bias = hint & 0xfffffffff0000000;
			else
				load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - es->vaddr);
		} else
			flags |= MAP_FIXED;

	//	pr_debug("load_bias: %#lx\n", load_bias);
	//	pr_debug("load_bias + vaddr: %#lx\n", load_bias + es->vaddr);

		addr = elf_map(ctx, fd, load_bias + es->vaddr, es, flags);
		if (addr == -1) {
			pr_perror("failed to map");
			load_bias = -1;
			break;
		}

		pr_debug("map_addr: %#lx\n", addr);

		if (!load_addr_set) {
			load_addr_set = 1;
			load_bias += addr - ELF_PAGESTART(load_bias + es->vaddr);
			pr_debug("load_bias: %#lx\n", load_bias);
		}
	}

	(void)process_close_file(ctx, fd);

	return load_bias;
}
