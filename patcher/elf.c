#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdio.h>
#include <gelf.h>

#include "include/elf.h"
#include "include/process.h"
#include "include/log.h"
#include "include/xmalloc.h"

#include <protobuf/segment.pb-c.h>

#define ELF_MIN_ALIGN		PAGE_SIZE

#define TASK_SIZE		((1UL << 47) - PAGE_SIZE)
#define ELF_ET_DYN_BASE		(TASK_SIZE / 3 * 2)

#define ELF_PAGESTART(_v)	((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v)	((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v)	(((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

struct elf_info_s {
	char			*path;
	Elf			*e;
	size_t			shstrndx;
};

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

int64_t load_elf(struct process_ctx_s *ctx, const BinPatch *bp, uint64_t hint)
{
	int i, fd;
	// TODO: there should be bigger offset. 2 or maybe even 4 GB.
	// But jmpq command construction fails, if map lays ouside 2g offset.
	// This might be a bug in jmps construction
	uint64_t load_bias = hint & 0xfffffffff0000000;
	int flags = MAP_PRIVATE;

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
		int64_t addr;

		if (strcmp(es->type, "PT_LOAD"))
			continue;

		pr_debug("  %s: offset: %#x, vaddr: %#x, paddr: %#x, mem_sz: %#x, flags: %#x, align: %#x, file_sz: %#x\n",
			 es->type, es->offset, es->vaddr, es->paddr, es->mem_sz, es->flags, es->align, es->file_sz);

		addr = elf_map(ctx, fd, load_bias + es->vaddr, es, flags);
		if (addr == -1) {
			pr_perror("failed to map");
			load_bias = -1;
			break;
		}

		load_bias += addr - ELF_PAGESTART(load_bias + es->vaddr);
		flags |= MAP_FIXED;
	}

	(void)process_close_file(ctx, fd);

	return load_bias;
}

static Elf *elf_open(const char *path)
{
	int fd;
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_err("ELF library initialization failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", path);
		return NULL;
	}

	e = elf_begin(fd, ELF_C_READ, NULL );
	if (!e)
		goto close_fd;

	if (elf_kind(e) != ELF_K_ELF) {
		pr_info("%s if not and regular ELF file\n", path);
		goto end_elf;
	}

	return e;

close_fd:
	close(fd);
	return NULL;

end_elf:
	(void)elf_end(e);
	return NULL;
}

static struct elf_info_s *elf_alloc_info(Elf *e, const char *path)
{
	struct elf_info_s *ei;

	ei = xzalloc(sizeof(*ei));
	if (!ei)
		return NULL;

	ei->path = strdup(path);
	if (!ei->path)
		goto free_ei;

	if (elf_getshdrstrndx(e, &ei->shstrndx)) {
		pr_err("failed to get section string index: %s\n", elf_errmsg(-1));
		goto free_ei_path;
	}

	ei->e = e;

	return ei;

free_ei_path:
	free(ei->path);
free_ei:
	free(ei);
	return NULL;
}

void elf_destroy_info(struct elf_info_s *ei)
{
	(void)elf_end(ei->e);
	free(ei);
}

struct elf_info_s *elf_create_info(const char *path)
{
	Elf *e;
	struct elf_info_s *ei;

	e = elf_open(path);
	if (!e) {
		pr_err("failed to parse ELF %s: %s\n", path, elf_errmsg(-1));
		return NULL;
	}

	ei = elf_alloc_info(e, path);
	if (!ei)
		goto end_elf;

	return ei;

end_elf:
	(void)elf_end(e);
	return NULL;
}

static char *get_section_name(struct elf_info_s *ei, Elf_Scn *scn)
{
	GElf_Shdr shdr;
	char *sname;

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		pr_err("getshdr() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	sname = elf_strptr(ei->e, ei->shstrndx, shdr.sh_name);
	if (!sname)
		pr_err("elf_strptr() failed: %s\n", elf_errmsg(-1));

	return sname;
}

static Elf_Scn *elf_get_section(struct elf_info_s *ei, const char *name)
{
	Elf_Scn *scn = NULL;

	while((scn = elf_nextscn(ei->e, scn)) != NULL) {
		char *sname;

		sname = get_section_name(ei, scn);
		if (!sname)
			break;

		if (!strcmp(sname, name))
			return scn;
	}

	return NULL;
}

static char *get_build_id(Elf_Scn *bid_scn)
{
	Elf_Data *data;
	GElf_Nhdr nhdr;
	size_t size, noff, doff, i;
	char *bid, *b, *d;

	data = elf_getdata(bid_scn, NULL);
	if (!data) {
		pr_err(".note.gnu.build-id section doesn't have data\n");
		return NULL;
	}

	size = gelf_getnote(data, 0, &nhdr, &noff, &doff);
	if (!size) {
		pr_err("failed to parse .note.gnu.build-id header\n");
		return NULL;
	}

	bid = xmalloc(nhdr.n_descsz * 2 + 1);
	if (!bid)
		return NULL;
	bid[nhdr.n_descsz * 2] = '\0';

	for (i = 0, d = data->d_buf + doff, b = bid; i < nhdr.n_descsz; i++, b += 2)
		sprintf(b, "%02x", *d++ & 0xff);

	return bid;
}

static char *elf_get_bid(struct elf_info_s *ei)
{
	Elf_Scn *bid_scn;

	bid_scn = elf_get_section(ei, ".note.gnu.build-id");
	if (!bid_scn) {
		pr_err("failed to find \".note.gnu.build-id\" section in %s\n", ei->path);
		return NULL;
	}
	return get_build_id(bid_scn);
}

char *elf_build_id(const char *path)
{
	struct elf_info_s *ei;
	char *bid = NULL;

	if (access(path, R_OK))
		return NULL;

	ei = elf_create_info(path);
	if (ei) {
		bid = elf_get_bid(ei);
		elf_destroy_info(ei);
	}
	return bid;
}
