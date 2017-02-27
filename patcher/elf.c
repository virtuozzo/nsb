#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdio.h>
#include <gelf.h>
#include <unistd.h>

#include "include/elf.h"
#include "include/process.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/protobuf.h"
#include "include/util.h"

#define ELF_MIN_ALIGN		PAGE_SIZE

#define TASK_SIZE		((1UL << 47) - PAGE_SIZE)
#define ELF_ET_DYN_BASE		(TASK_SIZE / 3 * 2)

#define ELF_PAGESTART(_v)	((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v)	((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v)	(((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define VZPATCH_SECTION		"vzpatch"

typedef struct elf_scn_s {
	Elf_Scn		*scn;
	Elf_Data	*data;
	unsigned	nr_ent;
} elf_scn_t;

struct elf_info_s {
	char			*path;
	Elf			*e;
	size_t			shstrndx;
	GElf_Ehdr		hdr;
	Elf_Scn			*strtab;
	elf_scn_t		*rela_plt;
	elf_scn_t		*rela_dyn;
	elf_scn_t		*dynamic;
	elf_scn_t		*dynsym;
	Elf_Scn			*dynstr;
	char			*soname;
	struct list_head	needed;
	char			*bid;
};

struct elf_data_s {
	GElf_Rela		rela;
	GElf_Sym		sym;
};

#define ES_RELA(es)		(&(es->ed->rela))
#define ES_SYM(es)		(&(es->ed->sym))

const char *symbol_bindings[STB_NUM] = {
	"STB_LOCAL",
	"STB_GLOBAL",
	"STB_WEAK",
};

const char *relocation_types[R_X86_64_NUM] = {
	"R_X86_64_NONE",
	"R_X86_64_64",
	"R_X86_64_PC32",
	"R_X86_64_GOT32",
	"R_X86_64_PLT32",
	"R_X86_64_COPY",
	"R_X86_64_GLOB_DAT",
	"R_X86_64_JUMP_SLOT",
	"R_X86_64_RELATIVE",
	"R_X86_64_GOTPCREL",
	"R_X86_64_32",
	"R_X86_64_32S",
	"R_X86_64_16",
	"R_X86_64_PC16",
	"R_X86_64_8",
	"R_X86_64_PC8",
	"R_X86_64_DTPMOD64",
	"R_X86_64_DTPOFF64",
	"R_X86_64_TPOFF64",
	"R_X86_64_TLSGD",
	"R_X86_64_TLSLD",
	"R_X86_64_DTPOFF32",
	"R_X86_64_GOTTPOFF",
	"R_X86_64_TPOFF32",
	"R_X86_64_PC64",
	"R_X86_64_GOTOFF64",
	"R_X86_64_GOTPC32",
	"R_X86_64_GOT64",
	"R_X86_64_GOTPCREL64",
	"R_X86_64_GOTPC64",
	"R_X86_64_GOTPLT64",
	"R_X86_64_PLTOFF64",
	"R_X86_64_SIZE32",
	"R_X86_64_SIZE64",
	"R_X86_64_GOTPC32_TLSDESC",
	"R_X86_64_TLSDESC_CALL",
	"R_X86_64_TLSDESC",
	"R_X86_64_IRELATIVE",
	"R_X86_64_RELATIVE64",
};

static int __elf_get_soname(struct elf_info_s *ei, char **soname);
static int elf_collect_needed(struct elf_info_s *ei);
static char *elf_get_bid(struct elf_info_s *ei);

int elf_library_status(void)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_err("ELF library initialization failed: %s\n", elf_errmsg(-1));
		return -EFAULT;
	}
	return 0;
}

static int64_t elf_map(struct process_ctx_s *ctx, int fd, uint64_t addr, struct segment_s *es, int flags)
{
	unsigned long size = es->file_sz + ELF_PAGEOFFSET(es->vaddr);
	unsigned long off = es->offset - ELF_PAGEOFFSET(es->vaddr);
	int prot = 0;
	int64_t maddr;

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
	maddr = process_create_map(ctx, fd, off, addr, size, flags, prot);
	if (maddr > 0)
		pr_info("    - %#lx-%#lx, prot: %#x, flags: %#x, off: %#lx\n", maddr, maddr + size, prot, flags, off);
	return maddr;
}

int64_t load_elf(struct process_ctx_s *ctx, uint64_t hint)
{
	const struct patch_info_s *pi = PI(ctx);
	int i, fd;
	// TODO: there should be bigger offset. 2 or maybe even 4 GB.
	// But jmpq command construction fails, if map lays ouside 2g offset.
	// This might be a bug in jmps construction
	uint64_t load_bias = hint & 0xfffffffff0000000;
	int flags = MAP_PRIVATE;

	pr_info("= Loading %s:\n", pi->path);
	fd = open(pi->path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s for read", pi->path);
		return -1;
	}

	fd = process_open_file(ctx, pi->path, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	for (i = 0; i < pi->n_segments; i++) {
		struct segment_s *es = pi->segments[i];
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

static Elf *elf_fd(const char *path, int fd)
{
	Elf *e;

	e = elf_begin(fd, ELF_C_READ, NULL );
	if (!e)
		return NULL;

	if (elf_kind(e) != ELF_K_ELF) {
		pr_debug("    %s is not and regular ELF file\n", path);
		goto end_elf;
	}

	return e;

end_elf:
	(void)elf_end(e);
	return NULL;
}

static Elf *elf_open(const char *path)
{
	int fd;
	Elf *e;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", path);
		return NULL;
	}

	e = elf_fd(path, fd);
	if (!e)
		goto close_fd;

	return e;

close_fd:
	close(fd);
	return NULL;
}

int elf_type_dyn(const struct elf_info_s *ei)
{
	return ei->hdr.e_type == ET_DYN;
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

	if (&ei->hdr != gelf_getehdr(e, &ei->hdr)) {
		pr_err("failed to get ELF header: %s\n", elf_errmsg(elf_errno()));
		goto free_ei_path;
	}

	INIT_LIST_HEAD(&ei->needed);

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
	free(ei->soname);
	(void)elf_end(ei->e);
	free(ei);
}

int is_elf_file(const char *path)
{
	int fd;
	Elf *e;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	e = elf_fd(path, fd);
	if (e)
		(void)elf_end(e);

	close(fd);
	return e != NULL;
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

	if (__elf_get_soname(ei, &ei->soname))
		goto destroy_elf;

	if (elf_collect_needed(ei))
		goto destroy_elf;

	ei->bid = elf_get_bid(ei);

	return ei;

end_elf:
	(void)elf_end(e);
	return NULL;

destroy_elf:
	elf_destroy_info(ei);
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
	pr_err("failed to find \"%s\" section in %s\n", name, ei->path);
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
	if (!bid_scn)
		return NULL;
	return get_build_id(bid_scn);
}

const char *elf_bid(struct elf_info_s *ei)
{
	return ei->bid;
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

static int sect_nr_ent(struct elf_info_s *ei, Elf_Scn *scn)
{
	GElf_Shdr shdr;

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		pr_err("failed to get header for section: %s\n",
					elf_errmsg(-1));
		return elf_errno();
	}

	return shdr.sh_size/shdr.sh_entsize;
}

static GElf_Sxword get_section_addr(struct elf_info_s *ei, Elf_Scn *scn)
{
	GElf_Shdr shdr;

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		pr_err("getshdr() failed: %s\n", elf_errmsg(-1));
		return -EINVAL;
	}

	return shdr.sh_addr;
}

static Elf_Scn *elf_get_section_by_addr(struct elf_info_s *ei, GElf_Addr addr)
{
	Elf_Scn *scn = NULL;

	while((scn = elf_nextscn(ei->e, scn)) != NULL) {
		GElf_Sxword saddr;

		saddr = get_section_addr(ei, scn);
		if (saddr < 0)
			break;

		if (saddr == addr)
			return scn;
	}

	return NULL;
}

static int elf_create_scn(struct elf_info_s *ei,
		          elf_scn_t **elf_scn, const char *sname)
{
	elf_scn_t *escn;
	Elf_Scn	*scn;
	Elf_Data *data;
	int nr_ent;

	scn = elf_get_section(ei, sname);
	if (!scn)
		return -ENOENT;

	data = elf_getdata(scn, NULL);
	if (!data) {
		pr_err("%s section doesn't have data\n", sname);
		return -ENODATA;
	}

	nr_ent = sect_nr_ent(ei, scn);
	if (nr_ent < 0)
		return nr_ent;

	escn = xmalloc(sizeof(*escn));
	if (!escn)
		return -ENOMEM;

	escn->scn = scn;
	escn->data = data;
	escn->nr_ent = nr_ent;
	*elf_scn = escn;

	return 0;
}

static elf_scn_t *elf_set_dynamic_scn(struct elf_info_s *ei)
{
	if (!ei->dynamic) {
		if (elf_create_scn(ei, &ei->dynamic, ".dynamic"))
			return NULL;
	}
	return ei->dynamic;
}

static int find_soname(struct elf_info_s *ei, const GElf_Dyn *d, const void *dummy)
{
	if (d->d_tag != DT_SONAME)
		return 0;
	return 1;
}

static int find_strtab(struct elf_info_s *ei, const GElf_Dyn *d, const void *dummy)
{
	if (d->d_tag != DT_STRTAB)
		return 0;
	return 1;
}

static int find_dyn_sym(struct elf_info_s *ei, GElf_Dyn *dyn,
			int (*compare)(struct elf_info_s *ei,
				       const GElf_Dyn *dyn, const void *data),
			const void *data)
{
	int i;
	elf_scn_t *scn;

	scn = elf_set_dynamic_scn(ei);
	if (!scn)
		return -ENOENT;

	for (i = 0; i < scn->nr_ent; i++) {
		int ret;

		if (!gelf_getdyn(scn->data, i, dyn)) {
			pr_err("failed to get %d tag from \".dynamic\" section\n", i);
			return -EINVAL;
		}

		ret = compare(ei, dyn, data);
		if (ret)
			return ret;
	}
	return -ENOENT;
}

#define DYN_PTR(dyn)		(dyn)->d_un.d_ptr
#define DYN_VAL(dyn)		(dyn)->d_un.d_val

static Elf_Scn *elf_get_strtab_scn(struct elf_info_s *ei)
{
	if (!ei->strtab) {
		int err;
		GElf_Dyn strtab_dyn;

		err = find_dyn_sym(ei, &strtab_dyn, find_strtab, NULL);
		if (err < 0) {
			pr_debug("Failed to find DT_STRTAB tag\n");
			return NULL;
		}

		ei->strtab = elf_get_section_by_addr(ei, DYN_PTR(&strtab_dyn));
	}
	return ei->strtab;
}

static int __elf_get_soname(struct elf_info_s *ei, char **soname)
{
	Elf_Scn *strtab_scn;
	GElf_Dyn soname_dyn;
	int err;
	char *name;

	if (!elf_type_dyn(ei))
		return 0;

	strtab_scn = elf_get_strtab_scn(ei);
	if (!strtab_scn)
		return -EINVAL;

	err = find_dyn_sym(ei, &soname_dyn, find_soname, NULL);
	if (err < 0) {
		if (err == -ENOENT)
			return 0;

		pr_debug("Failed to find DT_SONAME tag\n");
		return err;
	}

	name = elf_strptr(ei->e, elf_ndxscn(strtab_scn), DYN_VAL(&soname_dyn));
	if (!name) {
		pr_err("elf_strptr() failed: %s\n", elf_errmsg(-1));
		return -EINVAL;
	}

	*soname = xstrdup(name);
	if (!*soname)
		return -ENOMEM;

	return 0;
}

char *elf_get_soname(struct elf_info_s *ei)
{
	return ei->soname;
}

static int iter_dyn_sym(struct elf_info_s *ei,
			int (*actor)(struct elf_info_s *ei,
				     const GElf_Dyn *dyn, void *data),
			void *data)
{
	int i;
	elf_scn_t *scn;
	GElf_Dyn dyn;

	scn = elf_set_dynamic_scn(ei);
	if (!scn)
		return -ENOENT;

	for (i = 0; i < scn->nr_ent; i++) {
		int ret;

		if (!gelf_getdyn(scn->data, i, &dyn)) {
			pr_err("failed to get %d tag from \".dynamic\" section\n", i);
			return -EINVAL;
		}

		ret = actor(ei, &dyn, data);
		if (ret)
			return ret;
	}
	return 0;
}

static int collect_needed(struct elf_info_s *ei, const GElf_Dyn *d, void *data)
{
	struct list_head *head = data;
	struct elf_needed *n;
	Elf_Scn *strtab_scn;
	char *needed;

	if (d->d_tag != DT_NEEDED)
		return 0;

	strtab_scn = elf_get_strtab_scn(ei);
	if (!strtab_scn)
		return -EINVAL;

	needed = elf_strptr(ei->e, elf_ndxscn(strtab_scn), DYN_VAL(d));
	if (!needed) {
		pr_err("elf_strptr() failed: %s\n", elf_errmsg(-1));
		return -EINVAL;
	}

	n = xmalloc(sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->needed = xstrdup(needed);
	if (!n->needed) {
		free(n);
		return -ENOMEM;
	}

	list_add_tail(&n->list, head);
	return 0;
}

static int elf_collect_needed(struct elf_info_s *ei)
{
	if (list_empty(&ei->needed))
		return iter_dyn_sym(ei, collect_needed, &ei->needed);
	return 0;
}

int elf_soname_needed(struct elf_info_s *ei, const char *soname)
{
	struct elf_needed *n;

	list_for_each_entry(n, &ei->needed, list) {
		if (!strcmp(n->needed, soname))
			return 1;
	}
	return 0;
}

const struct list_head *elf_needed_list(struct elf_info_s *ei)
{
	return &ei->needed;
}

static struct extern_symbol *create_ext_sym(char *name, const GElf_Rela *rela,
					    const GElf_Sym *sym)
{
	struct extern_symbol *es;
	struct elf_data_s *ed;

	es = xmalloc(sizeof(*es));
	if (!es)
		return NULL;

	ed = xmalloc(sizeof(*ed));
	if (!ed) {
		free(es);
		return NULL;
	}

	memcpy(&ed->rela, rela, sizeof(GElf_Rela));
	memcpy(&ed->sym, sym, sizeof(GElf_Sym));
	es->ed = ed;
	es->name = name;
	es->address = 0;
	es->vma = NULL;
	return es;
}

static int get_symbol_name(const GElf_Sym *sym, struct elf_info_s *ei,
			   Elf_Scn *strscn, char **name)
{
	*name = NULL;

	if (sym->st_name) {
		*name = elf_strptr(ei->e, elf_ndxscn(strscn), sym->st_name);
		if (!*name) {
			pr_err("elf_strptr() failed: %s\n", elf_errmsg(-1));
			return -EINVAL;
		}
	}

	return 0;
}

static int dynsym_name(const GElf_Sym *sym, struct elf_info_s *ei, char **name)
{
	if (!ei->dynstr) {
		ei->dynstr = elf_get_section(ei, ".dynstr");
		if (!ei->dynstr) {
			pr_err("failed to find \".dynstr\" section\n");
			return -EINVAL;
		}
	}
	return get_symbol_name(sym, ei, ei->dynstr, name);
}

static elf_scn_t *elf_set_dynsym_scn(struct elf_info_s *ei)
{
	if (!ei->dynsym) {
		if (elf_create_scn(ei, &ei->dynsym, ".dynsym"))
			return NULL;
	}
	return ei->dynsym;
}

static int find_sym_dym(struct elf_info_s *ei, GElf_Sym *sym,
			int (*compare)(struct elf_info_s *ei,
				       const GElf_Sym *sym, const void *data),
			const void *data)
{
	int i;
	elf_scn_t *escn;

	escn = elf_set_dynsym_scn(ei);
	if (!escn)
		return -ENOENT;

	for (i = 0; i < escn->nr_ent; i++) {
		int ret;

		if (gelf_getsym(escn->data, i, sym) != sym)
			return -ENOENT;

		ret = compare(ei, sym, data);
		if (ret)
			return ret;
	}
	return -ENOENT;
}

static int compare_sym_name(struct elf_info_s *ei,
			    const GElf_Sym *sym, const void *data)
{
	const char *symname = data;
	char *name;
	int err;

	if (!sym->st_name)
		return 0;

	if (!sym->st_size)
		return 0;

	err = dynsym_name(sym, ei, &name);
	if (err)
		return err;

	return !strcmp(name, symname);
}

static int elf_find_dsym_by_name(struct elf_info_s *ei, const char *symname,
				 GElf_Sym *sym)
{
	return find_sym_dym(ei, sym, compare_sym_name, symname);
}

int64_t elf_dsym_offset(struct elf_info_s *ei, const char *name)
{
	GElf_Sym sym;
	int err;

	err = elf_find_dsym_by_name(ei, name, &sym);
	if (err < 0)
		return err;

	return sym.st_value;
}

static elf_scn_t *elf_set_rela_plt_scn(struct elf_info_s *ei)
{
	if (!ei->rela_plt) {
		if (elf_create_scn(ei, &ei->rela_plt, ".rela.plt"))
			return NULL;
	}
	return ei->rela_plt;
}

static elf_scn_t *elf_set_rela_dyn_scn(struct elf_info_s *ei)
{
	if (!ei->rela_dyn) {
		if (elf_create_scn(ei, &ei->rela_dyn, ".rela.dyn"))
			return NULL;
	}
	return ei->rela_dyn;
}

static int iter_rela(struct elf_info_s *ei, const elf_scn_t *escn,
		     int (*actor)(struct elf_info_s *ei,
				  const GElf_Rela *rela, void *data),
		     void *data)
{
	int i;
	GElf_Rela rela;

	for (i = 0; i < escn->nr_ent; i++) {
		int ret;

		if (!gelf_getrela(escn->data, i, &rela)) {
			pr_err("failed to get %d tag from \".rela.*\" section\n", i);
			return -EINVAL;
		}

		ret = actor(ei, &rela, data);
		if (ret)
			return ret;
	}
	return 0;
}

static int collect_es(struct elf_info_s *ei, const GElf_Rela *rela, void *data)
{
	struct list_head *head = data;
	elf_scn_t *escn;
	GElf_Sym sym;
	char *name;
	int err;
	struct extern_symbol *es;

	escn = elf_set_dynsym_scn(ei);
	if (!escn)
		return -EINVAL;

	if (gelf_getsym(escn->data, GELF_R_SYM(rela->r_info), &sym) != &sym)
		return -ENOENT;

	if (!sym.st_name)
		return 0;

	err = dynsym_name(&sym, ei, &name);
	if (err)
		return err;

	es = create_ext_sym(name, rela, &sym);
	if (!es)
		return -ENOMEM;

	list_add_tail(&es->list, head);

	return 0;
}

int elf_collect_rela(struct elf_info_s *ei, elf_scn_t *escn, struct list_head *head)
{
	int err;
	struct extern_symbol *es, *tmp;

	err = iter_rela(ei, escn, collect_es, head);
	if (err)
		goto free_list;
	return 0;

free_list:
	list_for_each_entry_safe(es, tmp, head, list) {
		list_del(&es->list);
		free(es);
	}
	return err;
}

int elf_rela_plt(struct elf_info_s *ei, struct list_head *head)
{
	elf_scn_t *escn;

	escn = elf_set_rela_plt_scn(ei);
	if (!escn)
		return -ENOENT;

	return elf_collect_rela(ei, escn, head);
}

int elf_rela_dyn(struct elf_info_s *ei, struct list_head *head)
{
	elf_scn_t *escn;

	escn = elf_set_rela_dyn_scn(ei);
	if (!escn)
		return -ENOENT;

	return elf_collect_rela(ei, escn, head);
}

int elf_contains_sym(struct elf_info_s *ei, const char *symname)
{
	int err;
	GElf_Sym sym;

	err = elf_find_dsym_by_name(ei, symname, &sym);
	switch (err) {
		case 0:
			return 1;
		case -ENOENT:
			return 0;
	}
	return err;
}

uint32_t es_r_type(const struct extern_symbol *es)
{
	return GELF_R_TYPE(ES_RELA(es)->r_info);
}

uint32_t es_r_sym(const struct extern_symbol *es)
{
	return GELF_R_SYM(ES_RELA(es)->r_info);
}

int64_t es_r_addend(const struct extern_symbol *es)
{
	return ES_RELA(es)->r_addend;
}

uint64_t es_r_offset(const struct extern_symbol *es)
{
	return ES_RELA(es)->r_offset;
}

uint32_t es_s_name(const struct extern_symbol *es)
{
	return ES_SYM(es)->st_name;
}

uint64_t es_s_value(const struct extern_symbol *es)
{
	return ES_SYM(es)->st_value;
}

uint64_t es_s_size(const struct extern_symbol *es)
{
	return ES_SYM(es)->st_size;
}

unsigned char es_s_bind(const struct extern_symbol *es)
{
	return GELF_ST_BIND(ES_SYM(es)->st_info);
}

unsigned char es_s_type(const struct extern_symbol *es)
{
	return GELF_ST_TYPE(ES_SYM(es)->st_info);
}

int elf_glob_sym(const struct extern_symbol *es)
{
	return es_s_bind(es) == STB_GLOBAL;
}

int elf_weak_sym(const struct extern_symbol *es)
{
	return es_s_bind(es) == STB_WEAK;
}

const char *es_binding(const struct extern_symbol *es)
{
	unsigned char bind;

	bind = es_s_bind(es);
	if (bind < STB_NUM)
		return symbol_bindings[bind];
	pr_err("unknown symbol binding: %d\n", bind);
	return NULL;
}

const char *es_relocation(const struct extern_symbol *es)
{
	unsigned char type;

	type = es_r_type(es);
	if (type < R_X86_64_NUM)
		return relocation_types[type];
	pr_err("unknown relocation type: %d\n", type);
	return NULL;
}

static int64_t elf_has_sym(struct elf_info_s *ei,
			   const char *name, unsigned char bind)
{
	int64_t err;
	GElf_Sym sym;

	err = elf_find_dsym_by_name(ei, name, &sym);
	if (err < 0) {
		return (err != -ENOENT) ? err : 0;
	}

	if (GELF_ST_BIND(sym.st_info) != bind)
		return 0;

	return sym.st_value;
}

int64_t elf_has_glob_sym(struct elf_info_s *ei, const char *name)
{
	return elf_has_sym(ei, name, STB_GLOBAL);
}

int64_t elf_has_weak_sym(struct elf_info_s *ei, const char *name)
{
	return elf_has_sym(ei, name, STB_WEAK);
}

int elf_reloc_sym(struct extern_symbol *es, uint64_t address)
{
	switch (es_r_type(es)) {
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			es->address = address;
			return 0;
		case R_X86_64_NONE:
		case R_X86_64_64:
		case R_X86_64_PC32:
		case R_X86_64_GOT32:
		case R_X86_64_PLT32:
		case R_X86_64_COPY:
		case R_X86_64_RELATIVE:
		case R_X86_64_GOTPCREL:
		case R_X86_64_32:
		case R_X86_64_32S:
		case R_X86_64_16:
		case R_X86_64_PC16:
		case R_X86_64_8:
		case R_X86_64_PC8:
		case R_X86_64_DTPMOD64:
		case R_X86_64_DTPOFF64:
		case R_X86_64_TPOFF64:
		case R_X86_64_TLSGD:
		case R_X86_64_TLSLD:
		case R_X86_64_DTPOFF32:
		case R_X86_64_GOTTPOFF:
		case R_X86_64_TPOFF32:
		case R_X86_64_PC64:
		case R_X86_64_GOTOFF64:
		case R_X86_64_GOTPC32:
		case R_X86_64_GOT64:
		case R_X86_64_GOTPCREL64:
		case R_X86_64_GOTPC64:
		case R_X86_64_GOTPLT64:
		case R_X86_64_PLTOFF64:
		case R_X86_64_SIZE32:
		case R_X86_64_SIZE64:
		case R_X86_64_GOTPC32_TLSDESC:
		case R_X86_64_TLSDESC_CALL:
		case R_X86_64_TLSDESC:
		case R_X86_64_IRELATIVE:
		case R_X86_64_RELATIVE64:
			break;
		default:
			pr_err("unknown relocations type: %d\n", es_r_type(es));
	}
	pr_err("relocation \"%s\" is not supported\n", es_relocation(es));
	return -ENOTSUP;
}

int parse_elf_binpatch(struct patch_info_s *binpatch, const char *patchfile)
{
	struct elf_info_s *ei;
	Elf_Scn *scn;
	Elf_Data *edata;
	GElf_Shdr shdr;
	int err = -EINVAL;
	const char *sname = VZPATCH_SECTION;
	void *data;

	ei = elf_create_info(patchfile);
	if (!ei)
		return -EINVAL;

	scn = elf_get_section(ei, sname);
	if (!scn)
		goto destroy_elf_info;

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		pr_err("failed to get %s section header\n", sname);
		goto destroy_elf_info;
	}

	if (!shdr.sh_size) {
		pr_err("section %s has 0 size\n", sname);
		goto destroy_elf_info;
	}

	edata = elf_getdata(scn, NULL);
	if (!edata) {
		pr_err("%s section doesn't have data\n", sname);
		err = -ENODATA;
		goto destroy_elf_info;
	}

	err = -ENOMEM;
	data = xzalloc(edata->d_size);
	if (!data)
		goto destroy_elf_info;

	err = unpack_protobuf_binpatch(binpatch, edata->d_buf, edata->d_size);
	if (err)
		goto free_data;

	if (!binpatch->path) {
		binpatch->path = strdup(patchfile);
		if (!binpatch->path)
			err = -ENOMEM;
	}

free_data:
	free(data);
destroy_elf_info:
	elf_destroy_info(ei);
	return err;
}
