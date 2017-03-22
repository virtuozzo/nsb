#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdio.h>
#include <gelf.h>
#include <unistd.h>

#include "include/elf.h"
#include "include/context.h"
#include "include/process.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/protobuf.h"
#include "include/util.h"
#include "include/vma.h"

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
	"LOCAL",
	"GLOBAL",
	"WEAK",
};

const char *symbol_types[STT_NUM] = {
	"NOTYPE",
	"OBJECT",
	"FUNC",
	"SECTION",
	"FILE",
	"COMMON",
	"TLS",
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

const char *segment_types[PT_NUM] = {
	"PT_NULL",
	"PT_LOAD",
	"PT_DYNAMIC",
	"PT_INTERP",
	"PT_NOTE",
	"PT_SHLIB",
	"PT_PHDR",
	"PT_TLS",
};

const char *segment_type(int type)
{
	if (type < R_X86_64_NUM)
		return segment_types[type];
	pr_err("unknown segment type: %d\n", type);
	return NULL;
}

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

static struct mmap_info_s *create_elf_mmap_info(const GElf_Phdr *p)
{
	struct mmap_info_s *mmi;

	mmi = xmalloc(sizeof(*mmi));
	if (!mmi)
		return NULL;

	mmi->addr = p->p_vaddr;
	mmi->length = ELF_PAGEALIGN(p->p_filesz + ELF_PAGEOFFSET(p->p_vaddr));
	mmi->flags = MAP_PRIVATE | MAP_FIXED;
	mmi->prot = 0;
	if (p->p_flags & PF_R)
		mmi->prot |= PROT_READ;
	if (p->p_flags & PF_W)
		mmi->prot |= PROT_WRITE;
	if (p->p_flags & PF_X)
		mmi->prot |= PROT_EXEC;
	mmi->offset = p->p_offset - ELF_PAGEOFFSET(p->p_vaddr);
	return mmi;
}

static int create_elf_mmaps(struct process_ctx_s *ctx, struct list_head *mmaps,
			    const struct elf_info_s *ei)
{
	int i, err = -1;
	size_t pnum;
	struct mmap_info_s *mmi, *tmp;

	if (elf_getphdrnum(ei->e, &pnum)) {
		pr_err("elf_getphdrnum() failed: %s\n", elf_errmsg(-1));
		return -1;
	}

	for (i = 0; i < pnum; i++) {
		GElf_Phdr phdr;
		struct mmap_info_s *mmi;

		if (gelf_getphdr(P(ctx)->ei->e, i, &phdr) != &phdr) {
			pr_err("gelf_getphdr() failed: %s\n", elf_errmsg(-1));
			goto err;
		}

		if (phdr.p_type != PT_LOAD)
			continue;

		mmi = create_elf_mmap_info(&phdr);
		if (!mmi)
			goto err;

		list_add_tail(&mmi->list, mmaps);
	}

	return 0;
err:
	list_for_each_entry_safe(mmi, tmp, mmaps, list) {
		list_del(&mmi->list);
		free(mmi);
	}
	return err;
}

static int pin_elf_mmaps(struct process_ctx_s *ctx, struct list_head *mmaps,
			  uint64_t hint)
{
	struct mmap_info_s *mmi;
	const struct vma_area *fvma, *lvma;
	size_t load_size;
	int64_t hole;

	fvma = first_vma(mmaps);
	lvma = last_vma(mmaps);
	if (!fvma || !lvma) {
		pr_err("elf doesn't have load segments\n");
		return -EINVAL;
	}

	load_size = ELF_PAGESTART(vma_start(lvma)) + vma_length(lvma) -
		    ELF_PAGESTART(vma_start(fvma));

	hole = find_vma_hole(&ctx->vmas, hint, load_size);
	if (hole < 0) {
		pr_err("failed to find address space hole with size %lx "
			"starting from address %lx\n", load_size, hint);
		return hole;
	}

	/* TODO: need to check, that found hole fits into 2GB boundary range
	 * from VMA to patch.
	 */
	list_for_each_entry(mmi, mmaps, list)
		mmi->addr = ELF_PAGESTART(hole + mmi->addr);

	return 0;
}

int load_elf(struct process_ctx_s *ctx, struct list_head *segments,
	     const struct elf_info_s *ei, uint64_t hint)
{
	int err;
	LIST_HEAD(mmaps);

	err = create_elf_mmaps(ctx, segments, ei);
	if (err)
		return err;

	err = pin_elf_mmaps(ctx, segments, hint);
	if (err)
		return err;

	return process_mmap_file(ctx, ei->path, segments);
}

int unload_elf(struct process_ctx_s *ctx, struct list_head *segments)
{
	return process_munmap(ctx, segments);
}

static Elf *elf_fd(const char *path, int fd)
{
	Elf *e;

	e = elf_begin(fd, ELF_C_READ, NULL );
	if (!e)
		return NULL;

	if (elf_kind(e) != ELF_K_ELF)
		goto end_elf;

	return e;

end_elf:
	(void)elf_end(e);
	return NULL;
}

static int elf_open(const char *path, Elf **elf)
{
	int fd;
	Elf *e;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	e = elf_fd(path, fd);
	if (!e)
		goto close_fd;

	*elf = e;
	return 0;

close_fd:
	close(fd);
	return -EINVAL;
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

	INIT_LIST_HEAD(&ei->needed);

	ei->e = e;

	return ei;

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
	int err;
	Elf *e;

	if (!check_file_type(path, S_IFREG))
		return 0;

	err = elf_open(path, &e);
	if (!err)
		(void)elf_end(e);

	return !err;
}

int elf_create_info(const char *path, struct elf_info_s **elf_info)
{
	Elf *e = NULL;
	struct elf_info_s *ei;
	int err;

	err = elf_open(path, &e);
	if (err) {
		pr_err("failed to open ELF %s\n", path);
		return err;
	}

	err = -ENOMEM;
	ei = elf_alloc_info(e, path);
	if (!ei)
		goto end_elf;

	err = -EINVAL;
	if (elf_getshdrstrndx(e, &ei->shstrndx)) {
		pr_err("failed to get section string index: %s\n", elf_errmsg(-1));
		goto destroy_elf;
	}

	if (&ei->hdr != gelf_getehdr(e, &ei->hdr)) {
		pr_err("failed to get ELF header: %s\n", elf_errmsg(elf_errno()));
		goto destroy_elf;
	}

	err = __elf_get_soname(ei, &ei->soname);
	if (err)
		goto destroy_elf;

	err = elf_collect_needed(ei);
	if (err)
		goto destroy_elf;

	ei->bid = elf_get_bid(ei);

	*elf_info = ei;
	return 0;

end_elf:
	(void)elf_end(e);
	return err;

destroy_elf:
	elf_destroy_info(ei);
	return err;
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

static Elf_Scn *find_section(struct elf_info_s *ei,
			     int (*compare)(struct elf_info_s *ei,
					    Elf_Scn *scn,
					    const void *data),
			     const void *data)
{
	Elf_Scn *scn = NULL;
	int ret;

	while((scn = elf_nextscn(ei->e, scn)) != NULL) {
		ret = compare(ei, scn, data);
		if (ret < 0)
			return NULL;
		if (ret)
			return scn;
	}
	return NULL;
}

static int scn_compare_name(struct elf_info_s *ei, Elf_Scn *scn,
			    const void *data)
{
	const char *name = data;
	char *sname;

	sname = get_section_name(ei, scn);
	if (!sname)
		return -EINVAL;

	return !strcmp(sname, name);
}

static Elf_Scn *elf_get_section_by_name(struct elf_info_s *ei, const char *name)
{
	Elf_Scn *scn;

	scn = find_section(ei, scn_compare_name, name);
	if (!scn)
		pr_err("failed to find \"%s\" section in %s\n", name, ei->path);
	return scn;
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

static int scn_compare_addr(struct elf_info_s *ei, Elf_Scn *scn,
			    const void *data)
{
	GElf_Sxword addr = *(GElf_Sxword *)data;
	GElf_Sxword saddr;

	saddr = get_section_addr(ei, scn);
	if (saddr < 0)
		return saddr;

	return saddr == addr;
}

static Elf_Scn *elf_get_section_by_addr(struct elf_info_s *ei, GElf_Addr addr)
{
	Elf_Scn *scn;

	scn = find_section(ei, scn_compare_addr, &addr);
	if (!scn)
		pr_err("failed to find section with address %#lx in %s\n",
				addr, ei->path);
	return scn;
}

static Elf_Scn *elf_get_section_by_ndx(struct elf_info_s *ei, GElf_Section ndx)
{
	Elf_Scn *scn;

	scn = elf_getscn(ei->e, ndx);
	if (!scn)
		pr_err("failed to find section with index %#x in %s\n",
				ndx, ei->path);
	return scn;
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

	bid_scn = elf_get_section_by_name(ei, ".note.gnu.build-id");
	if (!bid_scn)
		return NULL;
	return get_build_id(bid_scn);
}

const char *elf_path(struct elf_info_s *ei)
{
	return ei->path;
}

const char *elf_bid(struct elf_info_s *ei)
{
	return ei->bid;
}

char *elf_build_id(const char *path)
{
	struct elf_info_s *ei;
	char *bid = NULL;
	int err;

	err = elf_create_info(path, &ei);
	if (err)
		return NULL;

	if (ei->bid)
		bid = strdup(ei->bid);

	elf_destroy_info(ei);
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

static int elf_create_scn(struct elf_info_s *ei,
		          elf_scn_t **elf_scn, const char *sname)
{
	elf_scn_t *escn;
	Elf_Scn	*scn;
	Elf_Data *data;
	int nr_ent;

	scn = elf_get_section_by_name(ei, sname);
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

static int find_dyn(struct elf_info_s *ei, GElf_Dyn *dyn,
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

		err = find_dyn(ei, &strtab_dyn, find_strtab, NULL);
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

	err = find_dyn(ei, &soname_dyn, find_soname, NULL);
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
		ei->dynstr = elf_get_section_by_name(ei, ".dynstr");
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

static int find_sym(struct elf_info_s *ei, elf_scn_t *escn, GElf_Sym *sym,
		    int (*compare)(struct elf_info_s *ei,
				   const GElf_Sym *sym, const void *data),
		    const void *data)
{
	int i;

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

static int find_dyn_sym(struct elf_info_s *ei, GElf_Sym *sym,
		    int (*compare)(struct elf_info_s *ei,
				   const GElf_Sym *sym, const void *data),
		    const void *data)
{
	elf_scn_t *escn;

	escn = elf_set_dynsym_scn(ei);
	if (!escn)
		return -ENOENT;

	return find_sym(ei, escn, sym, compare, data);
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
	return find_dyn_sym(ei, sym, compare_sym_name, symname);
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

uint64_t es_r_info(const struct extern_symbol *es)
{
	return ES_RELA(es)->r_info;
}

uint32_t es_r_type(const struct extern_symbol *es)
{
	return GELF_R_TYPE(es_r_info(es));
}

uint32_t es_r_sym(const struct extern_symbol *es)
{
	return GELF_R_SYM(es_r_info(es));
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

const char *es_type(const struct extern_symbol *es)
{
	unsigned char type;

	type = es_s_type(es);
	if (type < STT_NUM)
		return symbol_types[type];
	pr_err("unknown symbol type: %d\n", type);
	return NULL;
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

int64_t elf_dyn_sym_value(struct elf_info_s *ei, const char *name)
{
	int64_t err;
	GElf_Sym sym;

	err = elf_find_dsym_by_name(ei, name, &sym);
	if (err < 0)
		return (err != -ENOENT) ? err : 0;

	return sym.st_value;
}

int64_t elf_section_virt_base(struct elf_info_s *ei, uint16_t ndx)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;

	scn = elf_get_section_by_ndx(ei, ndx);
	if (!scn)
		return -EINVAL;

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		pr_err("getshdr() failed: %s\n", elf_errmsg(-1));
		return -EINVAL;
	}

	return shdr.sh_addr - shdr.sh_offset;
}

int elf_reloc_sym(struct extern_symbol *es, uint64_t address)
{
	switch (es_r_type(es)) {
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			es->address = address;
			return 0;
		case R_X86_64_64:
			es->address = address + es_r_addend(es);
			return 0;
		case R_X86_64_NONE:
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
	int err;
	const char *sname = VZPATCH_SECTION;
	void *data;

	err = elf_create_info(patchfile, &ei);
	if (err)
		return err;

	err = -EINVAL;

	scn = elf_get_section_by_name(ei, sname);
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
