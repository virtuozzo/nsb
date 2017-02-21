#include <link.h>
#include <linux/limits.h>

#include "include/process.h"
#include "include/log.h"
#include "include/vma.h"
#include "include/elf.h"

#define DT_THISPROCNUM		0

struct r_scope_elem
{
	  /* Array of maps for the scope.  */
	  struct link_map **r_list;
	    /* Number of entries in the scope.  */
	    unsigned int r_nlist;
};

struct link_map_ext {
	/* These first few members are part of the protocol with the debugger.
	 *        This is the same format used in SVR4.  */

	ElfW(Addr) l_addr;          /* Difference between the address in the ELF
				       file and the addresses in memory.  */
	char *l_name;               /* Absolute file name object was found in.  */
	ElfW(Dyn) *l_ld;            /* Dynamic section of the shared object.  */
	struct link_map_ext *l_next, *l_prev; /* Chain of loaded objects.  */

	/* All following members are internal to the dynamic linker.
	 *        They may change without notice.  */

	/* This is an element which is only ever different from a pointer to
	 *        the very same copy of this type for ld.so when it is used in more
	 *               than one namespace.  */
	struct link_map_ext *l_real;

	/* Number of the namespace this link map belongs to.  */
	Lmid_t l_ns;

	struct libname_list *l_libname;

	ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		+ DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
	const ElfW(Phdr) *l_phdr;   /* Pointer to program header table in core.  */
	ElfW(Addr) l_entry;         /* Entry point location.  */
	ElfW(Half) l_phnum;         /* Number of program header entries.  */
	ElfW(Half) l_ldnum;         /* Number of dynamic segment entries.  */

	struct r_scope_elem l_searchlist;

	/* We need a special searchlist to process objects marked with
	 *        DT_SYMBOLIC.  */
	struct r_scope_elem l_symbolic_searchlist;

	/* Dependent object that first caused this object to be loaded.  */
	struct link_map_ext *l_loader;

	/* Array with version names.  */
	struct r_found_version *l_versions;
	unsigned int l_nversions;

	/* Symbol hash table.  */
	Elf_Symndx l_nbuckets;
	Elf32_Word l_gnu_bitmask_idxbits;
	Elf32_Word l_gnu_shift;
	const ElfW(Addr) *l_gnu_bitmask;
	union
	{
		const Elf32_Word *l_gnu_buckets;
		const Elf_Symndx *l_chain;
	};
	union
	{
		const Elf32_Word *l_gnu_chain_zero;
		const Elf_Symndx *l_buckets;
	};

	unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
	enum                        /* Where this object came from.  */
	{
		lt_executable,          /* The main executable program.  */
		lt_library,             /* Library needed by main executable.  */
		lt_loaded               /* Extra run-time loaded shared object.  */
	} l_type:2;
	unsigned int l_relocated:1; /* Nonzero if object's relocations done.  */
	unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.  */
	unsigned int l_global:1;    /* Nonzero if object in _dl_global_scope.  */
	unsigned int l_reserved:2;  /* Reserved for internal use.  */
	unsigned int l_phdr_allocated:1; /* Nonzero if the data structure pointed
					    to by `l_phdr' is allocated.  */
	unsigned int l_soname_added:1; /* Nonzero if the SONAME is for sure in
					  the l_libname list.  */
	unsigned int l_faked:1;     /* Nonzero if this is a faked descriptor
				       without associated file.  */
	unsigned int l_need_tls_init:1; /* Nonzero if GL(dl_init_static_tls)
					   should be called on this link map
					   when relocation finishes.  */
	unsigned int l_auditing:1;  /* Nonzero if the DSO is used in auditing.  */
	unsigned int l_audit_any_plt:1; /* Nonzero if at least one audit module
					   is interested in the PLT interception.*/
	unsigned int l_removed:1;   /* Nozero if the object cannot be used anymore
				       since it is removed.  */
	unsigned int l_contiguous:1; /* Nonzero if inter-segment holes are
					mprotected or if no holes are present at
					all.  */
	unsigned int l_symbolic_in_local_scope:1; /* Nonzero if l_local_scope
						     during LD_TRACE_PRELINKING=1
						     contains any DT_SYMBOLIC
						     libraries.  */
	unsigned int l_free_initfini:1; /* Nonzero if l_initfini can be
					   freed, ie. not allocated with
					   the dummy malloc in ld.so.  */
};

struct link_namespaces
{
	/* A pointer to the map for the main map.  */
	struct link_map_ext *_ns_loaded;
	/* Number of object in the _dl_loaded list.  */
	unsigned int _ns_nloaded;
};

/* We do support only one (1) namespace */

struct rtld_global
{
	struct link_namespaces _dl_ns;
};

static int64_t get_rtld_offset(const struct process_ctx_s *ctx)
{
	const struct vma_area *ldso;
	const char *ldso_path;
	int64_t offset;

	/*TODO need to find a proper way, how to define ld.so path */
	ldso_path = "/usr/lib64/ld-2.17.so";

	ldso = find_vma_by_path(&ctx->vmas, ldso_path);
	if (!ldso) {
		pr_err("failed to find vma for %s\n", ldso_path);
		return -EINVAL;
	}

	offset = elf_dsym_offset(ldso->ei, "_rtld_global");
	if (offset < 0) {
		pr_err("failed to find _rtld_global symbol\n");
		return -EINVAL;
	}

	return ldso->start + offset;
}

static int64_t get_rtld(const struct process_ctx_s *ctx,
			struct link_namespaces *_dl_ns, uint64_t rtld_addr)
{
	int err;

	err = process_read_data(ctx->pid, rtld_addr, _dl_ns,
				round_up(sizeof(*_dl_ns), 8));
	if (err < 0) {
		pr_err("failed to read process address %ld: %d\n", rtld_addr, err);
		return err;
	}

	pr_debug("  _rtld_global._ns_loaded : %p\n", _dl_ns->_ns_loaded);
	pr_debug("  _rtld_global._ns_nloaded: %d\n", _dl_ns->_ns_nloaded);
	return 0;
}

static int find_lm_by_vma(const struct process_ctx_s *ctx,
			  struct link_map_ext *lm)
{
	int err;
	char name[PATH_MAX+1] = { };

	pr_debug("  searching entry within range %#lx-%#lx:\n", ctx->pvma->start, ctx->pvma->end);
	while (lm->l_next) {
		void *lm_addr = lm->l_next;

		err = process_read_data(ctx->pid, (uint64_t)lm_addr, lm, round_up(sizeof(*lm), 8));
		if (err < 0) {
			pr_err("failed to read process address %p: %d\n", lm_addr, err);
			return err;
		}

		if (lm_addr != lm->l_real) {
			pr_err("lm != lm->l_real\n");
			return -EINVAL;
		}

		err = process_read_data(ctx->pid, (uint64_t)lm->l_name, name, round_up(PATH_MAX, 8));
		if (err < 0) {
			pr_err("failed to read process address %p: %d\n", lm->l_name, err);
			return err;
		}

		if (!strlen(name))
			continue;

		pr_debug("    name   : '%s'\n", name);
		pr_debug("    l_entry: %#lx\n", lm->l_entry);
		pr_debug("    l_prev : %p\n", lm->l_prev);
		pr_debug("    l_next : %p\n", lm->l_next);

		if ((lm->l_entry > ctx->pvma->start) &&
		    (lm->l_entry < ctx->pvma->end)) {
			pr_debug("  found\n");
			return 0;
		}
	}
	pr_err("failed to find %s library link_map\n", ctx->pvma->path);
	return -ENOENT;
}

static int remove_lm(const struct process_ctx_s *ctx,
		     const struct link_map_ext *lm)
{
	int err;
	uint64_t address;

	address = (uint64_t)lm->l_prev + offsetof(struct link_map, l_next);
	pr_debug( "  writing %p to %#lx\n", lm->l_next, address);

	err = process_write_data(ctx->pid, address, &lm->l_next, 8);
	if (err < 0) {
		pr_err("failed to write process address %ld: %d\n", address, err);
		return err;
	}

	address = (uint64_t)lm->l_next + offsetof(struct link_map, l_prev);
	pr_debug( "  writing %p to %#lx\n", lm->l_prev, address);

	err = process_write_data(ctx->pid, address, &lm->l_prev, 8);
	if (err < 0) {
		pr_err("failed to write process address %ld: %d\n", address, err);
		return err;
	}

	return 0;
}

int fixup_rtld(const struct process_ctx_s *ctx)
{
	/* Hire magic happens */
	int64_t rtld_addr;
	int err;
	struct link_namespaces _dl_ns;
	struct link_map_ext lm;

	pr_debug("= Fixing dynamic linker internals\n");

	rtld_addr =  get_rtld_offset(ctx);
	if (rtld_addr < 0)
		return rtld_addr;

	pr_debug("  _rtld_global address    : %#lx\n", rtld_addr);

	err = get_rtld(ctx, &_dl_ns, rtld_addr);
	if (err)
		return err;

	_dl_ns._ns_nloaded--;

	lm.l_next = _dl_ns._ns_loaded;

	err = find_lm_by_vma(ctx, &lm);
	if (err)
		return err;

	return remove_lm(ctx, &lm);
}
