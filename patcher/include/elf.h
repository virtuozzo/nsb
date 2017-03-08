#ifndef __PATCHER_ELF_H__
#define __PATCHER_ELF_H__

#include <unistd.h>
#include <stdint.h>

#include "list.h"

int elf_library_status(void);
int is_elf_file(const char *path);
struct patch_info_s;
int parse_elf_binpatch(struct patch_info_s *binpatch, const char *patchfile);

struct process_ctx_s;
struct elf_info_s;
int64_t load_elf(struct process_ctx_s *ctx, struct list_head *segments,
		 const struct elf_info_s *ei, uint64_t hint);
void unload_elf(struct process_ctx_s *ctx, struct list_head *segments);

struct elf_info_s *elf_create_info(const char *path);
void elf_destroy_info(struct elf_info_s *ei);

char *elf_build_id(const char *path);
const char *elf_path(struct elf_info_s *ei);
const char *elf_bid(struct elf_info_s *ei);
int elf_type_dyn(const struct elf_info_s *ei);

char *elf_get_soname(struct elf_info_s *ei);
int elf_soname_needed(struct elf_info_s *ei, const char *soname);
const struct list_head *elf_needed_list(struct elf_info_s *ei);

struct elf_needed {
	struct list_head        list;
	char                    *needed;
};

int64_t elf_dsym_offset(struct elf_info_s *ei, const char *name);
int elf_rela_plt(struct elf_info_s *ei, struct list_head *head);
int elf_rela_dyn(struct elf_info_s *ei, struct list_head *head);
int elf_contains_sym(struct elf_info_s *ei, const char *symname);

struct elf_data_s;
struct extern_symbol {
	struct list_head	list;
	char			*name;
	struct elf_data_s	*ed;
	const struct vma_area	*vma;
	int64_t			address;
};

uint64_t es_r_info(const struct extern_symbol *es);
uint32_t es_r_type(const struct extern_symbol *es);
uint32_t es_r_sym(const struct extern_symbol *es);
int64_t es_r_addend(const struct extern_symbol *es);
uint64_t es_r_offset(const struct extern_symbol *es);
uint32_t es_s_name(const struct extern_symbol *es);
uint64_t es_s_value(const struct extern_symbol *es);
uint64_t es_s_size(const struct extern_symbol *es);
unsigned char es_s_bind(const struct extern_symbol *es);
unsigned char es_s_type(const struct extern_symbol *es);

int elf_glob_sym(const struct extern_symbol *es);
int elf_weak_sym(const struct extern_symbol *es);
const char *es_type(const struct extern_symbol *es);
const char *es_binding(const struct extern_symbol *es);
const char *es_relocation(const struct extern_symbol *es);

int64_t elf_dyn_sym_value(struct elf_info_s *ei, const char *name);

int elf_reloc_sym(struct extern_symbol *es, uint64_t address);

int elf_contains_sym(struct elf_info_s *ei, const char *symname);

#endif /* __PATCHER_ELF_H__ */
