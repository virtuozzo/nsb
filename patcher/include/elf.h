#ifndef __PATCHER_ELF_H__
#define __PATCHER_ELF_H__

#include <unistd.h>
#include <stdint.h>

#include <protobuf/binpatch.pb-c.h>

#include "list.h"

struct process_ctx_s;
int64_t load_elf(struct process_ctx_s *ctx, const BinPatch *bp,
			  uint64_t hint);

struct elf_info_s;
struct elf_info_s *elf_create_info(const char *path);
void elf_destroy_info(struct elf_info_s *ei);

char *elf_build_id(const char *path);
const char *elf_bid(struct elf_info_s *ei);
int elf_type_dyn(const struct elf_info_s *ei);

char *elf_get_soname(struct elf_info_s *ei);
int path_get_soname(const char *path, char **soname);
int elf_soname_needed(struct elf_info_s *ei, const char *soname);
const struct list_head *elf_needed_list(struct elf_info_s *ei);

struct elf_needed {
	struct list_head        list;
	char                    *needed;
};

int64_t elf_dsym_offset(struct elf_info_s *ei, const char *name);
int elf_extern_dsyms(struct elf_info_s *ei, struct list_head *head);
int elf_contains_sym(struct elf_info_s *ei, const char *symname);

struct extern_symbol {
	struct list_head	list;
	char			*name;
	uint64_t		offset;
	int			bind;
	char			*soname;
	const struct vma_area	*vma;
};
int elf_weak_sym(const struct extern_symbol *es);

int elf_contains_sym(struct elf_info_s *ei, const char *symname);

#endif /* __PATCHER_ELF_H__ */
