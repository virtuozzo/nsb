#ifndef __PATCHER_ELF_H__
#define __PATCHER_ELF_H__

#include <unistd.h>
#include <stdint.h>

#include <protobuf/binpatch.pb-c.h>

struct process_ctx_s;
int64_t load_elf(struct process_ctx_s *ctx, const BinPatch *bp,
			  uint64_t hint);

struct elf_info_s;
struct elf_info_s *elf_create_info(const char *path);
void elf_destroy_info(struct elf_info_s *ei);

char *elf_build_id(const char *path);
int elf_type(const struct elf_info_s *ei);

#endif /* __PATCHER_ELF_H__ */
