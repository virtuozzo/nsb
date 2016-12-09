#ifndef __PATCHER_ELF_H__
#define __PATCHER_ELF_H__

#include <unistd.h>
#include <stdint.h>

#include <protobuf/binpatch.pb-c.h>

struct process_ctx_s;
int64_t load_elf_segments(struct process_ctx_s *ctx, const BinPatch *bp,
			  uint64_t hint);

#endif /* __PATCHER_ELF_H__ */
