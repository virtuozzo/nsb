#ifndef __PATCHER_RELOCATIONS_H__
#define __PATCHER_RELOCATIONS_H__

struct process_ctx_s;
int collect_relocations(struct process_ctx_s *ctx);
int resolve_relocations(struct process_ctx_s *ctx);
int apply_relocations(struct process_ctx_s *ctx);

#endif
