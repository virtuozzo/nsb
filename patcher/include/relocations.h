/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_RELOCATIONS_H__
#define __PATCHER_RELOCATIONS_H__

struct process_ctx_s;
int collect_relocations(struct process_ctx_s *ctx);
int resolve_relocations(struct process_ctx_s *ctx);
int apply_relocations(struct process_ctx_s *ctx);

#endif
