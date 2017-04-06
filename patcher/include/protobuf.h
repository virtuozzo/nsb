/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_PROTOBUF_H__
#define __PATCHER_PROTOBUF_H__

int unpack_protobuf_binpatch(struct patch_info_s *binpatch,
			     const void *data, size_t size);

#endif
