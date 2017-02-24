#ifndef __PATCHER_PROTOBUF_H__
#define __PATCHER_PROTOBUF_H__

int unpack_protobuf_binpatch(struct patch_info_s *binpatch,
			     const void *data, size_t size);
int parse_protobuf_binpatch(struct patch_info_s *binpatch, const char *patchfile);
char *protobuf_get_bid(const char *patchfile);

#endif
