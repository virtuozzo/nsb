#ifndef __PATCHER_PROTOBUF_H__
#define __PATCHER_PROTOBUF_H__

int parse_protbuf_binpatch(struct binpatch_s *binpatch, const char *patchfile);
char *protobuf_get_bid(const char *patchfile);

#endif
