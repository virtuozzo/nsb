#ifndef __PATCHER_PROTOBUF_H__
#define __PATCHER_PROTOBUF_H__

#include <protobuf/funcpatch.pb-c.h>
#include <protobuf/binpatch.pb-c.h>
#include <protobuf/objinfo.pb-c.h>

FuncPatch *read_funcpatch(const char *path);
BinPatch *read_binpatch(const char *path);

#endif
