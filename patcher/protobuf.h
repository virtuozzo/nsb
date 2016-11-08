#ifndef __CR_PROTOBUF_H__
#define __CR_PROTOBUF_H__

#include "funcpatch.pb-c.h"
#include "binpatch.pb-c.h"

FuncPatch *read_funcpatch(const char *path);
BinPatch *read_binpatch(const char *path);

#endif
