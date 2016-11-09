noinst_SCRIPTS =	funcpatch_pb2.py	\
			funcpatch.pb-c.c	\
			funcpatch.pb-c.h	\
						\
			objinfo_pb2.py		\
			objinfo.pb-c.c		\
			objinfo.pb-c.h		\
						\
			binpatch_pb2.py		\
			binpatch.pb-c.c		\
			binpatch.pb-c.h


CLEANFILES = $(noinst_SCRIPTS)

SUFFIXES = _pb2.py .pb-c.c .pb-c.h .proto

.proto_pb2.py:
	$(AM_V_GEN) protoc -I=. --python_out=. $<

.proto.pb-c.c:
	$(AM_V_GEN) protoc-c -I=. --c_out=. $<

# Make sure, that check for header happens _after_ source generation
funcpatch.pb-c.h: funcpatch.pb-c.c
binpatch.pb-c.h: binpatch.pb-c.c
objinfo.pb-c.h: objinfo.pb-c.c
