dist_noinst_DATA = funcpatch.proto	\
		   binpatch.proto	\
		   objinfo.proto	\
		   segment.proto	\
		   datasym.proto

DEPS	= $(dist_noinst_DATA:.proto=.dep)

-include $(DEPS)

PROTO_C_OUT = $(dist_noinst_DATA:.proto=.pb-c.c)
PROTO_PY_OUT = $(dist_noinst_DATA:.proto=_pb2.py)
BUILT_SOURCES  = $(PROTO_C_OUT) $(PROTO_PY_OUT)

SUFFIXES = .dep .proto _pb2.py .pb-c.c

.proto.dep:
	$(AM_V_at) $(GREP) import $< |					\
		$(SED) 's/import "/$(subst .dep,,$@).pb-c.c: /; s/proto";/pb-c.c/' > $@

.pb-c.c_pb2.py:

.proto_pb2.py:
	$(AM_V_GEN) protoc -I=. --python_out=. $<

.proto.pb-c.c:
	$(AM_V_GEN) protoc-c -I=. --c_out=. $<

CLEANFILES = $(BUILT_SOURCES) $(PROTO_C_OUT:.c=.h) $(PROTO_C_OUT:.c=.o) $(PROTO_PY_OUT:.py=.pyc) $(DEPS)
