# Make sure, that check for header happens _after_ source generation
dist_noinst_DATA = funcpatch.proto	\
		   binpatch.proto	\
		   objinfo.proto	\
		   relaplt.proto	\
		   segment.proto	\
		   datasym.proto

DEPS	= $(dist_noinst_DATA:.proto=.dep)

-include $(DEPS)

BUILT_SOURCES  = $(dist_noinst_DATA:.proto=.pb-c.c) $(dist_noinst_DATA:.proto=_pb2.py)

SUFFIXES = .dep .proto _pb2.py .pb-c.c

.proto.dep:
	$(AM_V_at) $(GREP) import $< |					\
		$(SED) 's/import "/$(subst .dep,,$@).pb-c.c: /; s/proto";/pb-c.c/' > $@

.pb-c.c_pb2.py:

.proto_pb2.py:
	$(AM_V_GEN) protoc -I=. --python_out=. $<

.proto.pb-c.c:
	$(AM_V_GEN) protoc-c -I=. --c_out=. $<

CLEANFILES = $(BUILT_SOURCES) $(BUILT_SOURCES:.c=.h) $(DEPS)
