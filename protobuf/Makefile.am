noinst_SCRIPTS = funcpatch_pb2.py
CLEANFILES = $(noinst_SCRIPTS)
EXTRA_DIST = funcpatch.proto

SUFFIXES = .proto _pb2.py

.proto_pb2.py:
	$(AM_V_GEN) protoc -I=. --python_out=. $<
	$(AM_V_at) cp $@ ../patchgen
