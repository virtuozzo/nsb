PYTHON_PROTOBUF = funcpatch_pb2.py

SUFFIXES = .proto _pb2.py

.proto_pb2.py:
	@echo "  GEN     " $@
	@protoc -I=. --python_out=. $<

all: $(PYTHON_PROTOBUF)

clean:
	rm -f $(PYTHON_PROTOBUF)
