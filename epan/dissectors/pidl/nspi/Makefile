all: packet-dcerpc-nspi.c packet-dcerpc-nspi.h

idl_types.h: ../idl_types.h
	cp ../idl_types.h idl_types.h

packet-dcerpc-nspi.c packet-dcerpc-nspi.h: nspi.idl nspi.cnf mapicodes_enum.h  mapitags_enum.h idl_types.h
	../../../../tools/pidl/pidl --ws-parser -- nspi.idl

clean:
	rm -f packet-dcerpc-nspi.c packet-dcerpc-nspi.h idl_types.h

install: packet-dcerpc-nspi.c packet-dcerpc-nspi.h
	cp packet-dcerpc-nspi.c packet-dcerpc-nspi.h ../../
