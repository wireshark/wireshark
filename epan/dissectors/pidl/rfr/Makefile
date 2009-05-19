all: packet-dcerpc-rfr.c packet-dcerpc-rfr.h

packet-dcerpc-rfr.c packet-dcerpc-rfr.h: rfr.idl rfr.cnf mapicodes_enum.h ../idl_types.h
	../../../../tools/pidl/pidl --includedir=.. --ws-parser -- rfr.idl

clean:
	rm -f packet-dcerpc-rfr.c packet-dcerpc-rfr.h idl_types.h

install: packet-dcerpc-rfr.c packet-dcerpc-rfr.h
	cp packet-dcerpc-rfr.c packet-dcerpc-rfr.h ../../
