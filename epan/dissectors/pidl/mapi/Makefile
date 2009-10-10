all: packet-dcerpc-mapi.c packet-dcerpc-mapi.h

packet-dcerpc-mapi.c packet-dcerpc-mapi.h: 	mapi.idl 		\
						mapi.cnf 		\
						request.cnf.c		\
						response.cnf.c		\
						mapicodes_enum.h  	\
						mapitags_enum.h 	\
						../idl_types.h
	../../../../tools/pidl/pidl --verbose --includedir=.. --ws-parser -- mapi.idl

clean:
	rm -f packet-dcerpc-mapi.c packet-dcerpc-mapi.h idl_types.h

install: packet-dcerpc-mapi.c packet-dcerpc-mapi.h
	cp packet-dcerpc-mapi.c packet-dcerpc-mapi.h ../../
