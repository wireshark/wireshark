PROTOCOL_NAME=mapi

all: packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h

packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h: $(PROTOCOL_NAME).idl \
						$(PROTOCOL_NAME).cnf 		\
						request.cnf.c		\
						response.cnf.c		\
						mapicodes_enum.h  	\
						mapitags_enum.h 	\
						../idl_types.h
	../../../../tools/pidl/pidl --verbose --includedir=.. --ws-parser -- $(PROTOCOL_NAME).idl

clean:
	rm -f packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h idl_types.h

install: packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h
	cp packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h ../../
