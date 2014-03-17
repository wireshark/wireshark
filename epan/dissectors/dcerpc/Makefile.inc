IDL2WRS=../idl2wrs

DISSECTOR_FILES=packet-dcerpc-$(PROTOCOL_NAME).c packet-dcerpc-$(PROTOCOL_NAME).h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): $(IDL2WRS) $(PROTOCOL_NAME).idl $(PROTOCOL_NAME).cnf packet-dcerpc-$(PROTOCOL_NAME)-template.c packet-dcerpc-$(PROTOCOL_NAME)-template.h
	$(IDL2WRS) $(PROTOCOL_NAME)

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
