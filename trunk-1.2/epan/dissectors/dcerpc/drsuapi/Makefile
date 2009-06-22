# $Id$

DISSECTOR_FILES=packet-dcerpc-drsuapi.c packet-dcerpc-drsuapi.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2wrs drsuapi.idl drsuapi.cnf template.c template.h 
	../idl2wrs drsuapi

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
