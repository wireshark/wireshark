# $Id$

DISSECTOR_FILES=packet-dcerpc-butc.c packet-dcerpc-butc.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2wrs butc.idl butc.cnf template.c template.h 
	../idl2wrs butc

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
