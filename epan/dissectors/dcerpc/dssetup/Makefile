# $Id$

DISSECTOR_FILES=packet-dcerpc-dssetup.c packet-dcerpc-dssetup.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2eth dssetup.idl dssetup.cnf template.c template.h 
	../idl2eth dssetup

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
