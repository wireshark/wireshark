# $Id$

DISSECTOR_FILES=packet-dcerpc-budb.c packet-dcerpc-budb.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2wrs budb.idl budb.cnf template.c template.h 
	../idl2wrs budb

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
