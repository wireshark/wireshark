# $Id$

DISSECTOR_FILES=packet-dcerpc-efs.c packet-dcerpc-efs.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2eth efs.idl efs.cnf template.c template.h 
	../idl2eth efs

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
