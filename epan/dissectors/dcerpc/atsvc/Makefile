# $Id$

DISSECTOR_FILES=packet-dcerpc-atsvc.c packet-dcerpc-atsvc.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../idl2eth atsvc.idl atsvc.cnf template.c template.h 
	../idl2eth atsvc

clean:
	rm -f ETH_* $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../..
