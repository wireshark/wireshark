# $Id$

DISSECTOR_FILES=packet-cmp.c packet-cmp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py CMP.asn packet-cmp-template.c packet-cmp-template.h cmp.cnf 
	python ../../tools/asn2eth.py -X -b -e -p cmp -c cmp.cnf -s packet-cmp-template CMP.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
