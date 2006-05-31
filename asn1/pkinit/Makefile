# $Id$

DISSECTOR_FILES=packet-pkinit.c packet-pkinit.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKINIT.asn packet-pkinit-template.c packet-pkinit-template.h pkinit.cnf
	python ../../tools/asn2wrs.py -e -b -p pkinit -c pkinit.cnf -s packet-pkinit-template PKINIT.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
