# $Id$

DISSECTOR_FILES=packet-x420.c packet-x420.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py x420.asn packet-x420-template.c packet-x420-template.h x420.cnf
	python ../../tools/asn2eth.py -X -b -e -p x420 -c x420.cnf -s packet-x420-template  x420.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

