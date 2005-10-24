# $Id$

DISSECTOR_FILES=packet-nbap.c packet-nbap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py nbap.asn packet-nbap-template.c packet-nbap-template.h nbap.cnf
	python ../../tools/asn2eth.py -X -e -p nbap -c nbap.cnf -s packet-nbap-template  nbap.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

