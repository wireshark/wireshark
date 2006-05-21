# $Id$

DISSECTOR_FILES=packet-acse.c packet-acse.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py acse.asn packet-acse-template.c packet-acse-template.h acse.cnf
	python ../../tools/asn2wrs.py -b -e -p acse -c acse.cnf -s packet-acse-template acse.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

