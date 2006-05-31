# $Id$

DISSECTOR_FILES=packet-pkixqualified.c packet-pkixqualified.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKIXqualified.asn packet-pkixqualified-template.c packet-pkixqualified-template.h pkixqualified.cnf
	python ../../tools/asn2wrs.py -b -e -p pkixqualified -c pkixqualified.cnf -s packet-pkixqualified-template PKIXqualified.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
