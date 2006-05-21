# $Id$

DISSECTOR_FILES=packet-pkixtsp.c packet-pkixtsp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKIXTSP.asn packet-pkixtsp-template.c packet-pkixtsp-template.h pkixtsp.cnf
	python ../../tools/asn2wrs.py -b -e -p pkixtsp -c pkixtsp.cnf -s packet-pkixtsp-template PKIXTSP.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
