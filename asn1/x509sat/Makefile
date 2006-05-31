# $Id$

DISSECTOR_FILES=packet-x509sat.c packet-x509sat.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py SelectedAttributeTypes.asn packet-x509sat-template.c packet-x509sat-template.h x509sat.cnf ../x509if/x509if-exp.cnf
	python ../../tools/asn2wrs.py -b -e -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn
	sed -e "s/\([\"\.]\)Syntax/\1/g" -i.orig packet-x509sat.c

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
