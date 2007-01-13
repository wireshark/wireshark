# $Id$

DISSECTOR_FILES=packet-pkcs12.c packet-pkcs12.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py pkcs12.asn packet-pkcs12-template.c packet-pkcs12-template.h pkcs12.cnf ../cms/cms-exp.cnf ../x509af/x509af-exp.cnf ../x509if/x509if-exp.cnf
	python ../../tools/asn2wrs.py -b -e -p pkcs12 -c pkcs12.cnf -s packet-pkcs12-template pkcs12.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
