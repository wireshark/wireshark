# $Id$

DISSECTOR_FILES=packet-x509if.c packet-x509if.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py InformationFramework.asn packet-x509if-template.c packet-x509if-template.h x509if.cnf ../x509sat/x509sat-exp.cnf
	python ../../tools/asn2wrs.py -b -e -p x509if -c x509if.cnf -s packet-x509if-template InformationFramework.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
