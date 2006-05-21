# $Id$

DISSECTOR_FILES=packet-x509ce.c packet-x509ce.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py CertificateExtensions.asn packet-x509ce-template.c packet-x509ce-template.h x509ce.cnf ../x509if/x509if-exp.cnf ../x509sat/x509sat-exp.cnf ../x509af/x509af-exp.cnf
	python ../../tools/asn2wrs.py -b -e -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
