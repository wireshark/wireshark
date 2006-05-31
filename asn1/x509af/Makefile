# $Id$

DISSECTOR_FILES=packet-x509af.c packet-x509af.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py AuthenticationFramework.asn packet-x509af-template.c packet-x509af-template.h x509af.cnf ../x509if/x509if-exp.cnf ../x509sat/x509sat-exp.cnf ../x509ce/x509ce-exp.cnf
	python ../../tools/asn2wrs.py -b -e -p x509af -c x509af.cnf -s packet-x509af-template AuthenticationFramework.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
