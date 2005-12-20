# $Id$

DISSECTOR_FILES=packet-rnsap.c packet-rnsap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py rnsap.asn packet-rnsap-template.c packet-rnsap-template.h rnsap.cnf
	python ../../tools/asn2eth.py -X -e -p rnsap -c rnsap.cnf -s packet-rnsap-template  rnsap.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

