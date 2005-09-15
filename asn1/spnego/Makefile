# $Id$

DISSECTOR_FILES=packet-spnego.c packet-spnego.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py spnego.asn packet-spnego-template.c packet-spnego-template.h spnego.cnf
	python ../../tools/asn2eth.py -X -b -e -p spnego -c spnego.cnf -s packet-spnego-template spnego.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

