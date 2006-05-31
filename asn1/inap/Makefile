# $Id$

DISSECTOR_FILES=packet-inap.c packet-inap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py inap.asn packet-inap-template.c packet-inap-template.h inap.cnf 
	python ../../tools/asn2wrs.py -b -e -p inap -c inap.cnf -s packet-inap-template inap.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
