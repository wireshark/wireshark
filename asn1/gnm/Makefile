# $Id$

DISSECTOR_FILES=packet-gnm.c packet-gnm.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py GNM.asn packet-gnm-template.c packet-gnm-template.h gnm.cnf
	python ../../tools/asn2eth.py -X -b -e -p gnm -c gnm.cnf -s packet-gnm-template GNM.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
