# $Id$

DISSECTOR_FILES=packet-h225.c packet-h225.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py h225.asn packet-h225-template.c packet-h225-template.h h225.cnf 
	python ../../tools/asn2wrs.py -e -p h225 -c h225.cnf -s packet-h225-template h225.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
