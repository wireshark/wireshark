# $Id$

DISSECTOR_FILES=packet-h450.c packet-h450.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py h4501.asn packet-h450-template.c packet-h450-template.h h450.cnf
	python ../../tools/asn2wrs.py -e -p h450 -c h450.cnf -s packet-h450-template h4501.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
