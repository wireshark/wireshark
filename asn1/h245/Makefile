# $Id$

DISSECTOR_FILES=packet-h245.c packet-h245.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-h245-template.c packet-h245-template.h h245.cnf
	python ../../tools/asn2wrs.py -e -p h245 -c h245.cnf -s packet-h245-template h245.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
