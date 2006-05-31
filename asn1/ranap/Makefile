# $Id$

DISSECTOR_FILES=packet-ranap.c packet-ranap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-ranap-template.c packet-ranap-template.h ranap.cnf
	python ../../tools/asn2wrs.py -e -p ranap -c ranap.cnf -s packet-ranap-template ranap.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
