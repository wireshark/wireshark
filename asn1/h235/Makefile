# $Id$

DISSECTOR_FILES=packet-h235.c packet-h235.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-h235-template.c packet-h235-template.h h235.cnf
	python ../../tools/asn2wrs.py -p h235 -c h235.cnf -s packet-h235-template H235-SECURITY-MESSAGES.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
