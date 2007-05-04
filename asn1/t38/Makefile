# $Id$

DISSECTOR_FILES=packet-t38.c packet-t38.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-t38-template.c packet-t38-template.h t38.cnf
	python ../../tools/asn2wrs.py -p t38 -c t38.cnf -s packet-t38-template T38(2002).asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
