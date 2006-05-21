# $Id$

DISSECTOR_FILES=packet-mms.c packet-mms.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py mms.asn packet-mms-template.c packet-mms-template.h mms.cnf
	python ../../tools/asn2wrs.py -b -e -p mms -c mms.cnf -s packet-mms-template mms.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

