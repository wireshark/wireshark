# $Id$

DISSECTOR_FILES=packet-x411.c packet-x411.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py x411.asn packet-x411-template.c packet-x411-template.h x411.cnf
	python ../../tools/asn2wrs.py -b -e -p x411 -c x411.cnf -s packet-x411-template  x411.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

