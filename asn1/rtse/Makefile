# $Id$

DISSECTOR_FILES=packet-rtse.c packet-rtse.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py rtse.asn packet-rtse-template.c packet-rtse-template.h rtse.cnf
	python ../../tools/asn2eth.py -X -b -e -p rtse -c rtse.cnf -s packet-rtse-template  rtse.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

