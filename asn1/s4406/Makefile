# $Id$

DISSECTOR_FILES=packet-s4406.c packet-s4406.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py s4406.asn packet-s4406-template.c packet-s4406-template.h s4406.cnf ../x411/x411-exp.cnf
	python ../../tools/asn2eth.py -X -b -e -p s4406 -c s4406.cnf -s packet-s4406-template  s4406.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

