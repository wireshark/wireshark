# $Id: Makefile 15679 2005-09-04 16:22:12Z etxrab $

DISSECTOR_FILES=packet-acp133.c packet-acp133.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py acp133.asn packet-acp133-template.c packet-acp133-template.h acp133.cnf
	python ../../tools/asn2eth.py -X -b -e -p acp133 -c acp133.cnf -s packet-acp133-template  acp133.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

