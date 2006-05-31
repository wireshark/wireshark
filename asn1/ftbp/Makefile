# $Id$

DISSECTOR_FILES=packet-ftbp.c packet-ftbp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ftbp.asn packet-ftbp-template.c packet-ftbp-template.h ftbp.cnf 
	python ../../tools/asn2wrs.py -b -e -p ftbp -c ftbp.cnf -s packet-ftbp-template  ftbp.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

