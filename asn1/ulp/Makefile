# $Id$

DISSECTOR_FILES=packet-ulp.c packet-ulp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ULP.asn packet-ulp-template.c packet-ulp-template.h ulp.cnf
	python ../../tools/asn2wrs.py -e -p ulp -c ulp.cnf -s packet-ulp-template  ULP.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

