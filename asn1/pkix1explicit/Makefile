# $Id$

DISSECTOR_FILES=packet-pkix1explicit.c packet-pkix1explicit.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKIX1EXPLICIT93.asn packet-pkix1explicit-template.c packet-pkix1explicit-template.h pkix1explicit.cnf
	python ../../tools/asn2wrs.py -e -b -p pkix1explicit -c pkix1explicit.cnf -s packet-pkix1explicit-template PKIX1EXPLICIT93.asn 

clean:
	rm -f pkix1explicit-exp.cnf parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
