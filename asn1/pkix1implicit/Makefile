# $Id$

DISSECTOR_FILES=packet-pkix1implicit.c packet-pkix1implicit.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKIX1IMPLICIT93.asn packet-pkix1implicit-template.c packet-pkix1implicit-template.h pkix1implicit.cnf
	python ../../tools/asn2wrs.py -e -b -p pkix1implicit -c pkix1implicit.cnf -s packet-pkix1implicit-template PKIX1IMPLICIT93.asn 

clean:
	rm -f pkix1implicit-exp.cnf parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
