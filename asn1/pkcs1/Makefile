# $Id$

DISSECTOR_FILES=packet-pkcs1.c packet-pkcs1.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py PKCS1.asn packet-pkcs1-template.c packet-pkcs1-template.h pkcs1.cnf
	python ../../tools/asn2wrs.py -b -p pkcs1 -c pkcs1.cnf -s packet-pkcs1-template PKCS1.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
