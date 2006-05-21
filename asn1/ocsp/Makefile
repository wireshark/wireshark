# $Id$

DISSECTOR_FILES=packet-ocsp.c packet-ocsp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py OCSP.asn packet-ocsp-template.c packet-ocsp-template.h ocsp.cnf
	python ../../tools/asn2wrs.py -b -e -p ocsp -c ocsp.cnf -s packet-ocsp-template OCSP.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
