# $Id$

DISSECTOR_FILES=packet-logotypecertextn.c packet-logotypecertextn.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py LogotypeCertExtn.asn packet-logotype-cert-extn-template.c packet-logotype-cert-extn-template.h logotype-cert-extn.cnf
	python ../../tools/asn2wrs.py -b -e -p logotypecertextn -c logotype-cert-extn.cnf -s packet-logotype-cert-extn-template LogotypeCertExtn.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
