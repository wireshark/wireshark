# $Id$

DISSECTOR_FILES=packet-tcap.c packet-tcap.h
TCAP_ASN=tcap.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(TCAP_ASN) packet-tcap-template.c packet-tcap-template.h tcap.cnf 
	python ../../tools/asn2wrs.py -b -e -p tcap -c tcap.cnf -s packet-tcap-template $(TCAP_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
