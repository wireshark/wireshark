# $Id$

PROTOCOL_NAME=nbap
DISSECTOR_FILES=packet-nbap.c
NBAP_ASN=NBAP-CommonDataTypes.asn NBAP-Constants.asn NBAP-Containers.asn NBAP-IEs.asn NBAP-PDU-Contents.asn NBAP-PDU-Descriptions.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(NBAP_ASN) packet-nbap-template.c nbap.cnf
	python ../../tools/asn2wrs.py -p $(PROTOCOL_NAME) -c nbap.cnf -s packet-nbap-template $(NBAP_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

