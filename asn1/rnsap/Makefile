# $Id$

PROTOCOL_NAME=rnsap
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c
RNSAP_ASN=RNSAP-CommonDataTypes.asn RNSAP-Constants.asn RNSAP-Containers.asn RNSAP-IEs.asn RNSAP-PDU-Contents.asn RNSAP-PDU-Descriptions.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(RNSAP_ASN) packet-rnsap-template.c rnsap.cnf
	python ../../tools/asn2wrs.py -p $(PROTOCOL_NAME) -c rnsap.cnf -s packet-rnsap-template $(RNSAP_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

