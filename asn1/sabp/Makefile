# $Id$

PROTOCOL_NAME=sabp
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c
SABP_ASN=SABP-CommonDataTypes.asn SABP-Constants.asn SABP-Containers.asn SABP-IEs.asn SABP-PDU-Contents.asn SABP-PDU-Descriptions.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(SABP_ASN) packet-sabp-template.c sabp.cnf
	python ../../tools/asn2wrs.py -p $(PROTOCOL_NAME) -c sabp.cnf -s packet-sabp-template $(SABP_ASN) 

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

