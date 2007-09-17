# $Id$

PROTOCOL_NAME=ranap
DISSECTOR_FILES=packet-ranap.c packet-ranap.h
RANAP_ASN=RANAP-CommonDataTypes.asn RANAP-Constants.asn RANAP-Containers.asn RANAP-IEs.asn RANAP-PDU-Contents.asn RANAP-PDU-Descriptions.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(RANAP_ASN) packet-ranap-template.c packet-ranap-template.h ranap.cnf
	python ../../tools/asn2wrs.py -p ranap -c ranap.cnf -s packet-ranap-template $(RANAP_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

