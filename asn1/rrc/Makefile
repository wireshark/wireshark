# $Id$

DISSECTOR_FILES=packet-rrc.c
RRC_ASN=Class-definitions.asn PDU-definitions.asn InformationElements.asn Constant-definitions.asn Internode-definitions.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(RRC_ASN) packet-rrc-template.c rrc.cnf
	python ../../tools/asn2wrs.py -p rrc -c rrc.cnf -s packet-rrc-template $(RRC_ASN)

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

