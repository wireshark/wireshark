# $Id$

DISSECTOR_FILES=packet-rnsap.c

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py rnsap.asn packet-rnsap-template.c rnsap.cnf
	python ../../tools/asn2wrs.py -p rnsap -c rnsap.cnf -s packet-rnsap-template  RNSAP-CommonDataTypes.asn RNSAP-Constants.asn RNSAP-Containers.asn RNSAP-IEs.asn RNSAP-PDU-Contents.asn RNSAP-PDU-Descriptions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

