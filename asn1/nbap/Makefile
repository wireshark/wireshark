# $Id$

DISSECTOR_FILES=packet-nbap.c

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py nbap.asn packet-nbap-template.c nbap.cnf
	python ../../tools/asn2wrs.py -p nbap -c nbap.cnf -s packet-nbap-template  NBAP-CommonDataTypes.asn NBAP-Constants.asn NBAP-Containers.asn NBAP-IEs.asn NBAP-PDU-Contents.asn NBAP-PDU-Descriptions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

