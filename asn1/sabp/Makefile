# $Id$

DISSECTOR_FILES=packet-sabp.c

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py sabp.asn packet-sabp-template.c sabp.cnf
	python ../../tools/asn2wrs.py -p sabp -c sabp.cnf -s packet-sabp-template  SABP-CommonDataTypes.asn SABP-Constants.asn SABP-Containers.asn SABP-IEs.asn SABP-PDU-Contents.asn SABP-PDU-Descriptions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

