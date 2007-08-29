# $Id$

DISSECTOR_FILES=packet-ranap.c packet-ranap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ranap.asn packet-ranap-template.c packet-ranap-template.h ranap.cnf
	python ../../tools/asn2wrs.py -p ranap -c ranap.cnf -s packet-ranap-template  RANAP-CommonDataTypes.asn RANAP-Constants.asn RANAP-Containers.asn RANAP-IEs.asn RANAP-PDU-Contents.asn RANAP-PDU-Descriptions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

