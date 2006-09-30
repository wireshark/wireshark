# $Id$

DISSECTOR_FILES=packet-umts_rrc_ies.c packet-umts_rrc_ies.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py umts_rrc_InformationElements.asn packet-umts_rrc_ies-template.c packet-umts_rrc_ies-template.h umts_rrc_ies.cnf
	python ../../tools/asn2wrs.py -X -e -p umts_rrc_ies -c umts_rrc_ies.cnf -s packet-umts_rrc_ies-template  umts_rrc_InformationElements.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

