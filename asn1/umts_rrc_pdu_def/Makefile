# $Id$

DISSECTOR_FILES=packet-umts_rrc_pdu_def.c packet-umts_rrc_pdu_def.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py umts_rrc_PDU_definitions.asn packet-umts_rrc_pdu_def-template.c packet-umts_rrc_pdu_def-template.h umts_rrc_pdu_def.cnf
	python ../../tools/asn2eth.py -X -e -p umts_rrc_pdu_def -c umts_rrc_pdu_def.cnf -s packet-umts_rrc_pdu_def-template  umts_rrc_PDU_definitions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

