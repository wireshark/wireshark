# $Id$

DISSECTOR_FILES=packet-umts_rrc.c packet-umts_rrc.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py umts_rrc_Internode-definitions.asn packet-umts_rrc_internode-defs-template.c packet-umts_rrc_internode-defs-template.h umts_rrc_internode-defs.cnf
	python ../../tools/asn2eth.py -X -e -p umts_rrc_internode-defs -c umts_rrc_internode-defs.cnf -s packet-umts_rrc_internode-defs-template  umts_rrc_Internode-definitions.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

