# $Id$

PROTOCOL_NAME=ansi_map
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ansi_map.asn packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h ansi_map.cnf
	python ../../tools/asn2wrs.py -b -X -e -p $(PROTOCOL_NAME) -c ansi_map.cnf -s packet-$(PROTOCOL_NAME)-template ansi_map.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

