# $Id$

DISSECTOR_FILES=packet-ansi_map.c packet-ansi_map.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ansi_map.asn packet-ansi_map-template.c packet-ansi_map-template.h ansi_map.cnf
	python ../../tools/asn2wrs.py -b -e -p ansi_map -c ansi_map.cnf -s packet-ansi_map-template ansi_map.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

