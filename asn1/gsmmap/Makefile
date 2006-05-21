# $Id$

DISSECTOR_FILES=packet-gsm_map.c packet-gsm_map.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py GSMMAP.asn packet-gsm_map-template.c packet-gsm_map-template.h gsmmap.cnf 
	python ../../tools/asn2wrs.py -b -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
