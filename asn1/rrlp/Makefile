# $Id$

DISSECTOR_FILES=packet-rrlp.c packet-rrlp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py rrlp.asn packet-rrlp-template.c packet-rrlp-template.h rrlp.cnf
	python ../../tools/asn2wrs.py -e -p rrlp -c rrlp.cnf -s packet-rrlp-template  rrlp.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

