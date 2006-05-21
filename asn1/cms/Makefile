# $Id$

DISSECTOR_FILES=packet-cms.c packet-cms.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py CryptographicMessageSyntax.asn packet-cms-template.c packet-cms-template.h cms.cnf
	python ../../tools/asn2wrs.py -b -e -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
