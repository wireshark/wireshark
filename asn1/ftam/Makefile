# $Id$

DISSECTOR_FILES=packet-ftam.c packet-ftam.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ISO8571-FTAM.asn packet-ftam-template.c packet-ftam-template.h ftam.cnf
	python ../../tools/asn2wrs.py -b -e -p ftam -c ftam.cnf -s packet-ftam-template ISO8571-FTAM.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

