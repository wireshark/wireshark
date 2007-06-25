# $Id$

DISSECTOR_FILES=packet-x420.c packet-x420.h

ASN_FILE_LIST=x420.asn ftbp.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-x420-template.c packet-x420-template.h x420.cnf
	python ../../tools/asn2wrs.py -b -e -p x420 -c x420.cnf -s packet-x420-template $(ASN_FILE_LIST) 

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

