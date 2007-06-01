# $Id$

DISSECTOR_FILES=packet-inap.c packet-inap.h
ASN_FILE_LIST=inap.asn IN-CS-1-Datatypes.asn IN-CS-1-Datatypes-appendix.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-inap-template.c packet-inap-template.h inap.cnf 
	python ../../tools/asn2wrs.py -b -X -e -p inap -c inap.cnf -s packet-inap-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
