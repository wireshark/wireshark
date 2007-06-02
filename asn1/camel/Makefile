# $Id$

PROTOCOL_NAME=camel
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h
ASN_FILE_LIST=camel.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h camel.cnf 
	python ../../tools/asn2wrs.py -b -e -p camel -c camel.cnf -s packet-$(PROTOCOL_NAME)-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
