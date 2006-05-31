# $Id$

PROTOCOL_NAME=cdt
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(PROTOCOL_NAME).asn packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h $(PROTOCOL_NAME).cnf 
	python ../../tools/asn2wrs.py -b -e -p $(PROTOCOL_NAME) -c $(PROTOCOL_NAME).cnf -s packet-$(PROTOCOL_NAME)-template $(PROTOCOL_NAME).asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
