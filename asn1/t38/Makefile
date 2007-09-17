# $Id$

PROTOCOL_NAME=t38
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h
T38_ASN=T38\(2002\).asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-t38-template.c packet-t38-template.h t38.cnf
	python ../../tools/asn2wrs.py -p $(PROTOCOL_NAME) -c t38.cnf -s packet-t38-template $(T38_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
