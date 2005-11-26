# $Id$

DISSECTOR_FILES=packet-x501.c packet-x501.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

ASN_EXPORTS=		

$(DISSECTOR_FILES): ../../tools/asn2eth.py x501.asn packet-x501-template.c packet-x501-template.h x501.cnf $(ASN_EXPORTS)
	python ../../tools/asn2eth.py -X -b -e -p x501 -c x501.cnf -s packet-x501-template  x501.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

