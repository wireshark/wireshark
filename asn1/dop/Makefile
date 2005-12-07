# $Id$

DISSECTOR_FILES=packet-dop.c packet-dop.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

ASN_EXPORTS=		

$(DISSECTOR_FILES): ../../tools/asn2eth.py dop.asn packet-dop-template.c packet-dop-template.h dop.cnf $(ASN_EXPORTS)
	python ../../tools/asn2eth.py -X -b -e -p dop -c dop.cnf -s packet-dop-template  dop.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

