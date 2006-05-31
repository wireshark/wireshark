# $Id$

DISSECTOR_FILES=packet-wlancertextn.c packet-wlancertextn.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py WLANCERTEXTN.asn packet-wlancertextn-template.c packet-wlancertextn-template.h wlancertextn.cnf
	python ../../tools/asn2wrs.py -b -e -p wlancertextn -c wlancertextn.cnf -s packet-wlancertextn-template WLANCERTEXTN.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
