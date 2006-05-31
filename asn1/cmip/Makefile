# $Id$

DISSECTOR_FILES=packet-cmip.c packet-cmip.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py CMIP.asn packet-cmip-template.c packet-cmip-template.h cmip.cnf 
	python ../../tools/asn2wrs.py -b -e -p cmip -c cmip.cnf -s packet-cmip-template CMIP.asn

clean:
	rm -f cmip-exp.cnf parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
