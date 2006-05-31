# $Id$

DISSECTOR_FILES=packet-crmf.c packet-crmf.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py CRMF.asn packet-crmf-template.c packet-crmf-template.h crmf.cnf 
	python ../../tools/asn2wrs.py -b -e -p crmf -c crmf.cnf -s packet-crmf-template CRMF.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
