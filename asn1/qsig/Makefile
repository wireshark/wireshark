# $Id$

DISSECTOR_FILES=packet-qsig.c packet-qsig.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py packet-qsig-template.c packet-qsig-template.h qsig.cnf
	python ../../tools/asn2wrs.py -b -T -X -e -p qsig -c qsig.cnf -s packet-qsig-template qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn qsig-na.asn qsig-cf.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
