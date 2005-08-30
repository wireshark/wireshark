# $Id: Makefile 15178 2005-08-02 05:21:19Z jmayer $

DISSECTOR_FILES=packet-pres.c packet-pres.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py ISO8823-PRESENTATION.asn packet-pres-template.c packet-pres-template.h pres.cnf
	python ../../tools/asn2eth.py -X -b -e -p pres -c pres.cnf -s packet-pres-template ISO8823-PRESENTATION.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

