# $Id$

DISSECTOR_FILES=packet-disp.c packet-disp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py disp.asn packet-disp-template.c packet-disp-template.h disp.cnf
	python ../../tools/asn2wrs.py -b -e -p disp -c disp.cnf -s packet-disp-template  disp.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

