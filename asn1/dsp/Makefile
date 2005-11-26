# $Id$

DISSECTOR_FILES=packet-dsp.c packet-dsp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py dsp.asn packet-dsp-template.c packet-dsp-template.h dsp.cnf ../x411/x411-exp.cnf
	python ../../tools/asn2eth.py -X -b -e -p dsp -c dsp.cnf -s packet-dsp-template  dsp.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *~

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

