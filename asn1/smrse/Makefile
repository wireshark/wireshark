# $Id$

DISSECTOR_FILES=packet-smrse.c packet-smrse.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py SMRSE.asn packet-smrse-template.c packet-smrse-template.h smrse.cnf 
	python ../../tools/asn2wrs.py -b -e -p smrse -c smrse.cnf -s packet-smrse-template SMRSE.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
