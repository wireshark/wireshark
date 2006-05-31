# $Id$

DISSECTOR_FILES=packet-gsm_ss.c packet-gsm_ss.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py SS-Operations.asn packet-gsm_ss-template.c packet-gsm_ss-template.h gsm_ss.cnf
	python ../../tools/asn2wrs.py -b -e -p gsm_ss -c gsm_ss.cnf -s packet-gsm_ss-template SS-Operations.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
