# $Id$

DISSECTOR_FILES=packet-ulp.c

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py ULP.asn SUPL.asn ULP-Components.asn packet-ulp-template.c ulp.cnf
	python ../../tools/asn2wrs.py -p ulp -c ulp.cnf -s packet-ulp-template  ULP.asn SUPL.asn ULP-Components.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

