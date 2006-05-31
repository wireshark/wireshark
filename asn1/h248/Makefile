# $Id$

DISSECTOR_FILES=packet-h248.c packet-h248.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py MEGACO.asn packet-h248-template.c packet-h248-template.h h248.cnf 
	python ../../tools/asn2wrs.py -b -e -p h248 -c h248.cnf -s packet-h248-template MEGACO.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES) *-fn.c *-ett.c *-hf.c

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
