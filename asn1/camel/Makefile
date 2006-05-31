# $Id$

DISSECTOR_FILES=packet-camel.c packet-camel.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py camel.asn packet-camel-template.c packet-camel-template.h camel.cnf 
	python ../../tools/asn2wrs.py -b -e -p camel -c camel.cnf -s packet-camel-template camel.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
