# $Id$

DISSECTOR_FILES=packet-pkixproxy.c packet-pkixproxy.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py PKIXProxy.asn packet-pkixproxy-template.c packet-pkixproxy-template.h pkixproxy.cnf
	python ../../tools/asn2eth.py -X -b -e -p pkixproxy -c pkixproxy.cnf -s packet-pkixproxy-template PKIXProxy.asn

clean:
	rm -f pkix1explicit-exp.cnf parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
