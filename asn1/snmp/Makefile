# $Id$

DISSECTOR_FILES=packet-snmp.c packet-snmp.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py snmp.asn packet-snmp-template.c packet-snmp-template.h snmp.cnf
	python ../../tools/asn2wrs.py -b -e -p snmp -c snmp.cnf -s packet-snmp-template snmp.asn

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
