# $Id$

DISSECTOR_FILES=packet-ldap.c packet-ldap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py Lightweight-Directory-Access-Protocol-V3.asn packet-ldap-template.c packet-ldap-template.h ldap.cnf $(ASN_EXPORTS)
	python ../../tools/asn2wrs.py -b -e -p ldap -c ldap.cnf -s packet-ldap-template Lightweight-Directory-Access-Protocol-V3.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
