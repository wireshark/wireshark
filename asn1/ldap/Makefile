# $Id$

DISSECTOR_FILES=packet-ldap.c packet-ldap.h
ASN_FILE_LIST=Lightweight-Directory-Access-Protocol-V3.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-ldap-template.c packet-ldap-template.h ldap.cnf $(ASN_EXPORTS)
	python ../../tools/asn2wrs.py -b -X -e -p ldap -c ldap.cnf -s packet-ldap-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
