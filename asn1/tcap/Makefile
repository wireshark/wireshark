# $Id$

TCAP_FILES=packet-tcap.c packet-tcap.h
ANSI_FILES=packet-ansi_tcap.c packet-ansi_tcap.h
DISSECTOR_FILES=$(TCAP_FILES) $(ANSI_FILES)
TCAP_ASN=tcap.asn
ANSI_ASN=TCAP-Remote-Operations-Information-Objects.asn TCAPPackage.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(TCAP_FILES): ../../tools/asn2wrs.py $(TCAP_ASN) packet-tcap-template.c packet-tcap-template.h tcap.cnf 
	python ../../tools/asn2wrs.py -b -e -p tcap -c tcap.cnf -s packet-tcap-template $(TCAP_ASN)

$(ANSI_FILES): ../../tools/asn2wrs.py $(ANSI_ASN) packet-ansi_tcap-template.c packet-ansi_tcap-template.h ansi_tcap.cnf 
	python ../../tools/asn2wrs.py -b -X -T -e -p ansi_tcap -c ansi_tcap.cnf -s packet-ansi_tcap-template $(ANSI_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
