# $Id$

DISSECTOR_FILES=packet-ns_cert_exts.c packet-ns_cert_exts.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py NETSCAPE-CERT-EXTS.asn packet-ns_cert_exts-template.c packet-ns_cert_exts-template.h ns_cert_exts.cnf 
	python ../../tools/asn2wrs.py -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
