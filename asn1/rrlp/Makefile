# $Id$

DISSECTOR_FILES=packet-rrlp.c
RRLP_ASN=RRLP-Messages.asn RRLP-Components.asn ../gsmmap/MAP-ExtensionDataTypes.asn ../gsmmap/MAP-LCS-DataTypes.asn 

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(RRLP_ASN) packet-rrlp-template.c rrlp.cnf
	python ../../tools/asn2wrs.py -p rrlp -c rrlp.cnf -s packet-rrlp-template $(RRLP_ASN)

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

