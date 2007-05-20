# $Id$

DISSECTOR_FILES=packet-MAP_DialoguePDU.c packet-MAP_DialoguePDU.h
MAP_DIALOUGE_PDU_ASN=MAP-DialogueInformation.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(MAP_DIALOUGE_PDU_ASN) packet-MAP-DialoguePDU-template.c packet-MAP-DialoguePDU-template.h MAP_DialoguePDU.cnf
	python ../../tools/asn2wrs.py -b -e -p MAP_DialoguePDU -c MAP_DialoguePDU.cnf -s packet-MAP-DialoguePDU-template $(MAP_DIALOUGE_PDU_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
