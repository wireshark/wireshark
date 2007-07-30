# $Id$

H450_FILES=packet-$(PROTOCOL_NAME).c
H450_ROS_FILES=packet-$(PROTOCOL_NAME)-ros.c packet-$(PROTOCOL_NAME)-ros.h
DISSECTOR_FILES=$(H450_FILES) $(H450_ROS_FILES)
H450_ASN=H4501-Supplementary-ServiceAPDU-Structure.asn Addressing-Data-Elements.asn H225-generic-parameters-definition.asn Manufacturer-specific-service-extension-definition.asn H4501-General-Error-List.asn
H450_OP_ASN=Call-Transfer-Operations.asn Call-Diversion-Operations.asn Call-Hold-Operations.asn Call-Park-Pickup-Operations.asn Call-Waiting-Operations.asn Message-Waiting-Indication-Operations.asn Name-Operations.asn Call-Completion-Operations.asn Call-Offer-Operations.asn Call-Intrusion-Operations.asn Common-Information-Operations.asn 
H450_ROS_ASN=../ros/Remote-Operations-Information-Objects.asn Remote-Operations-Apdus.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(H450_FILES): ../../tools/asn2wrs.py $(H450_ASN) $(H450_OP_ASN) packet-h450-template.c packet-h450-template.h h450.cnf
	python ../../tools/asn2wrs.py -c $(PROTOCOL_NAME).cnf -s packet-$(PROTOCOL_NAME)-template $(H450_ASN) $(H450_OP_ASN)

$(H450_ROS_FILES): ../../tools/asn2wrs.py $(H450_ROS_ASN) packet-$(PROTOCOL_NAME)-ros-template.c $(PROTOCOL_NAME)-ros.cnf
	python ../../tools/asn2wrs.py -e -p $(PROTOCOL_NAME).ros -c $(PROTOCOL_NAME)-ros.cnf -o $(PROTOCOL_NAME)-ros -s packet-$(PROTOCOL_NAME)-ros-template $(H450_ROS_ASN)
clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
