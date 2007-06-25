# $Id$

PROTOCOL_NAME=cmip
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h
ROS_ASN= ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn 
ASN1_FILES=CMIP-1.asn CMIP-A-ABORT-Information.asn CMIP-A-ASSOCIATE-Information.asn  ../x721/Attribute-ASN1Module.asn $(ROS_ASN)

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN1_FILES) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h cmip.cnf 
	python ../../tools/asn2wrs.py -b -e -p $(PROTOCOL_NAME) -c cmip.cnf -s packet-$(PROTOCOL_NAME)-template $(ASN1_FILES)

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
