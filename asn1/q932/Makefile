# $Id$

PROTOCOL_NAME=q932
Q932_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h 
Q932_ROS_FILES=packet-$(PROTOCOL_NAME)-ros.c packet-$(PROTOCOL_NAME)-ros.h 
DISSECTOR_FILES=$(Q932_FILES) $(Q932_ROS_FILES)
Q932_ASN=Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(Q932_FILES): ../../tools/asn2wrs.py $(Q932_ASN) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h $(PROTOCOL_NAME).cnf
	python ../../tools/asn2wrs.py -b -T -X -e -p $(PROTOCOL_NAME) -c $(PROTOCOL_NAME).cnf -s packet-$(PROTOCOL_NAME)-template $(Q932_ASN)

$(Q932_ROS_FILES): ../../tools/asn2wrs.py $(PROTOCOL_NAME)-ros.asn packet-$(PROTOCOL_NAME)-ros-template.c packet-$(PROTOCOL_NAME)-ros-template.h $(PROTOCOL_NAME)-ros.cnf
	python ../../tools/asn2wrs.py -b -T -X -e -p $(PROTOCOL_NAME).ros -c $(PROTOCOL_NAME)-ros.cnf -o $(PROTOCOL_NAME)-ros -s packet-$(PROTOCOL_NAME)-ros-template $(PROTOCOL_NAME)-ros.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
