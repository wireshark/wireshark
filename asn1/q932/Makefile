# $Id$

PROTOCOL_NAME=q932
Q932_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h 
Q932_ROS_FILES=packet-$(PROTOCOL_NAME)-ros.c 
DISSECTOR_FILES=$(Q932_FILES) $(Q932_ROS_FILES)
Q932_ASN=Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn
Q932_ROS_ASN=../ros/Remote-Operations-Information-Objects.asn Facility-Information-Element-Components.asn 

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(Q932_FILES): ../../tools/asn2wrs.py $(Q932_ASN) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h $(PROTOCOL_NAME).cnf
	python ../../tools/asn2wrs.py -b -T -X -e -p $(PROTOCOL_NAME) -c $(PROTOCOL_NAME).cnf -s packet-$(PROTOCOL_NAME)-template $(Q932_ASN)

$(Q932_ROS_FILES): ../../tools/asn2wrs.py $(Q932_ROS_ASN) packet-$(PROTOCOL_NAME)-ros-template.c $(PROTOCOL_NAME)-ros.cnf ../ros/ros-inv.cnf ../ros/ros-res.cnf ../ros/ros-err.cnf ../ros/ros-rej.cnf
	python ../../tools/asn2wrs.py -b -T -X -e -p $(PROTOCOL_NAME).ros -I ../ros -c $(PROTOCOL_NAME)-ros.cnf -o $(PROTOCOL_NAME)-ros -s packet-$(PROTOCOL_NAME)-ros-template $(Q932_ROS_ASN)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
