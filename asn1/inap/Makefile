# $Id$

DISSECTOR_FILES=packet-inap.c packet-inap.h
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h
ROS_ASN= ../ros/Remote-Operations-Information-Objects.asn 
1248_1_ASN_FILES= IN-object-identifiers.asn IN-common-datatypes.asn
1248_2_ASN_FILES=IN-SSF-SCF-datatypes.asn IN-SSF-SCF-ops-args.asn
1248_3_ASN_FILES=IN-SCF-SRF-datatypes.asn IN-SCF-SRF-ops-args.asn
1248_CLASSES_ASN=IN-common-classes.asn IN-SSF-SCF-Classes.asn IN-SCF-SRF-Classes.asn
ASN_FILE_LIST=$(ROS_ASN) $(1248_CLASSES_ASN) inap.asn $(1248_1_ASN_FILES) $(1248_2_ASN_FILES) $(1248_3_ASN_FILES)

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-inap-template.c packet-inap-template.h inap.cnf 
	python ../../tools/asn2wrs.py -b -X -e -p inap -c inap.cnf -s packet-inap-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
