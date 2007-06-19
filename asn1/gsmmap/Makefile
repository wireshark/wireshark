# $Id$

PROTOCOL_NAME=gsm_map
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h

DATATYPES_ASN_FILES=MAP-ExtensionDataTypes.asn MAP-CommonDataTypes.asn MAP-SS-DataTypes.asn MAP-ER-DataTypes.asn MAP-SM-DataTypes.asn MAP-OM-DataTypes.asn MAP-MS-DataTypes.asn MAP-CH-DataTypes.asn  MAP-LCS-DataTypes.asn MAP-GR-DataTypes.asn  
OPERATIONS_ASN_FILES=MAP-LocationServiceOperations.asn MAP-Group-Call-Operations.asn MAP-ShortMessageServiceOperations.asn MAP-SupplementaryServiceOperations.asn MAP-CallHandlingOperations.asn MAP-OperationAndMaintenanceOperations.asn MAP-MobileServiceOperations.asn
SS_ASN_FILES=SS-DataTypes.asn SS-Operations.asn
ROS_ASN= ../ros/Remote-Operations-Information-Objects.asn
ASN_FILE_LIST= $(ROS_ASN) MobileDomainDefinitions.asn MAP-ApplicationContexts.asn  MAP-SS-Code.asn MAP-BS-Code.asn MAP-TS-Code.asn $(DATATYPES_ASN_FILES) MAP-DialogueInformation.asn $(OPERATIONS_ASN_FILES) MAP-Protocol.asn GSMMAP.asn $(SS_ASN_FILES)

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h gsmmap.cnf 
	python ../../tools/asn2wrs.py -b -X -T -k -e -c gsmmap.cnf -s packet-$(PROTOCOL_NAME)-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
