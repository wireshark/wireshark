# $Id$

PROTOCOL_NAME=camel
DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c packet-$(PROTOCOL_NAME).h
ROS_ASN= ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn
ASN_FILE_LIST=TCAPMessages.asn CAP-object-identifiers.asn CAP-classes.asn CAP-datatypes.asn CAP-errorcodes.asn CAP-errortypes.asn CAP-operationcodes.asn CAP-GPRS-ReferenceNumber.asn CAP-gsmSCF-gsmSRF-ops-args.asn CAP-gsmSSF-gsmSCF-ops-args.asn CAP-gprsSSF-gsmSCF-ops-args.asn CAP-SMS-ops-args.asn CAP-U-ABORT-Data.asn $(ROS_ASN)

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2wrs.py $(ASN_FILE_LIST) packet-$(PROTOCOL_NAME)-template.c packet-$(PROTOCOL_NAME)-template.h camel.cnf 
	python ../../tools/asn2wrs.py  -b -X -T -L -e -k -p $(PROTOCOL_NAME) -c camel.cnf -s packet-$(PROTOCOL_NAME)-template $(ASN_FILE_LIST)

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
