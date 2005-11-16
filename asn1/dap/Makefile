# $Id: Makefile 13071 2005-01-16 10:19:21Z guy $

DISSECTOR_FILES=packet-dap.c packet-dap.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

ASN_EXPORTS=		../x509if/x509if-exp.cnf \
			../x509af/x509af-exp.cnf \
			../dsp/dsp-exp.cnf \
			../ros/ros-exp.cnf \
			../acse/acse-exp.cnf 

$(DISSECTOR_FILES): ../../tools/asn2eth.py dap.asn packet-dap-template.c packet-dap-template.h dap.cnf $(ASN_EXPORTS)
	python ../../tools/asn2eth.py -X -b -e -p dap -c dap.cnf -s packet-dap-template  dap.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

