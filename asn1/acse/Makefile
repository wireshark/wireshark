# $Id: Makefile 13071 2005-01-16 10:19:21Z guy $

DISSECTOR_FILES=packet-acse.c packet-acse.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py acse.asn packet-acse-template.c packet-acse-template.h acse.cnf
	python ../../tools/asn2eth.py -X -b -e -p acse -c acse.cnf -s packet-acse-template acse.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
#	cp $(DISSECTOR_FILES) ../../epan/dissectors
	echo "Dont use this dissector yet, there are two bugs in it you will"
	echo "have to fix manually first.  See packet-acse.c comment at top "

