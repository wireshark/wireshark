# $Id$

DISSECTOR_FILES=packet-ros.c packet-ros.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py ros.asn packet-ros-template.c packet-ros-template.h ros.cnf
	python ../../tools/asn2eth.py -X -b -e -p ros -c ros.cnf -s packet-ros-template  ros.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors

