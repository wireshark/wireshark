# $Id$

DISSECTOR_FILES=packet-q932.c packet-q932.h packet-q932-ros.c packet-q932-ros.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

packet-q932.c packet-q932.h: ../../tools/asn2wrs.py packet-q932-template.c packet-q932-template.h q932.cnf
	python ../../tools/asn2wrs.py -b -T -e -p q932 -c q932.cnf -s packet-q932-template Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn

packet-q932-ros.c packet-q932-ros.h: ../../tools/asn2wrs.py packet-q932-ros-template.c packet-q932-ros-template.h q932-ros.cnf
	python ../../tools/asn2wrs.py -b -T -e -p q932-ros -c q932-ros.cnf -s packet-q932-ros-template q932-ros.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
