# $Id$

DISSECTOR_FILES=packet-ess.c packet-ess.h

all: generate_dissector

generate_dissector: $(DISSECTOR_FILES)

$(DISSECTOR_FILES): ../../tools/asn2eth.py ExtendedSecurityServices.asn packet-ess-template.c packet-ess-template.h ess.cnf
	python ../../tools/asn2eth.py -X -b -k -e -p ess -c ess.cnf -s packet-ess-template ExtendedSecurityServices.asn

clean:
	rm -f parsetab.py $(DISSECTOR_FILES)	\
		packet-ess-ettarr.c	\
		packet-ess-hfarr.c	\
		packet-ess-dis-tab.c	\
		packet-ess-fn.c		\
		packet-ess-ett.c	\
		packet-ess-hf.c

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) ../../epan/dissectors
