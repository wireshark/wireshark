# $Id$

DISSECTOR_FILES=packet-mpeg-audio.c packet-mpeg-pes.c

all: $(DISSECTOR_FILES)

clean:
	rm -f parsetab.py parsetab.pyc $(DISSECTOR_FILES)

copy_files: all
	cp $(DISSECTOR_FILES) ../../epan/dissectors

.PHONY: all clean copy_files

packet-%.c: ../../tools/asn2wrs.py %.asn %.cnf packet-%-template.c
	python ../../tools/asn2wrs.py -e -p $* -c $*.cnf -s packet-$*-template $*.asn
