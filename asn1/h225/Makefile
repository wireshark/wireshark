# $Id$

../../epan/dissectors/packet-h225.c : ../../tools/asn2eth.py h225.asn packet-h225-template.c packet-h225-template.h h225.cnf 
	python ../../tools/asn2eth.py -X -e -p h225 -c h225.cnf -s packet-h225-template h225.asn
	cp packet-h225.* ../../epan/dissectors

