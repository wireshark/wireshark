
../../epan/dissectors/packet-pkix1implicit.c : ../../tools/asn2eth.py PKIX1IMPLICIT93.asn packet-pkix1implicit-template.c packet-pkix1implicit-template.h pkix1implicit.cnf
	python ../../tools/asn2eth.py -e -X -b -p pkix1implicit -c pkix1implicit.cnf -s packet-pkix1implicit-template PKIX1IMPLICIT93.asn 
	cp packet-pkix1implicit.* ../../epan/dissectors

