
../../epan/dissectors/packet-pkix1explicit.c : ../../tools/asn2eth.py PKIX1EXPLICIT93.asn packet-pkix1explicit-template.c packet-pkix1explicit-template.h pkix1explicit.cnf
	python ../../tools/asn2eth.py -e -X -b -p pkix1explicit -c pkix1explicit.cnf -s packet-pkix1explicit-template PKIX1EXPLICIT93.asn 
	cp packet-pkix1explicit.* ../../epan/dissectors

