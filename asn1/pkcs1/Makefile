../../epan/dissectors/packet-pkcs1.c : ../../tools/asn2eth.py PKCS1.asn packet-pkcs1-template.c packet-pkcs1-template.h pkcs1.cnf
	python ../../tools/asn2eth.py -X -b -p pkcs1 -c pkcs1.cnf -s packet-pkcs1-template PKCS1.asn
	cp packet-pkcs1.* ../../epan/dissectors

