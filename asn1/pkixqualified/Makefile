
../../epan/dissectors/packet-pkixqualified.c : ../../tools/asn2eth.py PKIXqualified.asn packet-pkixqualified-template.c packet-pkixqualified-template.h pkixqualified.cnf
	python ../../tools/asn2eth.py -X -b -e -p pkixqualified -c pkixqualified.cnf -s packet-pkixqualified-template PKIXqualified.asn
	cp packet-pkixqualified.* ../../epan/dissectors

