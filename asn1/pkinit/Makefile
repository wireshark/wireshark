
../../epan/dissectors/packet-pkinit.c : ../../tools/asn2eth.py PKINIT.asn packet-pkinit-template.c packet-pkinit-template.h pkinit.cnf
	python ../../tools/asn2eth.py -e -X -b -p pkinit -c pkinit.cnf -s packet-pkinit-template PKINIT.asn
	cp packet-pkinit.* ../../epan/dissectors

