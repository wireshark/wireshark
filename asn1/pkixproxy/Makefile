
../../epan/dissectors/packet-pkixproxy.c : ../../tools/asn2eth.py PKIXProxy.asn packet-pkixproxy-template.c packet-pkixproxy-template.h pkixproxy.cnf
	python ../../tools/asn2eth.py -X -b -e -p pkixproxy -c pkixproxy.cnf -s packet-pkixproxy-template PKIXProxy.asn
	cp packet-pkixproxy.* ../../epan/dissectors

