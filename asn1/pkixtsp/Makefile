
../../epan/dissectors/packet-pkixtsp.c : ../../tools/asn2eth.py PKIXTSP.asn packet-pkixtsp-template.c packet-pkixtsp-template.h pkixtsp.cnf
	python ../../tools/asn2eth.py -X -b -k -e -p pkixtsp -c pkixtsp.cnf -s packet-pkixtsp-template PKIXTSP.asn
	cp packet-pkixtsp.* ../../epan/dissectors

