
../../epan/dissectors/packet-ocsp.c : ../../tools/asn2eth.py OCSP.asn packet-ocsp-template.c packet-ocsp-template.h ocsp.cnf
	python ../../tools/asn2eth.py -X -b -e -p ocsp -c ocsp.cnf -s packet-ocsp-template OCSP.asn
	cp packet-ocsp.* ../../epan/dissectors

