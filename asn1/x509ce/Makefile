
../../epan/dissectors/packet-x509ce.c : ../../tools/asn2eth.py CertificateExtensions.asn packet-x509ce-template.c packet-x509ce-template.h x509ce.cnf ../x509if/x509if-exp.cnf ../x509sat/x509sat-exp.cnf ../x509af/x509af-exp.cnf
	python ../../tools/asn2eth.py -X -b -e -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn
	cp packet-x509ce.* ../../epan/dissectors

