
../../epan/dissectors/packet-x509if.c : ../../tools/asn2eth.py InformationFramework.asn packet-x509if-template.c packet-x509if-template.h x509if.cnf ../x509sat/x509sat-exp.cnf
	python ../../tools/asn2eth.py -X -b -k -e -p x509if -c x509if.cnf -s packet-x509if-template InformationFramework.asn
	cp packet-x509if.* ../../epan/dissectors

