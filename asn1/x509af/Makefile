
../../epan/dissectors/packet-x509af.c : ../../tools/asn2eth.py AuthenticationFramework.asn packet-x509af-template.c packet-x509af-template.h x509af.cnf ../x509if/x509if-exp.cnf ../x509sat/x509sat-exp.cnf ../x509ce/x509ce-exp.cnf
	python ../../tools/asn2eth.py -X -b -k -e -p x509af -c x509af.cnf -s packet-x509af-template AuthenticationFramework.asn
	cp packet-x509af.* ../../epan/dissectors

