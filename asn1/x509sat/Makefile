
../../epan/dissectors/packet-x509sat.c : ../../tools/asn2eth.py SelectedAttributeTypes.asn packet-x509sat-template.c packet-x509sat-template.h x509sat.cnf ../x509if/x509if-exp.cnf
	python ../../tools/asn2eth.py -X -b -k -e -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn
	cp packet-x509sat.* ../../epan/dissectors

