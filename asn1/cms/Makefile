
../../epan/dissectors/packet-cms.c : ../../tools/asn2eth.py CryptographicMessageSyntax.asn packet-cms-template.c packet-cms-template.h cms.cnf
	python ../../tools/asn2eth.py -X -b -e -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn
	cp packet-cms.* ../../epan/dissectors

