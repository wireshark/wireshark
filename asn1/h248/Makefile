
../../epan/dissectors/packet-h248.c : ../../tools/asn2eth.py MEGACO.asn packet-h248-template.c packet-h248-template.h h248.cnf 
	python ../../tools/asn2eth.py -X -b -k -e -p h248 -c h248.cnf -s packet-h248-template MEGACO.asn
	cp packet-h248.* ../../epan/dissectors

