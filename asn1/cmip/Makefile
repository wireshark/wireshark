
../../epan/dissectors/packet-cmip.c : ../../tools/asn2eth.py CMIP.asn packet-cmip-template.c packet-cmip-template.h cmip.cnf 
	python ../../tools/asn2eth.py -X -b -k -e -p cmip -c cmip.cnf -s packet-cmip-template CMIP.asn
	cp packet-cmip.* ../../epan/dissectors

