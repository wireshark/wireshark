
../../epan/dissectors/packet-gsm_map.c : ../../tools/asn2eth.py GSMMAP.asn packet-gsm_map-template.c packet-gsm_map-template.h gsmmap.cnf 
	python ../../tools/asn2eth.py -X -b -k -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn
	cp packet-gsm_map.* ../../epan/dissectors

