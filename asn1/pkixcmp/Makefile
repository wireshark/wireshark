
../../epan/dissectors/packet-cmp.c : ../../tools/asn2eth.py CMP.asn packet-cmp-template.c packet-cmp-template.h cmp.cnf 
	python ../../tools/asn2eth.py -X -b -e -p cmp -c cmp.cnf -s packet-cmp-template CMP.asn
	cp packet-cmp.* ../../epan/dissectors

