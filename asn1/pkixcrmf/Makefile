
../../epan/dissectors/packet-crmf.c : ../../tools/asn2eth.py CRMF.asn packet-crmf-template.c packet-crmf-template.h crmf.cnf 
	python ../../tools/asn2eth.py -X -b -e -p crmf -c crmf.cnf -s packet-crmf-template CRMF.asn
	cp packet-crmf.* ../../epan/dissectors

