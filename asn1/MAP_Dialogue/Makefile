
../../epan/dissectors/packet-MAP_DialoguePDU.c : ../../tools/asn2eth.py MAP_DialoguePDU.asn packet-MAP-DialoguePDU-template.c packet-MAP-DialoguePDU-template.h MAP_DialoguePDU.cnf
	python ../../tools/asn2eth.py -X -b -e -p MAP_DialoguePDU -c MAP_DialoguePDU.cnf -s packet-MAP-DialoguePDU-template MAP_DialoguePDU.asn
	cp packet-MAP_DialoguePDU.* ../../epan/dissectors

