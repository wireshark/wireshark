
../../epan/dissectors/packet-smrse.c : ../../tools/asn2eth.py SMRSE.asn packet-smrse-template.c packet-smrse-template.h smrse.cnf 
	python ../../tools/asn2eth.py -X -b -e -p smrse -c smrse.cnf -s packet-smrse-template SMRSE.asn
	cp packet-smrse.* ../../epan/dissectors

