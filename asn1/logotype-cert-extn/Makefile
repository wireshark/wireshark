
../../epan/dissectors/packet-logotypecertextn.c : ../../tools/asn2eth.py LogotypeCertExtn.asn packet-logotype-cert-extn-template.c packet-logotype-cert-extn-template.h logotype-cert-extn.cnf
	python ../../tools/asn2eth.py -X -b -e -p logotypecertextn -c logotype-cert-extn.cnf -s packet-logotype-cert-extn-template LogotypeCertExtn.asn
	cp packet-logotypecertextn.* ../../epan/dissectors

