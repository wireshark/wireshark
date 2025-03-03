#!/usr/bin/env python3
'''
Convert a CBOR diagnostic notation file into an HTTP request
for the encoded cbor.
This allows straightforward test and debugging of simple pcap files.

 Copyright 2021 Brian Sipos <brian.sipos@gmail.com>

SPDX-License-Identifier: LGPL-2.1-or-later
'''

from argparse import ArgumentParser
import cbor2
from io import BytesIO
import random
import scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.contrib.coap import CoAP
from scapy.packet import Raw
from scapy.utils import wrpcap
from subprocess import check_output
import sys


def intencode(val: int) -> bytes:
    return val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')


def main():
    parser = ArgumentParser()
    parser.add_argument('--infile', default=[], action='append',
                        help='The diagnostic text input file, or "-" for stdin')
    parser.add_argument('--outfile', default='-',
                        help='The PCAP output file, or "-" for stdout')
    parser.add_argument('--intype', default='cbordiag',
                        choices=['cbordiag', 'raw'],
                        help='The input data type.')
    subp = parser.add_subparsers(title='transport',
                                 dest='transport', required=True,
                                 help='Message transport')
    parse_http = subp.add_parser('http')
    parse_http.add_argument('--client-port', type=int,
                            help='The client port (default is random)')
    parse_http.add_argument('--uri-path', default="/",
                            help='The request path value')
    parse_http.add_argument('--content-type', default=[], action='append',
                            help='The request content-type header')
    parse_coap = subp.add_parser('coap')
    parse_coap.add_argument('--client-port', type=int,
                            help='The client port (default is random)')
    parse_coap.add_argument('--uri-path', default=[], action='append',
                            help='The request path segments')
    parse_coap.add_argument('--content-format', type=int, default=[], action='append',
                            help='The request content-format value')
    args = parser.parse_args()

    if not args.infile:
        args.infile = ['-']

    # First get the CBOR data itself
    cbordata = []
    for infile_name in args.infile:
        infile_name = infile_name.strip()
        if infile_name != '-':
            infile = open(infile_name, 'rb')
        else:
            infile = sys.stdin.buffer

        if args.intype == 'raw':
            cbordata.append(infile.read())
        elif args.intype == 'cbordiag':
            cbordata.append(check_output('diag2cbor.rb', stdin=infile))

    # Write the request directly into pcap
    outfile_name = args.outfile.strip()
    if outfile_name != '-':
        outfile = open(outfile_name, 'wb')
    else:
        outfile = sys.stdout.buffer

    cport = args.client_port or random.randint(49152, 65535)

    if args.transport == 'coap':
        uri_path = [
            ("Uri-Path", seg)
            for seg in args.uri_path
        ]

        cformat = args.content_format or [60] # default application/cbor
        # give each cbordata a cformat
        if len(cformat) == 1:
            cformat = cformat * len(cbordata)
        cformat = list(map(intencode, cformat))

        # Synthesize CoAP exchanges with bodies
        out_pkts = []
        for idx, data in enumerate(cbordata):
            if idx % 2 == 0:
                mid = random.randint(1, 0xFFFF)
                coapopts = dict(
                    type="CON",
                    code=2,
                    msg_id=mid,
                    options=(
                        [
                            ("Uri-Host", "example.com"),
                        ]
                        + uri_path +
                        [
                            ("Content-Format", cformat.pop(0)),
                        ]
                    ),
                    paymark=b'\xFF',
                )
                pyld = CoAP(**coapopts)/data
                udpopts = dict(sport=cport, dport=5683)
                out_pkts.append(Ether()/IP()/UDP(**udpopts)/pyld)
            else:
                coapopts = dict(
                    type="ACK",
                    code=68,
                    msg_id=mid,
                    options=[
                        ("Content-Format", cformat.pop(0)),
                    ],
                    paymark=b'\xFF',
                )
                pyld = CoAP(**coapopts)/data
                udpopts = dict(sport=5683, dport=cport)
                out_pkts.append(Ether()/IP()/UDP(**udpopts)/pyld)

    elif args.transport == 'http':
        ctype = args.content_type or ['application/cbor']
        # give each cbordata a ctype
        if len(ctype) == 1:
            ctype = ctype * len(cbordata)

        # Synthesize HTTP exchanges with bodies
        seq = [0, 0]
        out_pkts = []
        for idx, data in enumerate(cbordata):
            if idx % 2 == 0:
                req = HTTPRequest(
                    Method='POST',
                    Path=args.uri_path,
                    Host='example.com',
                    User_Agent='scapy',
                    Connection='keep-alive',
                    Content_Type=ctype.pop(0),
                    Content_Length=str(len(data)),
                ) / Raw(data)
                pyld = HTTP()/req

                if idx < 2:
                    flags = "S"
                    seqadd = 1
                else:
                    flags = ""
                    seqadd = 0
                udpopts = dict(sport=cport, seq=seq[0], flags=flags)
                out_pkts.append(Ether()/IP()/TCP(**udpopts)/pyld)
                seq[0] += len(bytes(pyld)) + seqadd
            else:
                rsp = HTTPResponse(
                    Status_Code='200',
                    Connection='keep-alive',
                    Content_Type=ctype.pop(0),
                    Content_Length=str(len(data)),
                ) / Raw(data)
                pyld = HTTP()/rsp

                if idx < 2:
                    flags = "S"
                    seqadd = 1
                else:
                    flags = ""
                    seqadd = 0
                udpopts = dict(dport=cport, seq=seq[1], flags=flags)
                out_pkts.append(Ether()/IP()/TCP(**udpopts)/pyld)
                seq[1] += len(bytes(pyld)) + seqadd

    wrpcap(outfile, out_pkts)


if __name__ == '__main__':
    sys.exit(main())
