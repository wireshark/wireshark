#!/usr/bin/env python3
'''
Convert a CBOR diagnostic notation file into an HTTP request
for the encoded cbor.
This allows straightforward test and debugging of simple pcap files.

 Copyright 2021 Brian Sipos <brian.sipos@gmail.com>

SPDX-License-Identifier: LGPL-2.1-or-later
'''

from argparse import ArgumentParser
from io import BytesIO
import scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw
from scapy.utils import wrpcap
from subprocess import check_output
import sys


def main():
    parser = ArgumentParser()
    parser.add_argument('--content-type', default='application/cbor',
                        help='The request content-type header')
    parser.add_argument('--infile', default='-',
                        help='The diagnostic text input file, or "-" for stdin')
    parser.add_argument('--outfile', default='-',
                        help='The PCAP output file, or "-" for stdout')
    parser.add_argument('--intype', default='cbordiag',
                        choices=['cbordiag', 'raw'],
                        help='The input data type.')
    args = parser.parse_args()

    # First get the CBOR data itself
    infile_name = args.infile.strip()
    if infile_name != '-':
        infile = open(infile_name, 'rb')
    else:
        infile = sys.stdin.buffer

    if args.intype == 'raw':
        cbordata = infile.read()
    elif args.intype == 'cbordiag':
        cbordata = check_output('diag2cbor.rb', stdin=infile)

    # Now synthesize an HTTP request with that body
    req = HTTPRequest(
        Method='POST',
        Host='example.com',
        User_Agent='scapy',
        Content_Type=args.content_type,
        Content_Length=str(len(cbordata)),
    ) / Raw(cbordata)

    # Write the request directly into pcap
    outfile_name = args.outfile.strip()
    if outfile_name != '-':
        outfile = open(outfile_name, 'wb')
    else:
        outfile = sys.stdout.buffer

    pkt = Ether()/IP()/TCP()/HTTP()/req
    wrpcap(outfile, pkt)

if __name__ == '__main__':
    sys.exit(main())
