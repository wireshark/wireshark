#!/usr/bin/env python3
'''
Convert a CBOR diagnostic notation file into a UDP payload
for the encoded cbor.
This allows straightforward test and debugging of simple pcap files.

Copyright 2021-2024 Brian Sipos <brian.sipos@gmail.com>

SPDX-License-Identifier: LGPL-2.1-or-later
'''

from argparse import ArgumentParser
from io import BytesIO
import scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandNum
from subprocess import check_output
import sys


def main():
    parser = ArgumentParser()
    parser.add_argument('--infile', default='-',
                        help='The diagnostic text input file, or "-" for stdin')
    parser.add_argument('--sport', type=int,
                        help='The source port (default is random)')
    parser.add_argument('--dport', type=int,
                        help='The destination port (default is random)')
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

    # Write the request directly into pcap
    outfile_name = args.outfile.strip()
    if outfile_name != '-':
        outfile = open(outfile_name, 'wb')
    else:
        outfile = sys.stdout.buffer

    sport = args.sport or RandNum(49152, 65535)
    dport = args.dport or RandNum(49152, 65535)

    pkt = Ether()/IP()/UDP(sport=sport, dport=dport)/Raw(cbordata)
    wrpcap(outfile, pkt)

if __name__ == '__main__':
    sys.exit(main())
