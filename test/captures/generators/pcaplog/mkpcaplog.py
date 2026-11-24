#!/usr/bin/env python3
# Generates test/captures/pcaplog_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcaplog.c. usage: mkpcaplog.py <outdir>
import sys
import struct
from lib import cb, epb, exp_pdu, gz, idb, shb, udp, write_pcapng

PEN_VCTR = 46254
out = sys.argv[1]

def body(dtype, data, length=None):
    return struct.pack('<II', dtype, len(data) if length is None else length) + data

xml = [b'<?xml version="1.0"?><log><entry id="1">hello</entry></log>',
       b'<conf><item name="a">1</item><item name="b">2</item></conf>',
       b'<stat><cpu>10</cpu></stat>']

main = [shb(), idb(1)]
# data types 1-3 are XML; 0 and larger types are shown as data
for t, x in zip((1, 2, 3), xml):
    main.append(cb(PEN_VCTR, body(t, x)))
main.append(cb(PEN_VCTR, body(0, b'\x01\x02\x03\x04binary')))
main.append(cb(PEN_VCTR, body(4, b'\xde\xad\xbe\xef')))
main.append(cb(PEN_VCTR, body(0x7fffffff, b'unknown type')))
# the same blocks as "do not copy" custom blocks (0x40000BAD)
main.append(cb(PEN_VCTR, body(1, xml[0]), copy=False))
main.append(cb(PEN_VCTR, body(0, b''), copy=False))
# empty and XML that does not parse
main.append(cb(PEN_VCTR, body(2, b'not xml at all <<<')))
# an ordinary packet in between, so that the custom blocks are not the only records
main.append(epb(udp(1000, 2000, b'plain')))
main.append(cb(PEN_VCTR, body(3, xml[2])))
write_pcapng(out + '/pcaplog-coverage.pcapng', main)

# Exported PDU naming the dissector: no custom block header is present
mal = [shb(), idb(252)]
mal.append(epb(exp_pdu('pcaplog', body(1, xml[0]))))
mal.append(epb(exp_pdu('pcaplog', body(0, b'abc'))))
# data length larger than the data: malformed
mal.append(epb(exp_pdu('pcaplog', body(0, b'abc', length=100))))
mal.append(epb(exp_pdu('pcaplog', body(1, xml[0], length=100))))
# shorter than the 8 byte header
mal.append(epb(exp_pdu('pcaplog', b'\x01\x00\x00')))
mal.append(epb(exp_pdu('pcaplog', b'')))
# custom block with the Vctr PEN but too short
mal.append(cb(PEN_VCTR, b'\x01\x00'))
write_pcapng(out + '/pcaplog-coverage-malformed.pcapng', mal)
gz(out + '/pcaplog-coverage.pcapng')
print('ok')
