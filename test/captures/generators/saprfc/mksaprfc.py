#!/usr/bin/env python3
# Generates test/captures/saprfc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP RFC (gateway) coverage captures.  Usage: mksaprfc.py <outdir>
# SAP RFC is on TCP 3300 (the dissector gets the TCP payload as it is,
# without an NI header); the internal handler "saprfcinternal" is reached
# through the RFC item of a SAP Diag message (TCP 3200 over SAP NI).  Nothing
# is captured from a network.  Table content is LZC compressed with
# lib.lzc_compress (not crypto).
import os
import struct
import sys
from sapcov_lib import Cap, Flow, lzc_compress, ni

CLI, SRV = '192.0.2.1', '192.0.2.2'
n = [54000]


def flow(c, port=3300):
    n[0] += 1
    f = Flow(c, CLI, SRV, n[0], port)
    f.syn()
    return f


def s(x, k):
    if isinstance(x, str):
        x = x.encode()
    return x.ljust(k, b'\0')[:k]


# ---- gateway messages (version <= 3) --------------------------------------

def gw_client(version, reqtype=3, addr=bytes([192, 0, 2, 9]), accept=0xff, rc=0):
    b = bytes([version, reqtype]) + addr + b'\0\0\0\0' + s('sapgw00', 10) + s('4103', 4) + b'\0' * 6
    b += s('LU01', 8) + s('TP01', 8) + s('CONV0001', 8) + bytes([3, accept]) + struct.pack('!H', 7)
    if version == 3:
        b += bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [9])
    b += struct.pack('!I', rc) + bytes([0x55, 0])
    return b


# ---- APPC header (version > 3) ---------------------------------------------

def appc(reqtype, params=b'', payload=b'', version=6, info=0, info2=0, info3=0, info4=0, reqtype2=0, cid=b'CONV0001'):
    h = bytes([version, reqtype, 0x42, 1]) + struct.pack('!HHH', 9, 3, 0) + bytes([info2, 2]) + \
        struct.pack('!I', 1700000000) + bytes([info3]) + struct.pack('!I', 300) + bytes([info4]) + \
        struct.pack('!I', 5) + struct.pack('!H', 0) + b'\0\0' + bytes([info, reqtype2]) + \
        struct.pack('!II', 0x2711, 0) + s(cid, 8) + s(params, 28) + struct.pack('!HH', 0, 0)
    assert len(h) == 80, len(h)
    return h + payload


# ---- RFC items ---------------------------------------------------------------

def ritem(i1, i2, value):
    return bytes([i1, i2]) + struct.pack('!H', len(value)) + value + bytes([i1, i2])


SESSION = struct.pack('!I', 0xd9c6c3f0) + b'\0' * 8


def epp1():
    b = bytearray(0x99)
    b[0:4] = b'*TH*'
    b[4] = 1
    struct.pack_into('!H', b, 5, 0x99)
    b[9:18] = b'COMPONENT'
    b[0x2b:0x2f] = b'USER'
    b[0x95:] = b'*TH*'
    return bytes(b)


def table_items(name, rows, compress=True, chunks=2, maxbits=13):
    '''Type structure, table name, table info and the content in several items.'''
    data = b''.join(b'ROW%04d:%s;' % (i, b'x' * 20) for i in range(rows))
    content = lzc_compress(data, maxbits=maxbits) if compress else data
    total = 8 + len(content)
    whole = b'\0\0\0\0' + struct.pack('!I', total) + content
    cut = [0] + [len(whole) * (i + 1) // chunks for i in range(chunks - 1)] + [len(whole)]
    parts = [whole[a:b] for a, b in zip(cut, cut[1:])]
    out = ritem(0x02, 0x13, b'\x01\x02\x03\x04') + ritem(0x03, 0x01, name.encode()) + \
        ritem(0x03, 0x02, struct.pack('!II', 30, rows))
    for p in parts:
        out += ritem(0x03, 0x05, p)
    return out + ritem(0x03, 0x06, b'')


def payload_items(session=False):
    p = SESSION if session else b''
    p += ritem(0x01, 0x02, b'Z_RFC_FUNCTION') + ritem(0x02, 0x01, b'IV_PARAMETER') + ritem(0x02, 0x05, b'EV_RESULT')
    p += ritem(0x01, 0x36, b'\x01' + bytes(range(16)) + bytes(range(16, 32)) + struct.pack('!I', 77))
    p += ritem(0x01, 0x31, epp1() + b'\0\0\0')          # extended passport with padding after it
    p += ritem(0x01, 0x31, epp1())
    p += ritem(0x07, 0x07, b'unknown item')
    p += ritem(0xff, 0xff, b'')
    if session:
        p += struct.pack('!II', 4096, 3)
    return p


def diag_msg(rfc):
    return bytes([0, 0x28, 0, 0, 1, 0, 0, 0]) + bytes([0x10, 0x08, 1]) + struct.pack('!H', len(rfc)) + rfc + bytes([0x0c])


def build_main(out):
    c = Cap()
    f = flow(c)
    # --- gateway: client, register, commands, other request types ---------------
    f.send(gw_client(1))
    f.send(gw_client(3), False)
    f.send(gw_client(3, reqtype=0x0b, accept=0x5a))
    f.send(gw_client(2, reqtype=0x0b, accept=0x00), False)
    for cmd in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 25, 32, 33, 34, 35, 36, 37, 38,
                39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 64, 65, 99):
        f.send(bytes([2, 9, cmd, 0]))
    for rt in (0, 1, 2, 4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 99):
        f.send(bytes([1, rt, 0, 0]))
    # --- APPC headers -------------------------------------------------------------
    f.send(appc(0x01, params=s('SDEST', 8) + s('LU', 8) + s('TP', 8) + b'\x43\x02', info=0xff, info2=0xff,
                info3=0xff, info4=1, reqtype2=0x1f))
    f.send(appc(0x01, params=s('SDEST', 8) + s('LU', 8) + s('TP', 8) + b'\x43\x01'), False)
    f.send(appc(0x0f, params=s('PARTLU', 8) + struct.pack('!I', 16) + bytes(range(16)),
                payload=b'LONGLUNAME_0123456' + z(128 - 18) + z(16)))
    f.send(appc(0x0f, params=s('PARTLU', 8) + struct.pack('!I', 500) + bytes(range(16)),
                payload=b'L' * 128 + z(16)))
    f.send(appc(0x0f, params=s('PARTLU', 8), payload=ritem(0x01, 0x02, b'SHORT') + ritem(0xff, 0xff, b'')))
    f.send(appc(0x17, params=s('PASSWORD', 8) + struct.pack('!I', 8) + z(16)))
    f.send(appc(0x07, payload=payload_items()), True)
    f.send(appc(0x08, version=5, payload=payload_items(session=True)), False)
    f.send(appc(0x0b))                                                  # no payload
    f.send(appc(0x05, version=4, payload=ritem(0x0c, 0, b'')[:1]))        # end of message item
    # --- tables: uncompressed, compressed in one, two and three chunks -----------
    f.send(appc(0x07, payload=table_items('TABLE_PLAIN', 20, compress=False, chunks=1) + ritem(0xff, 0xff, b'')))
    f.send(appc(0x07, payload=table_items('TABLE_LZC', 40, chunks=1) + ritem(0xff, 0xff, b'')))
    f.send(appc(0x07, payload=table_items('TABLE_LZC2', 60, chunks=2) + ritem(0xff, 0xff, b'')))
    f.send(appc(0x07, payload=table_items('TABLE_LZC3', 80, chunks=3) + ritem(0xff, 0xff, b'')))
    # --- the internal handler through the RFC item of a Diag message ---------------
    g = flow(c, 3200)
    g.send(ni(diag_msg(payload_items())))
    g.send(ni(diag_msg(table_items('DIAG_TABLE', 30, chunks=2) + ritem(0xff, 0xff, b''))), False)
    c.write(os.path.join(out, 'saprfc-coverage.pcap'))


def z(k):
    return bytes(k)


def build_malformed(out):
    c = Cap()
    f = flow(c)
    f.send(b'\x01')                                                      # shorter than 2 bytes
    f.send(gw_client(1)[:30])                                            # client header cut short
    f.send(gw_client(3)[:70])
    f.send(appc(0x01)[:60])                                              # APPC header cut short
    f.send(appc(0x01)[:80])                                              # exactly 80 bytes
    f.send(appc(0x0f, payload=z(100)))                                   # LU name payload short
    # item errors
    f.send(appc(0x07, payload=b'\x01'))                                  # id2 and length missing
    f.send(appc(0x07, payload=b'\x01\x02\x00'))
    f.send(appc(0x07, payload=b'\x01\x02\x00\x30abc'))                   # value longer than the packet
    f.send(appc(0x07, payload=ritem(0x03, 0x02, b'\1\2\3\4') + ritem(0xff, 0xff, b'')))     # table info length != 8
    f.send(appc(0x07, payload=ritem(0x01, 0x31, b'*TH*\x01\0\x99' + z(20))))                # bad passport
    f.send(appc(0x07, payload=ritem(0x01, 0x31, b'abc')))                                  # short passport
    f.send(appc(0x07, payload=ritem(0x01, 0x36, b'\1' * 37)[:20]))
    # table reassembly errors
    ts = table_items('T', 10, chunks=1)
    for cut in (30, 40, 56, 70, 80, 90):
        f.send(appc(0x07, payload=ts[:cut]))
    # reassembled length invalid, too large, item shorter than prefix
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1)) +
                ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 3) + z(8))))
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1)) +
                ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 0x7fffffff) + z(8))))
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1)) +
                ritem(0x03, 0x05, b'\0\0\0')))
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1)) +
                ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 5000) + z(8)) + ritem(0xff, 0xff, b'')))   # incomplete table
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, b'\1\2'))) # info too short
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x04, b'T')))        # not a name item
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x04, b'x')))
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1)) + ritem(0x03, 0x04, b'x')))
    # compressed table errors: bad length, bad stream
    good = lzc_compress(b'abcdefgh' * 50)
    def tab(content, total=None):
        t = 8 + len(content) if total is None else total
        return appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') +
                    ritem(0x03, 0x02, struct.pack('!II', 1, 1)) +
                    ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', t) + content) + ritem(0xff, 0xff, b''))
    f.send(tab(struct.pack('<I', 0) + good[4:]))
    f.send(tab(struct.pack('<I', 0x7fffffff) + good[4:]))
    f.send(tab(good[:7] + b'\x95' + good[8:]))
    f.send(tab(struct.pack('<I', 50) + good[4:]))
    f.send(tab(struct.pack('<I', 5000) + good[4:]))                                  # stream shorter than reported
    # more length checks of the table reassembly
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4')))                        # nothing after the structure
    f.send(appc(0x07, payload=ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T')))   # name item at the end
    pre = ritem(0x02, 0x13, b'\1\2\3\4') + ritem(0x03, 0x01, b'T') + ritem(0x03, 0x02, struct.pack('!II', 1, 1))
    f.send(appc(0x07, payload=pre + ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 20) + z(100))))   # item longer than the table
    f.send(appc(0x07, payload=pre + ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 5000) + z(8))))    # no more data after the item
    f.send(appc(0x07, payload=pre + ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 5000) + z(8)) + b'\x03\x05'))   # next item id only
    f.send(appc(0x07, payload=pre + ritem(0x03, 0x05, b'\0\0\0\0' + struct.pack('!I', 40) + z(12)) +
                ritem(0x03, 0x05, z(100)) + ritem(0xff, 0xff, b'')))                        # second item longer than the table
    f.send(tab(good[:4] + b'\x12' + good[5:]))
    f.send(tab(good[:9] + b'\xff' * 5))
    c.write(os.path.join(out, 'saprfc-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
