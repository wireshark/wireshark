#!/usr/bin/env python3
# Generates test/captures/etw_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ETW dissector
(packet-etw.c, Event Tracing for Windows).

ETW records are stored in pcapng files with link type 305 (290 before Wireshark 5.1)
(LINKTYPE_ETW): the 0x5C octet ETW event header, extended data items,
"extra information" TLVs (user data, message, provider name, addresses,
session id) and property key/value pairs, followed by the data they point
to. Providers with a special handling hand their user data to another
dissector: MBIM, SMB (NBSS), HTTP (WinInet, WebIO), LDAP and Bluetooth.
Every packet is built from scratch with struct.

Usage: mketw.py <output directory>

Writes:
  etw-coverage.pcapng            events of every kind (manifest, WPP,
                                 classic, TraceLogging), every extended
                                 data type, every TLV type, message
                                 formatting, every special provider, the
                                 reproducers of the fixes
  etw-coverage-malformed.pcapng  truncated records and pointers past the
                                 end of the record
"""
import os
import struct
import sys


def blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)


def pcapng(path, linktypes, pkts):
    """pkts: list of (interface id, data, direction) direction: None,
    1 (inbound) or 2 (outbound)."""
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, d, direction) in enumerate(pkts):
        ts = (1700000000 + i) * 1000000
        body = struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(d), len(d))
        body += d + b'\0' * ((-len(d)) % 4)
        if direction is not None:
            body += struct.pack('<HHI', 2, 4, direction) + struct.pack('<HH', 0, 0)
        out += blk(6, body)
    open(path, 'wb').write(out)


def guid_le(d1, d2, d3, d4):
    return struct.pack('<IHH', d1, d2, d3) + bytes(d4)


G_RANDOM = b'\x11' * 16
G_MBIM = guid_le(0xA42FE227, 0xA7BF, 0x4483, [0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96])
G_SMBC = guid_le(0x988C59C5, 0x0A1C, 0x45B6, [0xA5, 0x55, 0x0C, 0x62, 0x27, 0x6E, 0x32, 0x7D])
G_SMBS = guid_le(0xD48CE617, 0x33A2, 0x4BC3, [0xA5, 0xC7, 0x11, 0xAA, 0x4F, 0x29, 0x61, 0x9E])
G_WININET = guid_le(0xA70FF94F, 0x570B, 0x4979, [0xBA, 0x5C, 0xE5, 0x9C, 0x9F, 0xEA, 0xB6, 0x1B])
G_WEBIO = guid_le(0x50B3E73C, 0x9370, 0x461D, [0xBB, 0x9F, 0x26, 0xF3, 0x2D, 0x68, 0x88, 0x7D])
G_LDAP = guid_le(0x099614A5, 0x5DD7, 0x4788, [0x8B, 0xC9, 0xE2, 0x9F, 0x43, 0xDB, 0x28, 0xFC])
G_BTH = guid_le(0x8A1F9517, 0x3A8C, 0x4A9E, [0xA0, 0x18, 0x4F, 0x17, 0xA2, 0x00, 0xF2, 0x77])
G_KERNEL = guid_le(0x9E814AAD, 0x3204, 0x11D2, [0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39])

# TLV types
T_USER, T_MSG, T_PROV, T_SRC, T_DST, T_SESS = 0, 1, 2, 3, 4, 5
# extended data types
E_RELATED, E_SID, E_STACK64, E_SCHEMA, E_TRAITS = 1, 2, 6, 0x0B, 0x0C

FILETIME_UNIX = 0x019DB1DED53E8000   # what the dissector subtracts


def u16(s):
    return s.encode('utf-16-le')


def event(provider=G_RANDOM, eid=1, flags=0, evprop=0, edata=(), tlvs=(),
          props=(), keywords=0, ts=None, version=0, channel=0, level=4,
          opcode=0, task=0, edata_count=None, tlv_count=None, prop_count=None,
          big_ptr=False):
    """edata: (type, data bytes); tlvs: (type, data bytes); props:
    (key, value) strings. Returns the record."""
    if ts is None:
        ts = FILETIME_UNIX + 1700000000 * 10000000
    ne, nt, npr = len(edata), len(tlvs), len(props)
    base = 0x5C + 16 * ne + 12 * nt + 8 * npr
    blobs = b''
    ed = b''
    for k, (t, d) in enumerate(edata):
        ptr = base + len(blobs)
        if big_ptr and k == 0:
            ptr = 0x100000000
        ed += struct.pack('<HHHHQ', 0, t, 0, len(d), ptr)
        blobs += d
    tl = b''
    for t, d in tlvs:
        tl += struct.pack('<III', t, base + len(blobs), len(d))
        blobs += d
    pr = b''
    for key, val in props:
        kb, vb = u16(key), u16(val)
        pr += struct.pack('<IHH', base + len(blobs), len(kb), len(vb))
        blobs += kb + vb
    hdr = struct.pack('<HHHHII', 0x5C, 0, flags, evprop, 1234, 5678)
    hdr += struct.pack('<Q', ts)
    hdr += provider
    hdr += struct.pack('<HBBBBHQ', eid, version, channel, level, opcode, task, keywords)
    hdr += struct.pack('<Q', 4242) + bytes(range(16))
    hdr += struct.pack('<BBH', 3, 0, 7)
    hdr += struct.pack('<HHI', ne if edata_count is None else edata_count,
                       nt if tlv_count is None else tlv_count,
                       npr if prop_count is None else prop_count)
    assert len(hdr) == 0x5C
    return hdr + ed + tl + pr + blobs


def sid(subs=(21, 1, 2, 3)):
    return struct.pack('<BB', 1, len(subs)) + b'\0\0\0\0\0\x05' + b''.join(struct.pack('<I', s) for s in subs)


def schema_tl(name, fields):
    body = name.encode() + b'\0'
    for key, ftype in fields:
        body += key.encode() + b'\0' + bytes([ftype])
    size = 3 + len(body)
    return bytes([size]) + b'\0\0' + body


def smb2_negotiate():
    hdr = b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ', 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b'\0' * 16
    body = struct.pack('<HHHHI', 36, 1, 1, 0, 0) + b'\x22' * 16 + struct.pack('<Q', 0) + struct.pack('<H', 0x0202)
    msg = hdr + body
    return b'\0' + struct.pack('>I', len(msg))[1:] + msg


def http_req():
    return b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'


def http_resp():
    return b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'


LDAP_BIND = bytes.fromhex('300c020101600702010304008000')
LDAP_BIND_RESP = bytes.fromhex('300c02010161070a010004000400')
HCI_RESET = bytes.fromhex('01030c00')
HCI_EVENT = bytes.fromhex('040e0401030c00')


def main_records():
    R = []   # (interface, data, direction)

    def add(rec, direction=None, ifid=0):
        R.append((ifid, rec, direction))

    # 1: manifest event with provider name, properties and formatted message
    add(event(tlvs=[(T_PROV, u16('Contoso-Demo-Provider')),
                    (T_MSG, u16('File %1 failed with error %2!S! (%0, %99, %123, %, 100%)')),
                    (T_USER, b'user data bytes')],
              props=[('path', 'C:\\temp\\a.txt'), ('error', 'ACCESS_DENIED')],
              keywords=0x8000000000000001, version=2, channel=16, level=2, opcode=1, task=5))
    # 2: WPP trace message, no message: Info is the GUID
    add(event(flags=0x0008 | 0x0001, evprop=0x0003,
              edata=[(E_RELATED, bytes(range(16)))],
              tlvs=[(T_USER, b'\x01\x02\x03')]))
    # 3: classic (MOF) header, message but no properties
    add(event(flags=0x0100 | 0x0200 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0004 | 0x0002,
              evprop=0x000c, provider=G_KERNEL,
              tlvs=[(T_MSG, u16('classic event %1 without properties'))]))
    # 4: TraceLogging: schema with fields, SID, stack trace, provider traits
    add(event(edata=[(E_SCHEMA, schema_tl('MyEvent', [('field1', 0x08), ('name', 0x01), ('blob', 0x2e)])),
                     (E_SID, sid()),
                     (E_STACK64, struct.pack('<Q', 0x1234) + b''.join(struct.pack('<Q', 0x7ff600001000 + 16 * k) for k in range(3))),
                     (E_TRAITS, struct.pack('<H', 2 + 8) + b'Provider'),
                     (0x0010, b'\x00' * 16)],
              tlvs=[(T_PROV, u16('MyCompany.MyProvider'))], flags=0x0001))
    # 5: provider traits of size 0 and 1 (no name; used to give a length of -2/-1)
    add(event(edata=[(E_TRAITS, struct.pack('<H', 0)), (E_TRAITS, struct.pack('<H', 1) + b'x')], flags=0x0001))
    # 6: extended data pointer past 32 bits is skipped
    add(event(edata=[(E_RELATED, b'\0' * 16)], big_ptr=True, flags=0x0001))
    # 7: all the TLV types: addresses and session id
    add(event(tlvs=[(T_SRC, b'192.0.2.1:49152'), (T_DST, b'192.0.2.2:445'),
                    (T_SESS, struct.pack('<Q', 0x0000000100000007)),
                    (T_PROV, u16('Net-Provider')),
                    (6, b'unknown tlv type'),
                    (T_MSG, u16('Connection %1 opened'))],
              props=[('id', '7')]))
    # 8: no message, user data and properties; timestamp before 1970
    add(event(props=[('k', 'v')], tlvs=[(T_USER, b'abc')], ts=FILETIME_UNIX - 100 * 10000000))
    # 9: message formatting limits: a message close to the 64 KiB limit
    add(event(tlvs=[(T_MSG, u16('x' * 60000 + '%1'))], props=[('v', 'y' * 100)]))
    # 10: the output is capped once the next substitution would exceed 64 KiB
    add(event(tlvs=[(T_MSG, u16('%1 ' * 10))], props=[('v', 'A' * 20000)]))
    # 11: reproducer of "ETW: Bound the formatted message size": a 64 KiB
    #     property value and 48000 substitutions (4.7 GB before the fix)
    add(event(tlvs=[(T_MSG, u16('%1' * 48000))], props=[('k', '\u4e00' * 32767)]))
    # 12: MBIM (inbound, outbound, unknown direction)
    mbim_open = struct.pack('<IIII', 1, 16, 1, 4096)
    add(event(provider=G_MBIM, tlvs=[(T_USER, mbim_open)]), direction=1)
    add(event(provider=G_MBIM, tlvs=[(T_USER, mbim_open)]), direction=2)
    add(event(provider=G_MBIM, tlvs=[(T_USER, mbim_open)]), direction=0)
    add(event(provider=G_MBIM, tlvs=[(T_USER, mbim_open)]))
    # 16: SMB client and server packet events, and an SMB event that is not a packet
    add(event(provider=G_SMBC, eid=40000, tlvs=[(T_USER, smb2_negotiate())]))
    add(event(provider=G_SMBS, eid=2000, tlvs=[(T_USER, smb2_negotiate())]))
    add(event(provider=G_SMBC, eid=1, tlvs=[(T_USER, smb2_negotiate())]))
    # 19: WinInet HTTP: request events 2001/2002, response events 2003/2004
    add(event(provider=G_WININET, eid=2001, tlvs=[(T_USER, http_req())]))
    add(event(provider=G_WININET, eid=2002, tlvs=[(T_USER, http_req())]))
    add(event(provider=G_WININET, eid=2003, tlvs=[(T_USER, http_resp())]))
    add(event(provider=G_WININET, eid=2004, tlvs=[(T_USER, http_resp())]))
    add(event(provider=G_WININET, eid=2005, tlvs=[(T_USER, http_resp())]))
    # 24: WebIO
    for e, body in ((100, http_req()), (101, http_req()), (111, http_resp()), (129, http_resp())):
        add(event(provider=G_WEBIO, eid=e, tlvs=[(T_USER, body)]))
    add(event(provider=G_WEBIO, eid=7, tlvs=[(T_USER, http_req())]))
    # 29: LDAP
    add(event(provider=G_LDAP, eid=12, tlvs=[(T_USER, LDAP_BIND)]))
    add(event(provider=G_LDAP, eid=17, tlvs=[(T_USER, LDAP_BIND_RESP)]))
    add(event(provider=G_LDAP, eid=1, tlvs=[(T_USER, LDAP_BIND)]))
    # 32: Bluetooth (keyword bit 63), and the same provider without the bit
    add(event(provider=G_BTH, keywords=0x8000000000000000, tlvs=[(T_USER, HCI_RESET)]))
    add(event(provider=G_BTH, keywords=0x8000000000000000, tlvs=[(T_USER, HCI_EVENT)]))
    add(event(provider=G_BTH, keywords=0x1, tlvs=[(T_USER, HCI_RESET)]))
    # 35: special provider without user data falls back to the generic data
    add(event(provider=G_MBIM, tlvs=[(T_MSG, u16('no user data'))]))
    ifs = [305]
    # reproducer of the MBIM pseudo-header leak: an ERF record with three
    # extension headers (the third one is 0x4141414141414141) before an
    # MBIM event
    eh = bytes.fromhex('8000000000000000') * 2 + b'\x41' * 8
    eth = bytes.fromhex('020000000002020000000001') + b'\x88\xb5' + b'\0' * 46
    body = eh + b'\0\0' + eth
    rlen = 16 + len(body)
    erf = struct.pack('<Q', 1700000000 << 32) + struct.pack('>BBHHH', 0x82, 0x04, rlen, 0, len(eth) + 4) + body
    R.append((1, erf, None))
    add(event(provider=G_MBIM, tlvs=[(T_USER, mbim_open)]))
    return [305, 197], R


def malformed_records():
    R = []

    def add(rec, ifid=0):
        R.append((ifid, rec, None))
    good = event(tlvs=[(T_MSG, u16('hello %1'))], props=[('k', 'v')])
    add(good[:0x30])                                              # header cut short
    add(good[:0x5C + 4])                                          # TLVs cut short
    add(event(tlvs=[(T_SESS, b'\0' * 9)]))                        # session id of 9 octets
    add(event(tlvs=[(T_SRC, b'x')])[:-1])                         # address past the end
    add(event(tlvs=[(T_MSG, u16('m'))], tlv_count=3))             # more TLVs than present
    add(event(tlvs=[(T_USER, b'abc')], props=[('k', 'v')], prop_count=9))
    add(event(edata=[(E_SID, sid())], edata_count=4))            # more edata than present
    add(event(edata=[(E_SID, sid())])[:-6])                       # SID cut short
    add(event(edata=[(E_SCHEMA, schema_tl('E', [('a', 1)]))])[:-2])
    add(event(edata=[(E_STACK64, struct.pack('<Q', 1))])[:-3])
    add(event(edata=[(E_TRAITS, struct.pack('<H', 200) + b'Prov')]))   # traits size past the end
    add(event(provider=G_MBIM, tlvs=[(T_USER, b'\0' * 7)]))       # MBIM too short
    add(event(provider=G_SMBC, eid=40000, tlvs=[(T_USER, b'\0\0\0\x10\xfeSMB')]))
    add(event(provider=G_WININET, eid=2001, tlvs=[(T_USER, b'GET / HTTP/1.1\r\nHo')]))
    add(event(provider=G_LDAP, eid=12, tlvs=[(T_USER, b'\x30\x84\xff\xff\xff\xff')]))
    add(event(provider=G_BTH, keywords=0x8000000000000000, tlvs=[(T_USER, b'\x04\x0e\x20')]))
    # tlv offset beyond the record
    rec = bytearray(event(tlvs=[(T_USER, b'abc')]))
    struct.pack_into('<I', rec, 0x5C + 4, 0x10000)
    add(bytes(rec))
    # message offset beyond the record
    rec = bytearray(event(tlvs=[(T_MSG, u16('m'))], props=[('a', 'b')]))
    struct.pack_into('<I', rec, 0x5C + 4, 0x7fffffff)
    add(bytes(rec))
    # property key length past the end
    rec = bytearray(event(props=[('k', 'v')]))
    struct.pack_into('<H', rec, 0x5C + 4, 0xfff0)
    add(bytes(rec))
    # provider name offset beyond
    rec = bytearray(event(tlvs=[(T_PROV, u16('p'))]))
    struct.pack_into('<I', rec, 0x5C + 4, 0xffff0000)
    add(bytes(rec))
    return [305], R


def main():
    out = sys.argv[1]
    lts, R = main_records()
    pcapng(os.path.join(out, 'etw-coverage.pcapng'), lts, R)
    lts, R = malformed_records()
    pcapng(os.path.join(out, 'etw-coverage-malformed.pcapng'), lts, R)


main()
