#!/usr/bin/env python3
# Generates test/captures/oipf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the OIPF CI+ dissector
(packet-oipf.c, Open IPTV Forum CSPG-CI+ messages).

The messages are carried in DVB-CI (CI+) Specific Application Support (SAS)
sessions: after the host sends the SAS connect request for the application
id 0x0108113101190000 and the CAM confirms it, every SAS async message is
handed to this dissector. The capture is a DVB-CI link layer capture
(LINKTYPE_DVB_CI, 235): pseudo header, LPDU, TPDU, SPDU and APDU are built
here with struct; nothing comes from a real CAM or host.

Usage: mkoipf.py <output directory>

Writes:
  oipf-coverage.pcap            transport connection and SAS session setup,
                                then OIPF messages of every command and data
                                type, with several data items, empty items and
                                unknown ids; a message too short for the
                                dissector (shown as data)
  oipf-coverage-malformed.pcap  data items that run past the message
"""
import os
import struct
import sys

LT_DVBCI = 235
CAM2HOST = 0xFF
HOST2CAM = 0xFE
TCID = 1
SAS = (0x96 << 16) | (1 << 6) | 1
SESS = 15
OIPF_ID = struct.pack('>Q', 0x0108113101190000)


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82]) + struct.pack('>H', n)


def pseudo(event, payload):
    return struct.pack('>BBH', 0, event, len(payload)) + payload


def lpdu(tcid, tpdu):
    return bytes([tcid, 0x00]) + tpdu


def tpdu_hdr(tag, tcid, body):
    return bytes([tag]) + ber_len(len(body) + 1) + bytes([tcid]) + body


def apdu(tag, body=b''):
    return struct.pack('>I', tag)[1:] + ber_len(len(body)) + body


def spdu_sess_nb(ssnb, a):
    return bytes([0x90, 0x02]) + struct.pack('>H', ssnb) + a


def h2c(spdu):
    return pseudo(HOST2CAM, lpdu(TCID, tpdu_hdr(0xA0, TCID, spdu)))


def c2h(spdu):
    return pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, spdu) + bytes([0x80, 0x02, TCID, 0x00])))


def sas_async(msg_nb, payload, from_cam=True):
    sp = spdu_sess_nb(SESS, apdu(0x9F9A07, bytes([msg_nb]) + struct.pack('>H', len(payload)) + payload))
    return c2h(sp) if from_cam else h2c(sp)


def setup():
    fr = []
    fr.append(pseudo(CAM2HOST, b'\x04\x00'))                                  # CAM buffer size proposal
    fr.append(pseudo(HOST2CAM, b'\x04\x00'))                                  # negotiated buffer size
    fr.append(pseudo(HOST2CAM, lpdu(TCID, tpdu_hdr(0x82, TCID, b''))))        # T_create_t_c
    fr.append(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0x83, TCID, b'') + bytes([0x80, 0x02, TCID, 0x00]))))  # T_c_t_c_reply
    fr.append(h2c(bytes([0x93, 0x06]) + struct.pack('>IH', SAS, SESS)))        # create session (SAS)
    fr.append(c2h(bytes([0x94, 0x07, 0x00]) + struct.pack('>IH', SAS, SESS)))  # create session response
    fr.append(h2c(spdu_sess_nb(SESS, apdu(0x9F9A00, OIPF_ID))))                # SAS connect request
    fr.append(c2h(spdu_sess_nb(SESS, apdu(0x9F9A01, OIPF_ID + b'\x00'))))      # SAS connect confirm: connected
    return fr


def item(dat_id, data):
    return bytes([dat_id]) + struct.pack('>H', len(data)) + data


def oipf(cmd, ca_sys, trx, items, nitems=None):
    return (struct.pack('>BHIB', cmd, ca_sys, trx, len(items) if nitems is None else nitems)
            + b''.join(items))


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, LT_DVBCI))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def main_capture(path):
    fr = setup()
    n = 0

    def add(payload, from_cam=True):
        nonlocal n
        n += 1
        fr.append(sas_async(n, payload, from_cam))
    # every command id, every data type id
    for cmd in (1, 2, 3, 4, 5, 6, 0xff):
        add(oipf(cmd, 0x0b00 + cmd, 0x1000 + cmd, [item(cmd % 8 + 1, b'DEU')]), from_cam=cmd % 2 == 1)
    add(oipf(1, 0x0b00, 0x2000, [item(1, b'\x01\x02\x03'), item(2, b'DEU'), item(3, b'http://example.invalid/pc'),
                                  item(4, b'\x02'), item(5, b'\x0c'), item(6, b'http://example.invalid/ri'),
                                  item(7, b'\x01'), item(8, b'\x00')]))
    add(oipf(2, 0x0b00, 0x2001, [item(9, b'unknown id'), item(0xff, b'x'), item(0, b'')]))
    add(oipf(3, 0x0b00, 0x2002, []))                                          # no items
    add(oipf(4, 0x0b00, 0x2003, [item(1, b''), item(2, b'')]))                 # empty items
    add(oipf(5, 0xffff, 0xffffffff, [item(1, bytes(300))]))                    # long item
    add(oipf(1, 0x0b00, 0x2004, [item(2, b'DEU')]) + b'\xde\xad\xbe\xef')     # trailing data after the items
    add(b'\x01\x0b\x00\x00\x00\x20\x00')                                      # 7 octets: too short, shown as data
    add(b'\x01\x0b')                                                          # 2 octets
    write(path, fr)


def malformed_capture(path):
    fr = setup()
    n = 0

    def add(payload):
        nonlocal n
        n += 1
        fr.append(sas_async(n, payload))
    add(oipf(1, 0x0b00, 1, [item(2, b'DEU')], nitems=3))                       # one item more than present
    m = oipf(1, 0x0b00, 2, [item(2, b'DEU')])
    add(m[:-1])                                                                # item data cut
    add(m[:-3])                                                                # item length cut
    add(m[:-5])                                                                # item id cut? (only the id)
    add(oipf(1, 0x0b00, 3, [bytes([2]) + struct.pack('>H', 1000) + b'abc']))   # length beyond the message
    write(path, fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'oipf-coverage.pcap'))
    malformed_capture(os.path.join(out, 'oipf-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
