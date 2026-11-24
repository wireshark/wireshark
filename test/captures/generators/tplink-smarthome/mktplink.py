#!/usr/bin/env python3
# Generates test/captures/tplink-smarthome_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds tplink-smarthome-coverage.pcapng and ...-malformed.pcap
import struct
import sys
import os
import json
from pcaplib import Flow, write, write_ng, udp, exported_pdu, exp_tag

def enc(text):
    """TP-Link autokey XOR: key starts at 171, then is the previous cipher byte."""
    key, out = 171, bytearray()
    for ch in text if isinstance(text, bytes) else text.encode():
        c = ch ^ key
        out.append(c)
        key = c
    return bytes(out)

def j(o):
    return json.dumps(o, separators=(',', ':'))

def main(out):
    fr = []   # (interface, frame)
    E = lambda b: (0, b)
    # UDP discovery: command to port 9999, response from port 9999
    fr.append(E(udp(51000, 9999, enc(j({'system': {'get_sysinfo': {}}})))))
    fr.append(E(udp(9999, 51000, enc(j({'system': {'get_sysinfo': {'sw_ver': '1.5.6', 'model': 'HS100(EU)',
        'alias': 'Lamp', 'relay_state': 1, 'on_time': 3600, 'err_code': 0}}})), src='192.0.2.2', dst='192.0.2.1')))
    fr.append(E(udp(51001, 9999, enc('{}'))))                        # {} is accepted
    fr.append(E(udp(51002, 9999, enc(j({'emeter': {'get_realtime': {}}, 'schedule': {'get_rules': {}}})))))
    fr.append(E(udp(9999, 9999, enc(j({'system': {'set_relay_state': {'state': 1}}})))))   # both ports: Cmd
    fr.append(E(udp(51003, 9999, enc('{"a":"\x01\x02 control characters \x7f"}'))))      # not printable -> '.'
    # UDP that is not TP-Link: first octet decodes to another character, second not " or }
    fr.append(E(udp(51005, 9999, b'\x00\x01\x02\x03')))
    fr.append(E(udp(51006, 9999, enc('{x'))))
    fr.append(E(udp(51007, 9999, enc('{'))))                           # fewer than 2 octets
    # TCP: length-prefixed
    f = Flow(52000, 9999)
    def msg(o):
        e = enc(j(o) if not isinstance(o, str) else o)
        return struct.pack('!I', len(e)) + e
    fr.append(E(f.seg(msg({'system': {'get_sysinfo': {}}}))))
    fr.append(E(f.seg(msg({'system': {'get_sysinfo': {'alias': 'Plug', 'relay_state': 0}}}), client=False)))
    fr.append(E(f.seg(msg({'a': 1}) + msg({'b': 2}) + msg({'c': [1, 2, 3]}))))     # three messages in one segment
    p = msg({'system': {'set_dev_alias': {'alias': 'a rather long alias for splitting'}}})
    fr.append(E(f.seg(p[:2])))                                        # length field split
    fr.append(E(f.seg(p[2:10])))
    fr.append(E(f.seg(p[10:])))
    fr.append(E(f.seg(msg({'x': 1}) + p[:12])))                       # complete message and the start of the next
    fr.append(E(f.seg(p[12:])))
    fr.append(E(f.seg(msg('{}'))))
    # TCP stream on the port that does not start with a TP-Link message: not claimed
    g = Flow(52001, 9999)
    fr.append(E(g.seg(b'\x00\x00\x00\x08ABCDEFGH')))
    fr.append(E(g.seg(msg({'late': True}))))                          # still not claimed (conversation not marked)
    # TCP stream where the message starts after a valid first one on the same conversation
    h = Flow(52002, 9999)
    fr.append(E(h.seg(msg({'first': 1}))))
    fr.append(E(h.seg(b'\x00\x00\x00\x06garbage'.ljust(10, b'!'))))   # conversation marked; the PDU does not decode
    # Exported PDU (PT_NONE): the message handler declines
    fr.append((1, exported_pdu('tplink-smarthome-message', enc(j({'system': {'get_sysinfo': {}}})))))
    # Exported PDU with a TCP / UDP port type and ports: Cmd, Rsp and, with neither port 9999, Msg
    def ports(pt, sp, dp):
        return (exp_tag(24, struct.pack('!I', pt)) + exp_tag(25, struct.pack('!I', sp)) +
                exp_tag(26, struct.pack('!I', dp)))
    body = enc(j({'system': {'get_sysinfo': {}}}))
    L = struct.pack('!I', len(body))
    fr.append((1, exported_pdu('tplink-smarthome-message', L + body, ports(2, 40000, 9999))))
    fr.append((1, exported_pdu('tplink-smarthome-message', L + body, ports(2, 9999, 40000))))
    fr.append((1, exported_pdu('tplink-smarthome-message', L + body, ports(2, 1234, 1234))))
    fr.append((1, exported_pdu('tplink-smarthome-message', body, ports(3, 9999, 40000))))
    fr.append((1, exported_pdu('tplink-smarthome-message', b'\0\0\0\x03abc', ports(2, 1234, 9999))))   # not TP-Link data: declined
    write_ng(os.path.join(out, 'tplink-smarthome-coverage.pcapng'), [1, 252], fr)
    print('main frames', len(fr))
    # malformed: a length field larger than the data on a closed connection; truncated JSON
    m = []
    m.append(udp(51004, 9999, enc('{"unterminated":')))      # JSON cut short: malformed
    k = Flow(53000, 9999)
    e = enc(j({'system': {'get_sysinfo': {}}}))
    m.append(k.seg(struct.pack('!I', 0xffffffff) + e))                # huge length: reassembly waits
    k2 = Flow(53001, 9999)
    m.append(k2.seg(struct.pack('!I', 4000) + e))
    m.append(k2.seg(b'\x00' * 3000, client=False))
    write(os.path.join(out, 'tplink-smarthome-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
