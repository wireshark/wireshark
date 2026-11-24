#!/usr/bin/env python3
# Generates test/captures/dxl_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DXL dissector
(packet-dxl.c, OpenDXL "Data Exchange Layer").

DXL messages are carried as MQTT PUBLISH payloads. No dissector calls
"dxl" on its own: MQTT hands a payload to it only through the MQTT
"Message Decoding" table (mqtt_message_decoding UAT), and Wireshark's
own Exported PDU files name it directly. The main capture (pcapng, two
interfaces) therefore holds both: Exported PDU records (link type 252)
with the dissector name "dxl", decoded at default preferences, and on
an Ethernet interface an MQTT 3.1.1 session
over TCP port 1883 whose PUBLISH messages on /mcafee/... topics decode
as DXL with a UAT entry. A DXL message is a version octet, a type octet
and, for an event, eight MessagePack objects (message ID, client ID,
source broker ID, broker IDs, client IDs, payload, reply-to topic,
service ID). Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkdxl.py <output directory>

Writes:
  dxl-coverage.pcapng          frames 1-7 Exported PDU (link type 252):
                               events with strings, arrays and bin/str
                               payloads, the unsupported request,
                               response and error types, an unknown
                               type; frames 8-19 the same messages in
                               MQTT PUBLISH over TCP (decoded as DXL
                               with the MQTT UAT)
  dxl-coverage-malformed.pcap  Exported PDU: a header without the type,
                               events cut short
"""

import os
import struct
import sys

from pcaplib import TcpFlow, write_pcap, write_pcapng  # noqa: E402


def mp_str(s):
    b = s.encode()
    if len(b) < 32:
        return bytes([0xa0 | len(b)]) + b
    if len(b) < 256:
        return b'\xd9' + bytes([len(b)]) + b
    return b'\xda' + struct.pack('>H', len(b)) + b


def mp_bin(b):
    return b'\xc4' + bytes([len(b)]) + b


def mp_array(items):
    assert len(items) < 16
    return bytes([0x90 | len(items)]) + b''.join(items)


def dxl(mtype, body=b'', version=3):
    return bytes([version, mtype]) + body


def event(msgid, client, broker, brokers, clients, payload, reply, service):
    return dxl(2, mp_str(msgid) + mp_str(client) + mp_str(broker)
               + mp_array([mp_str(b) for b in brokers])
               + mp_array([mp_str(c) for c in clients])
               + payload + mp_str(reply) + mp_str(service))


def exp_tag(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def exported_pdu(name, payload):
    return exp_tag(12, name.encode()) + struct.pack('>HH', 0, 0) + payload


def messages():
    """(topic, DXL message) pairs."""
    M = []
    # 1: event with one broker and one client, bin payload
    M.append(('/mcafee/event/sample', event(
        '{4b9a3c2e-0001-4d1e-9e0f-000000000001}',
        '{c0ffee00-0000-4000-8000-000000000001}',
        '{b0b0b0b0-0000-4000-8000-000000000001}',
        ['{b0b0b0b0-0000-4000-8000-000000000001}'],
        ['{c0ffee00-0000-4000-8000-000000000002}'],
        mp_bin(b'{"severity": 3}'), '', '')))
    # 2: event with no brokers/clients, string payload, reply topic and
    #    service ID
    M.append(('/mcafee/event/sample', event(
        'id-2', 'client-a', 'broker-1', [], [],
        mp_str('hello'), '/mcafee/client/client-a', 'svc-17')))
    # 3: event with three brokers and two clients, empty payload
    M.append(('/mcafee/event/other', event(
        'id-3', 'client-b', 'broker-2', ['broker-1', 'broker-2', 'broker-3'],
        ['client-a', 'client-b'], mp_bin(b''), '', '')))
    # 4-6: request, response and error: not decoded, "unsupported"
    M.append(('/mcafee/service/x', dxl(0, mp_str('id-4'))))
    M.append(('/mcafee/client/client-a', dxl(1, mp_str('id-5'))))
    M.append(('/mcafee/client/client-a', dxl(3, mp_str('id-6'))))
    # 7: unknown type 7: only version and type
    M.append(('/mcafee/event/sample', dxl(7, b'\x00\x01', version=2)))
    return M


def mqtt_publish(topic, payload):
    t = topic.encode()
    var = struct.pack('>H', len(t)) + t + payload
    ln = len(var)
    rl = b''
    while True:
        b = ln & 0x7f
        ln >>= 7
        rl += bytes([b | (0x80 if ln else 0)])
        if not ln:
            break
    return b'\x30' + rl + var


def mqtt_connect(client_id):
    c = client_id.encode()
    var = struct.pack('>H', 4) + b'MQTT' + bytes([4, 0x02]) + struct.pack('>H', 60)
    var += struct.pack('>H', len(c)) + c
    return b'\x10' + bytes([len(var)]) + var


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    msgs = messages()
    fl = TcpFlow(50000, 1883, '192.0.2.10', '192.0.2.20')
    F = [(0, exported_pdu('dxl', m)) for _, m in msgs]
    F += [(1, f) for f in fl.handshake()]
    F.append((1, fl.send(mqtt_connect('client-a'))))
    F.append((1, fl.send(b'\x20\x02\x00\x00', reverse=True)))     # CONNACK
    for i, (topic, m) in enumerate(msgs):
        F.append((1, fl.send(mqtt_publish(topic, m), reverse=bool(i % 2))))
    write_pcapng(os.path.join(out, 'dxl-coverage.pcapng'), [252, 1], F)
    bad = [dxl(2)[:1],
           event('id-8', 'client-a', 'broker-1', [], [], mp_str('x'), '', '')[:-1],
           dxl(2, mp_str('id-9') + mp_str('client-a'))]
    write_pcap(os.path.join(out, 'dxl-coverage-malformed.pcap'),
               [exported_pdu('dxl', m) for m in bad], linktype=252)


if __name__ == '__main__':
    main()
