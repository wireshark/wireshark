#!/usr/bin/env python3
# Generates test/captures/asf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for coverage of epan/dissectors/packet-asf.c
# (Alert Standard Forum, RMCP class 6 on UDP port 623). Every packet is
# built with struct; nothing comes from a real network.
# Usage: mkasf.py <outdir>
# Writes asf-coverage.pcap (clean) and asf-coverage-malformed.pcap.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

CONSOLE = [192, 0, 2, 1]   # management console
CLIENT = [192, 0, 2, 50]   # managed client
MAC_CONSOLE = bytes.fromhex('020000000001')
MAC_CLIENT = bytes.fromhex('020000000032')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


ip_id = [0]


def frame(payload, to_client=True, sport=None, dport=623):
    src, dst = (CONSOLE, CLIENT) if to_client else (CLIENT, CONSOLE)
    if sport is None:
        sport, dport = (49152, dport) if to_client else (dport, 49152)
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    ip_id[0] += 1
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ip_id[0], 0x4000, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_CONSOLE, MAC_CLIENT) if to_client else (MAC_CLIENT, MAC_CONSOLE)
    return dmac + smac + b'\x08\x00' + ip + u


def rmcp(seq=0xff, cls=0x06):
    return bytes([0x06, 0x00, seq, cls])


def asf(typ, data=b'', tag=0x00, declared=None, iana=4542):
    return struct.pack('!IBBBB', iana, typ, tag, 0,
                       len(data) if declared is None else declared) + data


def payload(ptype, body=b'', plen=None):
    return struct.pack('!BBH', ptype, 0, 4 + len(body) if plen is None else plen) + body


AUTH = payload(1, bytes([1, 0, 0, 0]))     # RAKP-HMAC-SHA1
INTEG = payload(2, bytes([1, 0, 0, 0]))    # HMAC-SHA1-96

clean = []      # (frame bytes, description)
bad = []


def c(desc, data, to_client=True, **kw):
    clean.append((frame(data, to_client, **kw), desc))


def m(desc, data, to_client=True, **kw):
    bad.append((frame(data, to_client, **kw), desc))


tag = [0]


def t():
    tag[0] = (tag[0] + 1) % 0xff
    return tag[0]


# Discovery
k = t()
c('Presence Ping', rmcp() + asf(0x80, tag=k))
c('Presence Pong (IANA, OEM, entities, interactions)',
  rmcp() + asf(0x40, struct.pack('!IIBB6s', 4542, 0, 0x81, 0x00, b'\0' * 6), tag=k), False)
k = t()
c('Capabilities Request', rmcp() + asf(0x81, tag=k))
c('Capabilities Response',
  rmcp() + asf(0x41, struct.pack('!IIBBBBBBH', 4542, 0, 0x0f, 0x1f, 0x3f, 0x03, 0x07, 0, 0), tag=k),
  False)
k = t()
c('System State Request', rmcp() + asf(0x82, tag=k))
c('System State Response', rmcp() + asf(0x42, bytes([0x00, 0x00]), tag=k), False)
# Remote control (with boot options)
boot = struct.pack('!IBHHH', 4542, 0, 0, 0, 0)
for typ, name in ((0x10, 'Reset'), (0x11, 'Power-up'), (0x12, 'Unconditional Power-down'),
                  (0x13, 'Power Cycle')):
    c(name, rmcp() + asf(typ, boot, tag=t()))
# Secure session setup (RSSP)
k = t()
c('Open Session Request: auth and integrity payloads',
  rmcp() + asf(0x83, struct.pack('!I', 0x01020304) + AUTH + INTEG, tag=k))
c('Open Session Response: no errors, both payloads',
  rmcp() + asf(0x43, bytes([0, 0, 0, 0]) + struct.pack('!II', 0x01020304, 0x0a0b0c0d)
               + AUTH + INTEG, tag=k), False)
k = t()
c('Open Session Request: unknown algorithms, end-of-list payload, '
  'unknown payload type with data, empty payload, 2 octets left',
  rmcp() + asf(0x83, struct.pack('!I', 7)
               + payload(1, bytes([2, 0, 0, 0]))     # unknown auth algorithm
               + payload(2, bytes([0x7f, 0, 0]))     # unknown integrity algorithm
               + payload(0)                          # end of list (4 octets)
               + payload(9, b'\xaa\xbb\xcc\xdd')     # unknown payload type
               + payload(1)                          # authentication, no body
               + payload(2, b'\x01')                 # integrity, alg only
               + b'\x00\x00', tag=k))
c('Open Session Response: invalid authentication algorithm, no payloads',
  rmcp() + asf(0x43, bytes([4, 0, 0, 0]) + struct.pack('!II', 7, 0), tag=k), False)
for status in (1, 2, 3, 5, 6, 7, 8):
    k = t()
    c('Open Session Request: console ID only (status %d response follows)' % status,
      rmcp() + asf(0x83, struct.pack('!I', 100 + status), tag=k))
    c('Open Session Response: status %d' % status,
      rmcp() + asf(0x43, bytes([status, 0, 0, 0]) + struct.pack('!II', 100 + status, 0), tag=k),
      False)
# A message followed by octets after its data length: they are not
# dissected as ASF (they would have been read as payloads before the fix
# only when the fixed fields ran past the length; here they must not
# appear at all)
k = t()
c('Open Session Response: length 12 followed by octets that look like payloads',
  rmcp() + asf(0x43, bytes([0, 0, 0, 0]) + struct.pack('!II', 0x11, 0x22), tag=k)
  + AUTH + INTEG, False)
c('Open Session Request: length 20, trailing octets after the message',
  rmcp() + asf(0x83, struct.pack('!I', 0x33) + AUTH + INTEG, tag=k) + payload(9, b'\xee' * 4))
# Session close and RAKP (shown as data)
k = t()
c('Close Session Request', rmcp() + asf(0x84, struct.pack('!I', 0x0a0b0c0d), tag=k))
c('Close Session Response', rmcp() + asf(0x44, bytes([0]), tag=k), False)
k = t()
c('RAKP Message 1', rmcp() + asf(0xc0, struct.pack('!I', 0x0a0b0c0d) + bytes(range(16))
                                 + b'\0' * 4 + bytes(16) + b'\0\0', tag=k))
c('RAKP Message 2', rmcp() + asf(0xc1, bytes([0, 0, 0, 0]) + struct.pack('!I', 0x01020304)
                                 + bytes(range(16, 32)) + bytes(16) + bytes(20), tag=k), False)
k = t()
c('RAKP Message 3', rmcp() + asf(0xc2, bytes([0, 0, 0, 0]) + struct.pack('!I', 0x0a0b0c0d)
                                 + bytes(20), tag=k))
c('Unknown message type 0x55', rmcp() + asf(0x55, b'\x01\x02\x03', tag=t()))
c('Unknown message type 0x55, no data', rmcp() + asf(0x55, tag=t()), False)
# An RMCP ACK (no ASF message) and an ASF message with a sequence number
c('RMCP ACK of class ASF (no data)', rmcp(seq=5, cls=0x86), False)
c('Presence Ping with RMCP sequence 5', rmcp(seq=5) + asf(0x80, tag=t()))
# Over the RMCP security extension (UDP 664, session 0)
c('RSP: Presence Ping over UDP 664',
  struct.pack('!II', 0, 1) + rmcp() + asf(0x80, tag=t()), dport=664)
# Message tag 0xff (no response expected) and maximum data length
c('Open Session Request: 252 octets of payloads (data length 252)',
  rmcp() + asf(0x83, struct.pack('!I', 0x44) + payload(9, b'\x5a' * 240) + payload(0),
               tag=0xff))

# ---- malformed -----------------------------------------------------------
# The reproducers from asf_len_overrun.py: now malformed
# instead of decoded from the octets after the message.
d = struct.pack('!I', 0x11111111) + struct.pack('!BBH', 1, 0, 8)
m('Reproducer 1: Open Session Request length 8, payload claims 8 octets',
  rmcp() + asf(0x83, d) + bytes([0x01, 0xAA, 0xBB, 0xCC]))
m('Reproducer 2: Open Session Response length 1',
  rmcp() + asf(0x43, b'\x00') + bytes(range(1, 12)))
m('Payload length 2 (< 4): payload too short', rmcp() + asf(0x83, struct.pack('!I', 1)
                                                            + payload(1, plen=2)))
m('Payload length 0: payload too short', rmcp() + asf(0x43, bytes(4) + bytes(8)
                                                      + payload(2, plen=0)), False)
m('Data length past the end of the packet', rmcp() + asf(0x40, b'\x00' * 4, declared=16), False)
m('Open Session Request with 2 octets', rmcp() + asf(0x83, b'\x00\x01'))
m('Open Session Response with 8 octets', rmcp() + asf(0x43, bytes(8)), False)
m('Payload longer than the message', rmcp() + asf(0x83, struct.pack('!I', 1) + payload(1, b'\x01', plen=40)))
m('Integrity payload longer than the message',
  rmcp() + asf(0x43, bytes(12) + payload(2, b'\x01\x00', plen=8)), False)
m('ASF header cut short', rmcp() + struct.pack('!IB', 4542, 0x80))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (p, desc) in enumerate(frames):
            ts = 1700000000 + i
            f.write(struct.pack('<IIII', ts, (i * 1000) % 1000000, len(p), len(p)) + p)


os.makedirs(OUT, exist_ok=True)
write_pcap(os.path.join(OUT, 'asf-coverage.pcap'), clean)
write_pcap(os.path.join(OUT, 'asf-coverage-malformed.pcap'), bad)
with open(os.path.join(OUT, 'frames.txt'), 'w') as f:
    for name, frames in (('asf-coverage.pcap', clean), ('asf-coverage-malformed.pcap', bad)):
        f.write('%s\n' % name)
        for i, (p, desc) in enumerate(frames):
            f.write('%3d  %s\n' % (i + 1, desc))
