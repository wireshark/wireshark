#!/usr/bin/env python3
# Generates test/captures/megaco_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the MEGACO (H.248 text) dissector
(packet-megaco.c).

MEGACO text is registered by default on UDP, TCP and SCTP port 2944 and
for SCTP PPID 7.  Every packet is built with struct; nothing comes from a
real network (192.0.2.0/24).

Usage: mkmegaco.py <output directory>
  megaco-coverage.pcap            long and short form messages with every
                                  command, descriptor, termination id,
                                  context kind; error, pending and ack
                                  transactions; SDP, H.245 and statistics;
                                  TCP with TPKT, SCTP with fragments,
                                  heuristic fallbacks (binary, other)
  megaco-coverage-malformed.pcap  parse errors and truncated messages
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000001')
SMAC = bytes.fromhex('020000000002')
CIP = bytes([192, 0, 2, 1])
SIP = bytes([192, 0, 2, 2])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip_frame(proto, l4, c2s=True, ipid=[1]):
    sip, dip = (CIP, SIP) if c2s else (SIP, CIP)
    smac, dmac = (CMAC, SMAC) if c2s else (SMAC, CMAC)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(l4), ipid[0], 0x4000, 64, proto, 0) + sip + dip
    ipid[0] += 1
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return dmac + smac + b'\x08\x00' + ip + l4


def udp(payload, c2s=True, sport=2944, dport=2944):
    l4 = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ip_frame(17, l4, c2s)


class Tcp:
    def __init__(self, frames, cport, sport=2944):
        self.f, self.cport, self.sport = frames, cport, sport
        self.cseq, self.sseq = 100, 900

    def seg(self, c2s, flags, payload=b''):
        opts = b''
        if flags & 2:
            opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        if c2s:
            sp, dp, seq, ack = self.cport, self.sport, self.cseq, self.sseq
        else:
            sp, dp, seq, ack = self.sport, self.cport, self.sseq, self.cseq
        if flags == 2:
            ack = 0
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        sip, dip = (CIP, SIP) if c2s else (SIP, CIP)
        ph = sip + dip + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.f.append(ip_frame(6, t, c2s))
        n = len(payload) + (1 if flags & 3 else 0)
        if c2s:
            self.cseq += n
        else:
            self.sseq += n

    def handshake(self):
        self.seg(True, 2)
        self.seg(False, 0x12)
        self.seg(True, 0x10)

    def data(self, c2s, payload):
        self.seg(c2s, 0x18, payload)
        self.seg(not c2s, 0x10)


def tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload


def crlf(s):
    return s.replace('\n', '\r\n').encode()


def sctp(chunks, c2s=True, sport=2944, dport=2944, vtag=0x11223344):
    body = b''
    for c in chunks:
        body += c + b'\0' * (-len(c) % 4)
    l4 = struct.pack('>HHII', sport, dport, vtag, 0) + body
    return ip_frame(132, l4, c2s)


def data_chunk(payload, tsn, sid=0, ssn=0, flags=3, ppid=7):
    return struct.pack('>BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppid) + payload


SDP_L = 'v=0\nc=IN IP4 192.0.2.1\nm=audio 4000 RTP/AVP 0\na=ptime:20\n'
SDP_R = 'v=0\nc=IN IP4 192.0.2.2\nm=audio 5000 RTP/AVP 0 8\n'


def msg(body, mid='[192.0.2.1]:2944', ver=1):
    return 'MEGACO/%d %s\n%s' % (ver, mid, body)


def sf(body, mid='[192.0.2.1]:2944', ver=1):
    return '!/%d %s\n%s' % (ver, mid, body)


MSGS = []   # (label, text bytes)
MALF = []


def add(text, label=''):
    MSGS.append((label, text if isinstance(text, bytes) else crlf(text)))


def build_messages():
    # --- every command, request and reply, long form, in various contexts
    cmds = ['Add', 'Modify', 'Subtract', 'Move', 'AuditValue', 'AuditCapability',
            'Notify', 'ServiceChange']
    n = 1
    for c, ctx in zip(cmds, ['$', '1', '*', '-', '7', '$', '2', '-']):
        add(msg('Transaction = %d {\n Context = %s {\n  %s = A%d\n }\n}\n' % (n, ctx, c, n)), 'req ' + c)
        add(msg('Reply = %d {\n Context = %s {\n  %s = A%d\n }\n}\n' % (n, ctx, c, n)), 'reply ' + c)
        n += 1
    # an unknown command name
    add(msg('Transaction = 20 {\n Context = 1 {\n  Frobnicate = A1\n }\n}\n'))
    add(msg('Reply = 20 {\n Context = 1 {\n  Frobnicate = A1\n }\n}\n'))
    # optional and wildcard prefixes (O- and W-)
    add(msg('Transaction = 21 {\n Context = $ {\n  O-Add = $,\n  W-Modify = *,\n  O-W-Subtract = ROOT\n }\n}\n'))
    # commands without descriptors, several commands, termination ids
    add(msg('Transaction = 22 {\n Context = 3 {\n  Add = ephemeral/1/2, Modify = e/5 { Media { TerminationState { ServiceStates = InService } } }, Subtract = * , Move = $\n }\n}\n'))
    add(msg('Transaction = 23 {\n Context = 3 {\n  Subtract = ep/1/x\n }\n}\n'))
    # several contexts in one transaction, several transactions in a message
    add(msg('Transaction = 24 {\n Context = 1 {\n  Add = A1 { Media { Stream = 1 { LocalControl { Mode = SendReceive } } } },\n  Add = A2\n },\n Context = $ {\n  Modify = B1 { Events = 5 { al/on } }\n }\n}\n'))
    add(msg('Transaction = 25 {\n Context = 1 {\n  Modify = A1\n }\n}\nTransaction = 26 {\n Context = 2 {\n  Modify = A2\n }\n}\n'))
    # priority, topology (before the command, after the context), compact tokens
    add(msg('Transaction = 27 {\n Context = 4 {\n  Priority = 3,\n  Topology { A1, A2, bothway },\n  Add = A1\n }\n}\n'))
    add(msg('Transaction = 28 {\n Context = 5 {\n  Topology { A1, A2, isolate }\n }\n}\n'))
    add(msg('Transaction = 29 {\n Context = 5 {\n  Topology { A1, A2, oneway },\n  Topology { A3, A1, isolate }\n }\n}\n'))
    # --- Error, Pending, ResponseAck
    add(msg('Error = 400 {\n "Syntax error in message"\n}\n'))
    add(msg('Error = 504 { "Command Received from unauthorized entity" }\n'))
    add(msg('Error = 999 { "Not in the table" }\n'))
    add(msg('Pending = 17 { }\n'))
    add(msg('TransactionResponseAck { 17 }\n'))
    add(msg('TransactionResponseAck { 17-20, 25 }\n'))
    add(msg('Reply = 30 {\n Error = 501 { "Not Implemented" }\n}\n'))
    add(msg('Reply = 31 {\n ImmAckRequired,\n Context = 1 {\n  Modify = A1\n }\n}\n'))
    add(msg('Reply = 32 {\n Context = 1 {\n  Add = A1,\n  Error = 430 { "Unknown TerminationID" }\n }\n}\n'))
    add(msg('Transaction = 33 {\n Context = 1 {\n  Add = A1 { Error = 440 { "Unsupported or unknown Package" } }\n }\n}\n'))
    # --- Media: stream, local control, local/remote SDP, termination state, statistics
    add(msg('Transaction = 40 {\n Context = $ {\n  Add = $ {\n   Media {\n    Stream = 1 {\n     LocalControl {\n      Mode = SendReceive,\n      ReservedValue = on,\n      ReservedGroup = off,\n      ds/dscp = 2e,\n      tman/sdr = 100,\n      tman/pol = on,\n      tman/mbs = 200,\n      tman/pdr = 300,\n      tman/dvt = 10,\n      gm/saf = on, gm/sam = 1, gm/spf = 2, gm/spr = 3, gm/esas = on, gm/rsb = 1, gm/lsa = 1, gm/esps = 1, gm/lsp = 1,\n      ipdc/realm = foo,\n      vendor/x = 5\n     },\n     Local {\n' + SDP_L + '     },\n     Remote {\n' + SDP_R + '     }\n    },\n    Stream = 2 {\n     LocalControl { Mode = Inactive }\n    },\n    TerminationState { ServiceStates = InService, EventBufferControl = OFF, vendor/p = 3 },\n    Statistics { nt/os = 1, nt/or = 2 }\n   }\n  }\n }\n}\n'), 'media rich')
    add(msg('Reply = 40 {\n Context = 9 {\n  Add = A1 {\n   Media {\n    Stream = 1 {\n     Local {\n' + SDP_L + '     }\n    }\n   }\n  }\n }\n}\n'), 'media reply, context 9')
    add(msg('Transaction = 41 {\n Context = - {\n  Modify = A4 {\n   Media {\n    Stream = 1 { Local { ' + 'v=0\nc=IN IP4 192.0.2.3\nm=audio 6000 RTP/AVP 18\n' + ' } }\n   }\n  }\n }\n}\n'), 'local in null context')
    add(msg('Transaction = 42 {\n Context = 1 {\n  Modify = A1 {\n   Media {\n    LocalControl { Mode = ReceiveOnly },\n    Local { v=0\nm=audio 4000 RTP/AVP 0\n },\n    Remote { v=0\nm=audio 5000 RTP/AVP 0\n }\n   }\n  }\n }\n}\n'), 'media without stream')

    for i, h in enumerate(('a0b1c2', 'A0B1C2', 'f')):
        MALF.append(('h245 hex letters %d' % i, crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = %s } }\n  }\n }\n}\n' % h))))
        MALF.append(('h223capr hex letters %d' % i, crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/h223capr = %s } } }\n  }\n }\n}\n' % h))))
        MALF.append(('h245 muxtbl hex letters %d' % i, crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/muxtbl_in = %s } } }\n  }\n }\n}\n' % h))))
    MALF.append(('h245 non hex character after digits', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = 42zz } }\n  }\n }\n}\n'))))
    MALF.append(('observed events h245 not decodable', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 1 { h245/x { h245 = a0b1 } }\n  }\n }\n}\n'))))
    MALF.append(('observed events invalid offset', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 1 { al/on { a = b } al/of }\n  }\n }\n}\n'))))
    MALF.append(('topology without a closing brace', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Topology { A1, A2'))))
    MALF.append(('invalid sdr', crlf(msg('Transaction = 43 {\n Context = 1 {\n  Modify = A1 {\n   Media {\n    Stream = 1 { LocalControl { Mode = SendOnly, tman/sdr = abc } }\n   }\n  }\n }\n}\n'))))

    MALF.append(('audit without braces', crlf(msg('Transaction = 140 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit\n  }\n }\n}\n'))))
    MALF.append(('no slash', crlf('MEGACO 1 [192.0.2.1]:2944\nPending = 1 { }\n')))
    MALF.append(('no SEP after version', crlf('MEGACO/1[192.0.2.1]:2944\nPending = 1 { }\n')))
    MALF.append(('no body', crlf('MEGACO/1 [192.0.2.1]:2944')))
    MALF.append(('unknown message body', crlf(msg('Frobnicate = 1 { }\n'))))
    MALF.append(('empty braces', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 { }\n }\n}\n'))))
    MALF.append(('no braces after context', crlf(msg('Transaction = 1 {\n Context = 1\n}\n'))))
    MALF.append(('truncated topology', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Topology { A1, A2, isolate'))))
    MALF.append(('command without =', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Add\n }\n}\n'))))
    MALF.append(('empty termination id', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Add =\n }\n}\n'))))
    MALF.append(('long termination id', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Add = ' + 'e' * 40 + '\n }\n}\n'))))
    MALF.append(('unknown short command', crlf(sf('T=1{C=1{Z=A1}}\n'))))
    MALF.append(('invalid reason', crlf(msg('Transaction = 1 {\n Context = - {\n  ServiceChange = ROOT {\n   Services { Method = Forced, Reason = 9x }\n  }\n }\n}\n'))))
    MALF.append(('invalid error code', crlf(msg('Error = abc { "text" }\n'))))
    MALF.append(('local control without =', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { Mode } } }\n  }\n }\n}\n'))))
    MALF.append(('unbalanced braces', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 { Events = 1 { al/on }\n }\n'))))
    MALF.append(('audit with local/remote and no SDP', crlf(msg('Transaction = 1 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Media { Stream = 1 { Local, Remote } } }\n  }\n }\n}\n'))))
    MALF.append(('audit events then signals', crlf(msg('Transaction = 1 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Events = 1 { al/on }, Signals }\n  }\n }\n}\n'))))
    MALF.append(('audit events with several', crlf(msg('Transaction = 1 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Events = 1 { al/on, dd/ce { ds = 1 } } }\n  }\n }\n}\n'))))
    MALF.append(('h245 events not decodable', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = 0a1b2c } }\n  }\n }\n}\n'))))
    MALF.append(('h245 no =', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 } }\n  }\n }\n}\n'))))
    MALF.append(('h245 no hex', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = zz } }\n  }\n }\n}\n'))))
    MALF.append(('h245 odd hex digits', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = 4 } }\n  }\n }\n}\n'))))
    MALF.append(('h223capr no =', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/h223capr = } } }\n  }\n }\n}\n'))))
    MALF.append(('h223capr not decodable', crlf(msg('Transaction = 1 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/h223capr = 0A0B0C } } }\n  }\n }\n}\n'))))
    MALF.append(('erlang internal format', bytes.fromhex('836803') + b'\x00\x01\x02\x03'))
    add(msg('Transaction = 44 {\n Context = 1 {\n  Modify = A1 {\n   Media {\n    Stream = 1 { Local { v=0 } }\n   }\n  }\n }\n}\n'), 'short local')
    # compact tokens in media
    add(msg('Transaction = 45 {\n Context = 1 {\n  Modify = A1 {\n   M {\n    ST = 1 {\n     O { MO = SR, RV = on, RG = off },\n     L { v=0\nm=audio 4000 RTP/AVP 0\n },\n     R { v=0\nm=audio 5000 RTP/AVP 0\n }\n    },\n    TS { SV = InService }\n   }\n  }\n }\n}\n'))
    # --- Events, Signals, Observed events, DigitMap, Packages, Audit, Services, Statistics, Modem, Mux
    add(msg('Transaction = 50 {\n Context = 1 {\n  Modify = A1 {\n   Events = 12 {\n    al/on,\n    dd/ce {\n     DigitMap = dmap1\n    },\n    cg/ft { ds = 1 },\n    al/of { strict = exact, other = { nested } }\n   }\n  }\n }\n}\n'))
    add(msg('Transaction = 51 {\n Context = 1 {\n  Modify = A1 {\n   Events = 13 {\n    dd/ce {\n     dm = (0s|00s|[1-7]xxx|8xxxxxxx)\n    }\n   }\n  }\n }\n}\n'), 'events dm')
    add(msg('Transaction = 52 {\n Context = 1 {\n  Modify = A1 {\n   Signals {\n    cg/rt,\n    cg/dt { dur = 1000 },\n    al/ri { d = { a }, e = 1 }\n   }\n  }\n }\n}\n'))
    add(msg('Transaction = 53 {\n Context = 1 {\n  Modify = A1 {\n   Signals { }\n  }\n }\n}\n'))
    add(msg('Transaction = 54 {\n Context = 1 {\n  Modify = A1 {\n   Signals\n  }\n }\n}\n'), 'signals without braces')
    add(msg('Transaction = 55 {\n Context = 1 {\n  Modify = A1 {\n   SG { cg/rt }\n  }\n }\n}\n'), 'compact SG')
    add(msg('Transaction = 56 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 12 {\n    19990729T22000000:al/of,\n    dd/ce { ds = 12345, meth = UM },\n    al/on { a = b, c = d },\n    h245/x { h245 = 42 }\n   }\n  }\n }\n}\n'))
    add(msg('Transaction = 57 {\n Context = 1 {\n  Notify = A1 {\n   OE = 14 {\n    al/on\n   }\n  }\n }\n}\n'), 'compact OE')
    add(msg('Transaction = 58 {\n Context = 1 {\n  Modify = A1 {\n   DigitMap = dmap1 { (0s|00s|[1-7]xxx|8xxxxxxx) },\n   DM = dmap2 { (xxxx) }\n  }\n }\n}\n'))
    add(msg('Transaction = 59 {\n Context = 1 {\n  Modify = A1 {\n   Packages { al-1, rtp-1 { x }, nt-2 }\n  }\n }\n}\n'))
    add(msg('Transaction = 60 {\n Context = 1 {\n  Modify = A1 {\n   PG = 1 { al-1, rtp-1 { x }, nt-2 },\n   Packages = 5 { cg-1 }\n  }\n }\n}\n'))
    add(msg('Transaction = 61 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Media, Signals, Packages, Statistics { nt/os }, DigitMap { dm1 }, Mux, Modem, ObservedEvents, Topology, Events = 1 { al/on } }\n  }\n }\n}\n'), 'audit')
    add(msg('Transaction = 62 {\n Context = 1 {\n  AuditCapability = A1 {\n   AT { M, SG, PG, SA { nt/os }, DM { x }, MX, MD, OE, E = 2 { al/on } }\n  }\n }\n}\n'), 'audit compact')
    add(msg('Transaction = 63 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit {\n    Media { Stream = 1 { LocalControl { Mode = SendReceive } } },\n    Signals { cg/rt }\n   }\n  }\n }\n}\n'), 'audit descriptors')
    add(msg('Transaction = 64 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { }\n  }\n }\n}\n'), 'audit empty')
    add(msg('Transaction = 65 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Media }\n  }\n }\n}\n'), 'audit media only')
    add(msg('Reply = 65 {\n Context = 1 {\n  AuditValue = A1 {\n   Media { TerminationState { ServiceStates = InService }, Stream = 1 { LocalControl { Mode = SendReceive } } },\n   Statistics { nt/os = 1 },\n   Events = 2 { al/on },\n   Signals { cg/rt },\n   Packages { al-1 }\n  }\n }\n}\n'))
    add(msg('Transaction = 66 {\n Context = - {\n  ServiceChange = ROOT {\n   Services {\n    Method = Restart,\n    Reason = "901 Cold Boot",\n    Delay = 3,\n    ServiceChangeAddress = 55555,\n    MgcIdToTry = [192.0.2.9]:2944,\n    Profile = ResGW/1,\n    Version = 1,\n    X-vend = 4\n   }\n  }\n }\n}\n'))
    add(msg('Transaction = 67 {\n Context = - {\n  ServiceChange = ROOT {\n   SV { MT = Graceful, RE = 905, DL = 1, AD = 2944, MG = x, PF = p/1, V = 3 }\n  }\n }\n}\n'), 'service change compact')
    add(msg('Transaction = 68 {\n Context = - {\n  ServiceChange = ROOT {\n   Services { Method = Forced, Reason = 999, Version = 2 }\n  }\n }\n}\n'), 'service change unknown reason')
    add(msg('Transaction = 69 {\n Context = - {\n  ServiceChange = ROOT {\n   Services { Method = Forced, Reason = "no digit" }\n  }\n }\n}\n'), 'service change reason without a nine')
    add(msg('Reply = 66 {\n Context = - {\n  ServiceChange = ROOT {\n   Services { MgcIdToTry = [192.0.2.9]:2944, Version = 1 }\n  }\n }\n}\n'))
    add(msg('Transaction = 70 {\n Context = 1 {\n  Modify = A1 {\n   Statistics { nt/os = 1, nt/or = 2 },\n   Modem { v34 },\n   Mux { H221, A1, A2 }\n  }\n }\n}\n'), 'statistics modem mux')
    add(msg('Transaction = 71 {\n Context = 1 {\n  Modify = A1 {\n   SA { nt/os },\n   Statistics { a = 1 }\n  }\n }\n}\n'))
    add(msg('Transaction = 72 {\n Context = 1 {\n  Modify = A1 {\n   Unknown { x }\n  }\n }\n}\n'), 'unknown descriptor')
    add(msg('Transaction = 73 {\n Context = 1 {\n  Modify = A1 {\n   Error = 442 { "Syntax Error in Command" }\n  }\n }\n}\n'), 'error descriptor in command')
    # --- short form
    add(sf('T=100{C=$ {A=$ {M{ST=1{O{MO=SR},L{' + SDP_L.replace('\n', '\n') + '},R{' + SDP_R + '}}}}}}\n'), 'short add')
    add(sf('P=100{C=7{A=A1{M{ST=1{L{' + SDP_L + '}}}}}}\n'), 'short reply')
    add(sf('T=101{C=1{AV=A1{AT{M,SG,E,PG}},AC=A2,N=A3{OE=1{al/of}},MF=A1,MV=A2,S=A3,SC=ROOT{SV{MT=RS}},A=A5}}\n'), 'short commands')
    add(sf('P=101{C=1{AV=A1,AC=A2,N=A3,MF=A1,MV=A2,S=A3,SC=ROOT,A=A5}}\n'), 'short replies')
    add(sf('T=102{C=1{PG=1{al-1},PN=2,PR=3,PF=x,IE=1}}\n'), 'short package/pending/priority/profile/ieps')
    add(sf('T=103{C=1{X=A1}}\n'), 'short unknown command')
    add(sf('ER=400{"Syntax error"}\n'), 'short error')
    add(sf('PN=5{}\n'), 'short pending')
    add(sf('K{5-9}\n'), 'short ack')
    add(sf('T=104{C=1{MF=A1{E=3{al/on},SG{cg/rt}}}}\n'), 'short events signals')
    add(sf('T=105{C=1{TP{A1,A2,isolate},A=A1}}\n'), 'short topology')
    # AU header
    add('Authentication=0x0000000A:0x00000001:0x0123456789abcdef0123456789abcdef\nMEGACO/1 [192.0.2.1]:2944\nTransaction = 110 {\n Context = 1 {\n  Modify = A1\n }\n}\n', 'auth header')
    add('AU=0x0000000A:0x00000001:0x00112233445566778899aabbccddeeff\nMEGACO/1 [192.0.2.1]:2944\nTransaction = 111 {\n Context = 1 {\n  Modify = A1\n }\n}\n', 'compact auth header')
    add('  MEGACO/1 [192.0.2.1]:2944\nPending = 112 { }\n', 'leading spaces')
    # mId and version forms
    add(msg('Pending = 113 { }\n', mid='<mg1.example.com>:2944'))
    add(msg('Pending = 114 { }\n', mid='MTP{0123}'))
    add(msg('Pending = 115 { }\n', mid='mg1/a@example.com'))
    add(msg('Pending = 116 { }\n', ver=10))
    add(msg('Pending = 117 { }\n', ver=3))
    # LF only line ends and tabs
    add(('MEGACO/1 [192.0.2.1]:2944\nTransaction\t=\t118\t{\n\tContext\t=\t1\t{\n\t\tModify\t=\tA1\t{\n\t\t\tEvents\t=\t1\t{\n\t\t\t\tal/on\n\t\t\t}\n\t\t}\n\t}\n}\n').encode(), 'tabs')
    # lower case tokens
    add(msg('transaction = 119 {\n context = 1 {\n  modify = a1 { events = 1 { al/on }, media { stream = 1 { localcontrol { mode = SendReceive } } } }\n }\n}\n'), 'lower case')
    # --- H.245 over MEGACO
    add(msg('Transaction = 120 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { h245/x { h245 = 42 } },\n   Signals { h245/s { h245 = 42 } }\n  }\n }\n}\n'), 'h245 events/signals')
    add(msg('Transaction = 121 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 1 { h245/e { h245 = 42 } }\n  }\n }\n}\n'), 'h245 observed')
    add(msg('Transaction = 122 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/muxtbl_in = 42, h324/muxtbl_out = 42 } } }\n  }\n }\n}\n'), 'h245 muxtbl')
    add(msg('Transaction = 123 {\n Context = 1 {\n  Modify = A1 {\n   Media { Stream = 1 { LocalControl { h324/h223capr = 00000000000000000000 } } }\n  }\n }\n}\n'), 'h223capr')

    # --- lower case short form (the second letter is folded)
    add(sf('t=130{c=1{av=a1,ac=a2,mf=a1,mv=a2,sc=root,sb=a3}}\n'), 'short lower case')
    add(sf('p=130{c=1{av=a1,ac=a2,mf=a1,mv=a2,sc=root,sb=a3}}\n'), 'short reply lower case')
    # replies for commands that have no command type (package, pending, ...)
    add(sf('P=131{C=1{PG=1,PN=2,PR=3,PF=x,IE=1}}\n'), 'short reply without cmd type')
    add(msg('Reply = 132 {\n Context = 1 {\n  Packages = 1,\n  Frobnicate = A1\n }\n}\n'), 'long reply, other cmd')
    # termination id starting with O
    add(msg('Transaction = 133 {\n Context = 1 {\n  Modify = other/1\n }\n}\n'), 'termination id O')
    # compact descriptor names, unknown media parameter, unknown local control
    add(msg('Transaction = 134 {\n Context = 1 {\n  Modify = A1 {\n   Media {\n    Foo { x },\n    Stream = 1 { Bar { y } },\n    TerminationState { Buffer = off, Foo = bar }\n   }\n  }\n }\n}\n'), 'unknown media parameters')
    # events/observed/packages/audit variants
    add(msg('Transaction = 135 {\n Context = 1 {\n  Modify = A1 {\n   Events = 5\n  }\n }\n}\n'), 'events without braces')
    add(msg('Transaction = 136 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 5\n  }\n }\n}\n'), 'observed events without braces')
    add(msg('Transaction = 137 {\n Context = 1 {\n  Notify = A1 {\n   ObservedEvents = 5 {\n    al/on { a = { b }, c = d },\n    al/of\n   }\n  }\n }\n}\n'), 'observed events nested')
    add(msg('Transaction = 138 {\n Context = 1 {\n  Modify = A1 {\n   Packages = 3 {\n    al-1 { a = { b } },\n    rtp-1\n   }\n  }\n }\n}\n'), 'packages nested')
    add(msg('Transaction = 139 {\n Context = 1 {\n  AuditValue = A1 {\n   Audit { Packages { al-1 }, Modem { x }, Foo }\n  }\n }\n}\n'), 'audit packages, unknown items')
    add(msg('Transaction = 141 {\n Context = 1 {\n  Modify = A1 {\n   Topology { A1, A2, isolate },\n   Events = 1 { al/on }\n  }\n }\n}\n'), 'topology descriptor')
    add(msg('Transaction = 142 {\n Context = 1 {\n  Modify = A1 {\n   Events = 1 { al/on, al/of { a = { b } }, cg/ft }\n  }\n }\n}\n'), 'events nested')


MIN = 'Transaction = %d {\n Context = 1 {\n  Modify = A1 { Events = 1 { al/on } }\n }\n}\n'
MIN2 = 'Transaction = %d {\n  Context = 1 {\n    Notify = A1\n  }\n}\n'
MINR = 'Reply = %d {\n Context = 1 {\n  Modify = A1\n }\n}\n'


def tlv(t, v):
    return bytes([t, len(v)]) + v


# binary H.248 (BER): MegacoMessage { mess [1] { version [0], mId [1] deviceName,
# messageBody [2] messageError [0] { errorCode 400, errorText } } }
BER = tlv(0x30, tlv(0xa1, tlv(0x80, b'\x01') + tlv(0xa1, tlv(0x83, b'mgc')) +
                    tlv(0xa2, tlv(0xa0, tlv(0x80, b'\x01\x90') + tlv(0x81, b'oops')))))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build_messages()
    f = []
    for label, text in MSGS:
        f.append(udp(text, c2s=not text.startswith(b'MEGACO/1 [192.0.2.1]:2944\r\nReply')))
    n_udp = len(f)
    # --- other transports
    # TCP with TPKT: request, reply, two PDUs in one segment, a PDU over two segments
    t = Tcp(f, 40100)
    t.handshake()
    t.data(True, tpkt(crlf(msg(MIN % 200))))
    t.data(False, tpkt(crlf(msg(MINR % 200))))
    t.data(True, tpkt(crlf(msg(MIN % 201))) + tpkt(crlf(msg(MIN % 202))))
    big = tpkt(crlf(msg(MINR % 201)))
    t.data(False, big[:30])
    t.data(False, big[30:])
    # TCP without TPKT: the raw text
    t.data(True, crlf(msg(MIN % 203)))
    t.data(False, crlf(msg(MINR % 203)))
    # SCTP: PPID 7 on port 2944, PPID 7 on another port, fragments
    f.append(sctp([data_chunk(crlf(msg(MIN % 210)), 1)]))
    f.append(sctp([data_chunk(crlf(msg(MINR % 210)), 1)], c2s=False, vtag=0x55667788))
    f.append(sctp([data_chunk(crlf(msg(MIN % 211)), 2)], sport=5000, dport=5001))
    m = crlf(msg(MIN % 212))
    f.append(sctp([data_chunk(m[:40], 3, flags=2)]))
    f.append(sctp([data_chunk(m[40:], 4, flags=1)]))
    # --- not text MEGACO: BER H.248 and other data (UDP 2944)
    f.append(udp(BER))
    f.append(udp(b'this is not a megaco message\r\n'))
    f.append(udp(b'\x00\x01\x02\x03\x04\x05'))
    pcap(os.path.join(out, 'megaco-coverage.pcap'), f)
    mf = [udp(text) for label, text in MALF]
    # the two fragmented messages completed in one SCTP packet (see README)
    a, b = crlf(msg(MIN2 % 10)), crlf(msg(MIN2 % 20))
    ha, hb = len(a) // 2, len(b) // 2
    mf.append(sctp([data_chunk(a[:ha], 100, 0, 0, flags=2), data_chunk(b[:hb], 102, 1, 0, flags=2)], vtag=0x01020304))
    mf.append(sctp([data_chunk(a[ha:], 101, 0, 0, flags=1), data_chunk(b[hb:], 103, 1, 0, flags=1)], vtag=0x01020304))
    pcap(os.path.join(out, 'megaco-coverage-malformed.pcap'), mf)
    if len(sys.argv) > 2:
        for i, (label, text) in enumerate(MSGS, 1):
            print(i, label)
        print('udp frames', n_udp, 'total', len(f))


if __name__ == "__main__":
    main()
