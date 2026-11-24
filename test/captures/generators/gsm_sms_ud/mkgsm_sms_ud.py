#!/usr/bin/env python3
# Generates test/captures/gsm_sms_ud_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GSM SMS UD coverage captures.  Usage: mkgsm_sms_ud.py <outdir>
# gsm_sms_ud is called by the SMPP dissector for the short message of
# submit_sm, deliver_sm, data_sm, ... PDUs.  The SMPP is carried over TCP
# (192.0.2.1 ESME -> 192.0.2.2 SMSC, port 2775) and found by the SMPP
# heuristic dissector, so no port or preference is needed.  Synthetic.
import os
import struct
import socket
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_tcp(payload, sport, dport, seq, ack, flags, src, dst):
    opts = bytes.fromhex('020405b4010303070402') + b'\x01\x01' if flags & 2 else b''
    s = socket.inet_aton(src)
    d = socket.inet_aton(dst)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp + payload

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

class Conn:
    def __init__(self, frames, cport=40000, c='192.0.2.1', s='192.0.2.2', port=2775):
        self.f, self.cp, self.c, self.s, self.port = frames, cport, c, s, port
        self.cseq, self.sseq = 1000, 5000
        self.f.append(eth_tcp(b'', cport, port, self.cseq, 0, 0x02, c, s))
        self.cseq += 1
        self.f.append(eth_tcp(b'', port, cport, self.sseq, self.cseq, 0x12, s, c))
        self.sseq += 1
        self.f.append(eth_tcp(b'', cport, port, self.cseq, self.sseq, 0x10, c, s))
    def send(self, data, down=False):
        if down:
            self.f.append(eth_tcp(data, self.port, self.cp, self.sseq, self.cseq, 0x18, self.s, self.c))
            self.sseq += len(data)
        else:
            self.f.append(eth_tcp(data, self.cp, self.port, self.cseq, self.sseq, 0x18, self.c, self.s))
            self.cseq += len(data)

seqno = [0]
def pdu(cmd, body=b'', status=0):
    seqno[0] += 1
    return struct.pack('>IIII', 16 + len(body), cmd, status, seqno[0]) + body

def cstr(s): return s.encode() + b'\0'

def submit_body(sm, esm=0x00, dcs=0x04, tlvs=b''):
    return (b'\0' + bytes([1, 1]) + cstr('1234') + bytes([1, 1]) + cstr('5678') +
            bytes([esm, 0, 0]) + b'\0\0' + bytes([0, 0, dcs, 0, len(sm)]) + sm + tlvs)

def tlv(tag, val): return struct.pack('>HH', tag, len(val)) + val

# --- User data header information elements
def udh(*ies):
    body = b''.join(ies)
    return bytes([len(body)]) + body
def ie(iei, data): return bytes([iei, len(data)]) + data
def concat8(ref, total, seq): return ie(0x00, bytes([ref, total, seq]))
def concat16(ref, total, seq): return ie(0x08, struct.pack('>HBB', ref, total, seq))
def ports8(dst, src): return ie(0x04, bytes([dst, src]))
def ports16(dst, src): return ie(0x05, struct.pack('>HH', dst, src))

WSP = b'\x01\x06\x01\x83' + b'Hello WSP push'    # TID, Push, headers length 1, text/plain, body
WTP_ = b'\x0e\x00\x01\x10' + b'\x06\x01\x83Hello WTP push'                                 # WTP invoke, TID, ...

def build(outdir):
    f = []
    c = Conn(f)
    c.send(pdu(2, cstr('esme') + cstr('secret') + cstr('') + bytes([0x34, 0, 0]) + b'\0'))     # bind_transmitter
    c.send(pdu(0x80000002, cstr('smsc')), down=True)
    # 1. single message with a port number IE to the registered WSP push port
    c.send(pdu(4, submit_body(udh(ports16(2948, 9200)) + WSP, esm=0x40)))
    # 2. 8 bit ports, to the WSP port (dst lookup after the source port fails)
    c.send(pdu(4, submit_body(udh(ports8(0x40, 0x41)) + WSP, esm=0x40)))
    c.send(pdu(4, submit_body(udh(ports16(2948, 9202)) + WSP, esm=0x40)))
    c.send(pdu(4, submit_body(udh(ports16(2948, 9201)) + WTP_, esm=0x40)))   # WTP
    # 3. ports that no dissector claims: shown as Short Message body
    c.send(pdu(4, submit_body(udh(ports16(5000, 5001)) + b'unclaimed port data', esm=0x40)))
    # 4. UDH without port or concatenation IE
    c.send(pdu(4, submit_body(udh(ie(0x01, b'\x80\x01')) + b'plain user data', esm=0x40)))
    # 5. 3 fragment message with 8 bit concatenation and ports in each part
    for n, part in enumerate((WSP[:6], WSP[6:12], WSP[12:]), 1):
        c.send(pdu(4, submit_body(udh(concat8(7, 3, n), ports16(2948, 9200)) + part, esm=0x40)))
    # 6. 2 fragments, 16 bit concatenation, no ports, delivered by deliver_sm
    for n, part in enumerate((b'first part, ', b'second part'), 1):
        c.send(pdu(5, submit_body(udh(concat16(0x1234, 2, n)) + part, esm=0x40)), down=True)
    # 7. fragments arriving in reverse order
    c.send(pdu(4, submit_body(udh(concat8(8, 2, 2), ports16(2948, 9200)) + WSP[6:], esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(8, 2, 1), ports16(2948, 9200)) + WSP[:6], esm=0x40)))
    # 8. fragment 0 of 2 and 1 of 0 (not reassembled), 1 of 1 (not
    # fragmented), fragment number larger than the number of fragments
    c.send(pdu(4, submit_body(udh(concat8(9, 2, 0)) + b'frag zero', esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(9, 0, 1)) + b'frags zero', esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(9, 1, 1)) + b'single fragment', esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(10, 2, 3)) + b'frag 3 of 2', esm=0x40)))
    # 9. a repeated fragment (overlap with the same data)
    c.send(pdu(4, submit_body(udh(concat8(11, 2, 1)) + b'repeated ', esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(11, 2, 1)) + b'repeated ', esm=0x40)))
    c.send(pdu(4, submit_body(udh(concat8(11, 2, 2)) + b'last', esm=0x40)))
    # 10. the UDH uses the whole short message (no more data)
    c.send(pdu(4, submit_body(udh(ports16(2948, 9200)), esm=0x40)))
    # 11. no UDHI but SAR and port TLVs (SMPP 3.4 sar_* / port TLVs)
    for n, part in enumerate((WSP[:8], WSP[8:]), 1):
        tl = (tlv(0x020c, struct.pack('>H', 0x55)) + tlv(0x020e, b'\x02') + tlv(0x020f, bytes([n])) +
              tlv(0x020a, struct.pack('>H', 9200)) + tlv(0x020b, struct.pack('>H', 2948)))
        c.send(pdu(5, submit_body(part, esm=0x00, tlvs=tl)), down=True)
    # TLVs without UDHI: only ports
    c.send(pdu(5, submit_body(WSP, tlvs=tlv(0x020a, struct.pack('>H', 9200)) + tlv(0x020b, struct.pack('>H', 2948)))), down=True)
    # 12. data_sm with the message in message_payload and UDHI
    def data_sm(payload, esm=0x40):
        return pdu(0x103, cstr('') + bytes([1, 1]) + cstr('1234') + bytes([1, 1]) + cstr('5678') +
                   bytes([esm, 0, 0x04]) + tlv(0x0424, payload))
    c.send(data_sm(udh(ports16(2948, 9200)) + WSP))
    c.send(data_sm(udh(concat8(12, 2, 1), ports16(2948, 9200)) + WSP[:5]))
    c.send(data_sm(udh(concat8(12, 2, 2), ports16(2948, 9200)) + WSP[5:]))
    # 13. 7 bit data coding with a UDH (fill bits)
    c.send(pdu(4, submit_body(udh(ports16(5000, 5001)) + b'\x00' * 10, esm=0x40, dcs=0x00)))

    # ---- malformed
    b = []
    d = Conn(b, 40001)
    d.send(pdu(2, cstr('esme') + cstr('secret') + cstr('') + bytes([0x34, 0, 0]) + b'\0'))
    # UDH length longer than the short message
    d.send(pdu(4, submit_body(bytes([200, 0, 1, 2, 3]), esm=0x40)))
    # IE length running over the UDH
    d.send(pdu(4, submit_body(bytes([3, 0x04, 5, 1]) + b'xx', esm=0x40)))
    d.send(pdu(4, submit_body(bytes([2, 0x00, 3]), esm=0x40)))
    d.send(pdu(4, submit_body(bytes([1, 0x05]), esm=0x40)))
    # reserved IEIs and zero length IEs
    d.send(pdu(4, submit_body(udh(ie(0x00, b''), ie(0x08, b''), ie(0x04, b''), ie(0x05, b''), ie(0x70, b'ab'), ie(0xff, b'')) + b'data', esm=0x40)))
    # conflicting data in a repeated fragment, fragment bigger than the total
    d.send(pdu(4, submit_body(udh(concat8(20, 2, 1)) + b'conflict A', esm=0x40)))
    d.send(pdu(4, submit_body(udh(concat8(20, 2, 1)) + b'conflict B', esm=0x40)))
    d.send(pdu(4, submit_body(udh(concat8(20, 2, 2)) + b'tail', esm=0x40)))
    d.send(pdu(4, submit_body(udh(concat8(20, 2, 2)) + b'tail again', esm=0x40)))
    # short message length larger than the PDU
    d.send(pdu(4, submit_body(b'x')[:-1] + bytes([30]) + b'x'))
    # SAR TLVs with zero segments
    d.send(pdu(5, submit_body(b'abc', tlvs=tlv(0x020c, b'\x00\x01') + tlv(0x020e, b'\x00') + tlv(0x020f, b'\x00'))))
    d.send(pdu(5, submit_body(b'abc', tlvs=tlv(0x020a, b'\x23\x28'))))
    d.send(pdu(5, submit_body(b'abc', tlvs=tlv(0x020a, b'\x23'))))
    write_pcap(os.path.join(outdir, 'gsm_sms_ud-coverage.pcap'), f)
    write_pcap(os.path.join(outdir, 'gsm_sms_ud-coverage-malformed.pcap'), b)
    print(len(f), len(b))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
