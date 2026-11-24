#!/usr/bin/env python3
# Generates test/captures/exported_pdu_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Exported PDU dissector
(epan/dissectors/packet-exported_pdu.c, LINKTYPE_WIRESHARK_UPPER_PDU 252).

Every packet is built from scratch with struct; no captured traffic is used.
Addresses are from the documentation ranges or 10/8.

Usage: mkexported_pdu.py <output directory>

Writes:
  exported_pdu-coverage.pcap            the main capture (linktype 252)
  exported_pdu-coverage-malformed.pcap  paths that end in an exception or
                                        a dissector bug report (linktype 252)
  exported_pdu-tcp-source.pcap          an Ethernet capture of the TCP and
                                        UDP flows that section A of the main
                                        capture is the layer 4 export of
                                        ("tshark -U 'OSI layer 4'"); used by
                                        checkexport.sh, not for the tree
  exported_pdu-bug-strtable.pcap        a dissector table tag that names a
                                        string table: aborts tshark
  exported_pdu-bug-reexport.pcap        PROXY v1 PDUs as TCP exports them;
                                        exporting this file again crashes
  exported_pdu-bug-rtmpt-heur.pcap      the rtmpt_tcp heuristic without TCP
                                        information: crashes tshark when the
                                        heuristic is enabled
"""

import struct
import sys

# --------------------------------------------------------------------------
# Exported PDU tags (wsutil/exported_pdu_tlvs.h)

END_OF_OPT, OPTIONS_LENGTH, LINKTYPE = 0, 10, 11
DISSECTOR_NAME, HEUR_DISSECTOR_NAME, DISSECTOR_TABLE_NAME = 12, 13, 14
IPV4_SRC, IPV4_DST, IPV6_SRC, IPV6_DST = 20, 21, 22, 23
PORT_TYPE, SRC_PORT, DST_PORT = 24, 25, 26
SS7_OPC, SS7_DPC, ORIG_FNO, DVBCI_EVT = 28, 29, 30, 31
TABLE_NUM_VAL, COL_PROT_TEXT, TCP_INFO_DATA, P2P_DIRECTION = 32, 33, 34, 35
COL_INFO_TEXT, USER_DATA_PDU, TGPP_ID, LINK_DIRECTION, TGPP_UE_ID = 36, 37, 38, 39, 40

PT_NONE, PT_SCTP, PT_TCP, PT_UDP, PT_DCCP, PT_IPX, PT_NCP, PT_EXCHG = range(8)
PT_DDP, PT_SBCCS, PT_IDP, PT_TIPC, PT_USB, PT_I2C, PT_IBQP = range(8, 15)
PT_BLUETOOTH, PT_TDMOP, PT_IWARP_MPA, PT_MCTP = range(15, 19)

TH_FIN, TH_SYN, TH_PUSH, TH_ACK, TH_URG = 0x01, 0x02, 0x08, 0x10, 0x20


def u8(v):  return struct.pack('>B', v)
def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)
def i32(v): return struct.pack('>i', v)


def tlv(tag, value, length=None):
    """A tag; length overrides the length field (the value is written as given)."""
    return u16(tag) + u16(len(value) if length is None else length) + value


def name_tlv(tag, name):
    """A name tag the way epan/exported_pdu.c writes it: padded with nulls
    to a multiple of 4 octets."""
    b = name.encode()
    return tlv(tag, b + b'\0' * (-len(b) % 4))


def end():
    return tlv(END_OF_OPT, b'')


def tcpinfo(seq, nxtseq, lastack, flags, urg=0, reassembled=0, version=1, pad=True):
    """EXP_PDU_TAG_TCP_INFO_DATA, as packet-tcp.c writes it (20 octets, the
    last one padding) or with the 19 octets the format describes."""
    v = u16(version) + u32(seq) + u32(nxtseq) + u32(lastack) + u8(reassembled) + u16(flags) + u16(urg)
    return tlv(TCP_INFO_DATA, v + (b'\0' if pad else b''))


def addr_tlvs(src, dst):
    if len(src) == 4:
        return tlv(IPV4_SRC, bytes(src)) + tlv(IPV4_DST, bytes(dst))
    return tlv(IPV6_SRC, bytes(src)) + tlv(IPV6_DST, bytes(dst))


def l4_tlvs(src, dst, ptype, sport, dport, fno=None):
    out = addr_tlvs(src, dst) + tlv(PORT_TYPE, u32(ptype)) + tlv(SRC_PORT, u32(sport)) + tlv(DST_PORT, u32(dport))
    if fno is not None:
        out += tlv(ORIG_FNO, u32(fno))
    return out


# --------------------------------------------------------------------------
# pcap writers

class Pcap:
    def __init__(self, linktype):
        self.linktype = linktype
        self.frames = []        # (timestamp, data)
        self.marks = {}         # section name -> (first, last) frame numbers

    def add(self, data, ts=None):
        if ts is None:
            ts = 1700000000 + len(self.frames)
        self.frames.append((ts, data))
        return len(self.frames)

    def section(self, name):
        """Mark a section: call once before its first frame and once after its last."""
        if name in self.marks:
            self.marks[name] = (self.marks[name][0], len(self.frames))
        else:
            self.marks[name] = (len(self.frames) + 1, None)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype)]
        for ts, f in self.frames:
            out.append(struct.pack('<IIII', int(ts), int(round((ts % 1) * 1e6)), len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def epdu(cap, *parts, ts=None):
    """An exported PDU frame: the tags and the payload, concatenated."""
    return cap.add(b''.join(parts), ts)


# --------------------------------------------------------------------------
# Source capture (Ethernet) and its layer 4 export, built side by side.

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


C4, S4, BCAST4 = (10, 1, 0, 1), (10, 1, 0, 2), (10, 1, 0, 255)
C6 = bytes.fromhex('20010db8000000000000000000000001')
S6 = bytes.fromhex('20010db8000000000000000000000002')
MAC_C, MAC_S = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'


class Source:
    """Writes the Ethernet source capture and, for each PDU that TCP or UDP
    hands to a subdissector, the frame that "tshark -U 'OSI layer 4'"
    writes for it (epan/exported_pdu.c, packet-tcp.c, packet-udp.c)."""

    def __init__(self, src_cap, exp_cap):
        self.src, self.exp = src_cap, exp_cap

    def ip(self, s, d, proto, l4, dmac=None):
        if len(s) == 4:
            ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.src.frames) & 0xffff,
                             0x4000, 64, proto, 0, bytes(s), bytes(d))
            ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
            etype = b'\x08\x00'
        else:
            ip = struct.pack('>IHBB16s16s', 0x60000000, len(l4), proto, 64, bytes(s), bytes(d))
            etype = b'\x86\xdd'
        fr = (dmac or MAC_S) + MAC_C + etype + ip + l4
        return self.src.add(fr)

    @staticmethod
    def pseudo(s, d, proto, length):
        if len(s) == 4:
            return struct.pack('>4s4sBBH', bytes(s), bytes(d), 0, proto, length)
        return struct.pack('>16s16sIxxxB', bytes(s), bytes(d), length, proto)

    def tcp(self, s, d, sport, dport, seq, ack, flags, payload=b'', urg=0):
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, urg)
        hdr = hdr[:16] + u16(csum(self.pseudo(s, d, 6, len(hdr) + len(payload)) + hdr + payload)) + hdr[18:]
        return self.ip(s, d, 6, hdr + payload)

    def udp(self, s, d, sport, dport, payload, how, dmac=None):
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        hdr = hdr[:6] + u16(csum(self.pseudo(s, d, 17, len(hdr) + len(payload)) + hdr + payload) or 0xffff)
        fno = self.ip(s, d, 17, hdr + payload, dmac)
        kind, val = how
        if kind == 'table':
            epdu(self.exp, name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'),
                 l4_tlvs(s, d, PT_UDP, sport, dport, fno), tlv(TABLE_NUM_VAL, u32(val)), end(), payload)


class Conn:
    """A TCP connection with a handshake. Each data segment names how TCP
    hands it on: ('table', port) for the tcp.port table, ('heur', name) for
    a heuristic of the "tcp" list, ('name', name) for the dissector of the
    TCP conversation, None for nothing exported."""

    def __init__(self, source, cport, sport, client=C4, server=S4):
        self.x, self.cp, self.sp, self.ca, self.sa = source, cport, sport, client, server
        self.cisn, self.sisn = 1000 + cport, 7000 + sport
        self.c, self.s = self.cisn, self.sisn
        source.tcp(client, server, cport, sport, self.c, 0, TH_SYN)
        source.tcp(server, client, sport, cport, self.s, self.c + 1, TH_SYN | TH_ACK)
        self.c += 1
        self.s += 1
        source.tcp(client, server, cport, sport, self.c, self.s, TH_ACK)

    def _seg(self, from_client, data, how, flags, urg):
        if from_client:
            s, d, sp, dp, seq, ack, isn, pisn = self.ca, self.sa, self.cp, self.sp, self.c, self.s, self.cisn, self.sisn
        else:
            s, d, sp, dp, seq, ack, isn, pisn = self.sa, self.ca, self.sp, self.cp, self.s, self.c, self.sisn, self.cisn
        fno = self.x.tcp(s, d, sp, dp, seq, ack, flags, data, urg)
        rel = seq - isn
        info = tcpinfo(rel, rel + len(data), ack - pisn, flags, urg)
        if how is not None:
            kind, val = how
            if kind == 'table':
                epdu(self.x.exp, name_tlv(DISSECTOR_TABLE_NAME, 'tcp.port'),
                     l4_tlvs(s, d, PT_TCP, sp, dp, fno), tlv(TABLE_NUM_VAL, u32(val)), info, end(), data)
            else:
                epdu(self.x.exp, name_tlv(HEUR_DISSECTOR_NAME if kind == 'heur' else DISSECTOR_NAME, val),
                     l4_tlvs(s, d, PT_TCP, sp, dp, fno), info, end(), data)
        n = len(data) + (flags & TH_FIN)
        if from_client:
            self.c += n
        else:
            self.s += n

    def cli(self, data, how, flags=TH_PUSH | TH_ACK, urg=0):
        self._seg(True, data, how, flags, urg)

    def srv(self, data, how, flags=TH_PUSH | TH_ACK, urg=0):
        self._seg(False, data, how, flags, urg)


# --------------------------------------------------------------------------
# Payloads

HTTP_REQ = b'GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: synthetic\r\n\r\n'
HTTP_RSP = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nhello\n'
HTTP_REQ2 = b'GET /alt HTTP/1.1\r\nHost: alt.example.com\r\n\r\n'
HTTP_RSP2 = b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'


def tls_client_hello(sni=b'www.example.com'):
    sni_ext = u16(0) + u16(len(sni) + 5) + u16(len(sni) + 3) + b'\0' + u16(len(sni)) + sni
    sv_ext = u16(0x002b) + u16(3) + b'\x02\x03\x04'
    groups = u16(0x000a) + u16(4) + u16(2) + u16(0x001d)
    exts = sni_ext + sv_ext + groups
    body = (u16(0x0303) + bytes(range(32)) + b'\0' + u16(4) + u16(0x1301) + u16(0x002f)
            + b'\x01\x00' + u16(len(exts)) + exts)
    hs = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + u16(len(hs)) + hs


def nb_name(name, suffix):
    raw = (name.ljust(15)[:15]).encode() + bytes([suffix])
    enc = b''.join(bytes([0x41 + (c >> 4), 0x41 + (c & 0xf)]) for c in raw)
    return b'\x20' + enc + b'\0'


NBSS_REQ_BODY = nb_name('FILESERVER', 0x20) + nb_name('CLIENT', 0x00)
NBSS_REQ = b'\x81\x00' + u16(len(NBSS_REQ_BODY)) + NBSS_REQ_BODY
NBSS_RSP = b'\x82\x00\x00\x00'
RTMP_C0C1 = b'\x03' + struct.pack('>II', 0, 0) + bytes((i * 7) & 0xff for i in range(1528))
RTMP_S0S1S2 = b'\x03' + struct.pack('>II', 0, 0) + bytes((i * 11) & 0xff for i in range(1528)) + RTMP_C0C1[1:]
MPA_REQ = b'MPA ID Req Frame' + b'\x00\x01\x00\x00'
RLOGIN_START = b'\0guest\0guest\0xterm/38400\0'
DNS_QUERY = (u16(0x1234) + u16(0x0100) + u16(1) + u16(0) + u16(0) + u16(0)
             + b'\x07example\x03com\x00' + u16(1) + u16(1))
SIP_OPTIONS = (b'OPTIONS sip:bob@example.com SIP/2.0\r\n'
               b'Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK776asdhds\r\n'
               b'Max-Forwards: 70\r\nFrom: <sip:alice@example.com>;tag=1928301774\r\n'
               b'To: <sip:bob@example.com>\r\nCall-ID: a84b4c76e66710@10.1.0.1\r\n'
               b'CSeq: 63104 OPTIONS\r\nContent-Length: 0\r\n\r\n')
AMR_OA = bytes([0xf0, 0x3c]) + b'\x00' * 31      # CMR 15, one 12.2 kbit/s frame
AMR_WB_OA = bytes([0xf0, 0x44]) + b'\x00' * 60   # CMR 15, one 23.85 kbit/s frame
# IPv4 + UDP + DNS for the "ethertype" table
def ipv4_udp(payload, sport=40099, dport=53):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, bytes(C4), bytes(S4))
    return ip[:10] + u16(csum(ip)) + ip[12:] + udp


# A CI+ SAC message (cc_sac_data_req / cnf), not encrypted
def sac_msg(nbr_items=0):
    payload = u8(nbr_items) + b'\0' * 7  # send_datatype_nbr, padding to 8
    return u32(1) + u8(0x10) + u8(0x00) + u16(len(payload)) + payload + bytes(16)


# --------------------------------------------------------------------------
# Main capture

def build_main(out):
    cap = Pcap(252)
    src = Pcap(1)
    x = Source(src, cap)

    # ---- A: the layer 4 export of the source capture -------------------
    cap.section('A')
    h = Conn(x, 40001, 80)
    h.cli(HTTP_REQ, ('table', 80))
    h.srv(HTTP_RSP, ('table', 80))
    h2 = Conn(x, 40002, 40200)                     # HTTP on a port with no dissector
    h2.cli(HTTP_REQ2, ('heur', 'http_tcp'))
    h2.srv(HTTP_RSP2, ('name', 'http-over-tcp'))   # the conversation's dissector
    t = Conn(x, 40003, 443)
    t.cli(tls_client_hello(), ('table', 443))
    t2 = Conn(x, 40004, 40300)
    t2.cli(tls_client_hello(b'alt.example.com'), ('heur', 'tls_tcp'))
    f = Conn(x, 40005, 79)
    f.cli(b'alice\r\n', ('table', 79))
    f.srv(b'Login: alice\r\nName: Alice Example\r\n', ('table', 79), flags=TH_FIN | TH_PUSH | TH_ACK)
    w = Conn(x, 40006, 43)
    w.cli(b'example.com\r\n', ('table', 43))
    w.srv(b'Domain Name: EXAMPLE.COM\r\n', ('table', 43), flags=TH_FIN | TH_PUSH | TH_ACK)
    r = Conn(x, 1023, 513)
    r.cli(RLOGIN_START, ('table', 513))
    r.srv(b'\0', ('table', 513))
    r.srv(b'Last login: never\r\n', ('table', 513))
    r.srv(b'abc\x80', ('table', 513), flags=TH_URG | TH_PUSH | TH_ACK, urg=4)  # control byte 0x80
    n = Conn(x, 40007, 139)
    n.cli(NBSS_REQ, ('table', 139))
    n.srv(NBSS_RSP, ('table', 139))
    m = Conn(x, 40008, 1935)
    m.cli(RTMP_C0C1, ('table', 1935))
    m.srv(RTMP_S0S1S2, ('table', 1935))
    i = Conn(x, 40009, 40100)
    i.cli(MPA_REQ, ('heur', 'iwarp_mpa_tcp'))
    h6 = Conn(x, 40010, 80, C6, S6)
    h6.cli(HTTP_REQ, ('table', 80))
    h6.srv(HTTP_RSP, ('table', 80))
    x.udp(C4, S4, 40011, 53, DNS_QUERY, ('table', 53))
    x.udp(C4, S4, 5060, 5060, SIP_OPTIONS, ('table', 5060))
    x.udp(C6, S6, 40012, 53, DNS_QUERY, ('table', 53))
    cap.section('A')

    # ---- B: TCP information still reaches TCP dissectors ---------------
    cap.section('B')
    tcp4 = lambda sp, dp: l4_tlvs(C4, S4, PT_TCP, sp, dp)
    srv4 = lambda sp, dp: l4_tlvs(S4, C4, PT_TCP, sp, dp)
    # by name: rlogin (in tcp.port 513) sees the urgent pointer
    epdu(cap, name_tlv(DISSECTOR_NAME, 'rlogin'), srv4(513, 1022),
         tcpinfo(2, 6, 26, TH_URG | TH_PUSH | TH_ACK, urg=4), end(), b'xyz\x02')
    # by name: nbss (in tcp.port 139) rejects a PDU without TCP information
    epdu(cap, name_tlv(DISSECTOR_NAME, 'nbss'), tcp4(40020, 139),
         tcpinfo(1, 1 + len(NBSS_REQ), 1, TH_PUSH | TH_ACK), end(), NBSS_REQ)
    # by name: rtmpt.tcp labels the handshake from the sequence number
    epdu(cap, name_tlv(DISSECTOR_NAME, 'rtmpt.tcp'), tcp4(40021, 1935),
         tcpinfo(1, 1 + len(RTMP_C0C1), 1, TH_PUSH | TH_ACK), end(), RTMP_C0C1)
    # by name: iwarp_mpa is only "Decode As" for tcp.port
    epdu(cap, name_tlv(DISSECTOR_NAME, 'iwarp_mpa'), tcp4(40022, 40101),
         tcpinfo(1, 21, 1, TH_PUSH | TH_ACK), end(), MPA_REQ)
    # by name: http-over-tcp, tls, finger with FIN
    epdu(cap, name_tlv(DISSECTOR_NAME, 'http-over-tcp'), tcp4(40023, 8080),
         tcpinfo(1, 1 + len(HTTP_REQ), 1, TH_PUSH | TH_ACK), end(), HTTP_REQ)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'tls'), tcp4(40024, 8443),
         tcpinfo(1, 200, 1, TH_PUSH | TH_ACK), end(), tls_client_hello(b'name.example.com'))
    epdu(cap, name_tlv(DISSECTOR_NAME, 'finger'), srv4(79, 40025),
         tcpinfo(1, 20, 8, TH_FIN | TH_PUSH | TH_ACK), end(), b'Login: bob\r\n')
    # heuristic of the "tcp" list: rtmpt_tcp (disabled by default) matches
    # only the server handshake at seq 1 / ack 1538
    epdu(cap, name_tlv(HEUR_DISSECTOR_NAME, 'rtmpt_tcp'), srv4(1936, 40026),
         tcpinfo(1, 1 + len(RTMP_S0S1S2), 1538, TH_PUSH | TH_ACK), end(), RTMP_S0S1S2)
    # table: tcp.port 513 and 139 with the TCP information
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'tcp.port'), srv4(513, 1021), tlv(TABLE_NUM_VAL, u32(513)),
         tcpinfo(2, 4, 26, TH_URG | TH_PUSH | TH_ACK, urg=2), end(), b'q\x10')
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'tcp.port'), tcp4(40027, 139), tlv(TABLE_NUM_VAL, u32(139)),
         tcpinfo(1, 1 + len(NBSS_REQ), 1, TH_PUSH | TH_ACK, pad=False), end(), NBSS_REQ)
    cap.section('B')

    # ---- C: TCP information is not given to other dissectors -----------
    cap.section('C')
    # the reproducer from gen_amr_exppdu_tcpinfo.py (AMR read the
    # struct tcpinfo as a struct _rtp_info and crashed)
    epdu(cap, tlv(DISSECTOR_NAME, b'amr'),
         tlv(TCP_INFO_DATA, struct.pack('>HIIIBHH', 1, 1, 2, 3, 0, 0x18, 0)), end(), AMR_OA)
    epdu(cap, tlv(DISSECTOR_NAME, b'amr-wb'),
         tlv(TCP_INFO_DATA, struct.pack('>HIIIBHH', 1, 1, 2, 3, 0, 0x18, 0)), end(), AMR_WB_OA)
    # "http" is not in tcp.port (http-over-tcp is)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'http'), tcp4(40030, 8000),
         tcpinfo(1, 1 + len(HTTP_REQ2), 1, TH_PUSH | TH_ACK), end(), HTTP_REQ2)
    # a heuristic of the "udp" list and the udp.port table
    epdu(cap, name_tlv(HEUR_DISSECTOR_NAME, 'sip_udp'), l4_tlvs(C4, S4, PT_UDP, 5062, 5062),
         tcpinfo(1, 2, 3, TH_PUSH | TH_ACK), end(), SIP_OPTIONS)
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'), l4_tlvs(C4, S4, PT_UDP, 40031, 53),
         tlv(TABLE_NUM_VAL, u32(53)), tcpinfo(1, 2, 3, TH_PUSH | TH_ACK), end(), DNS_QUERY)
    # nbss without TCP information (no tag; an unsupported version)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'nbss'), tcp4(40032, 139), end(), NBSS_REQ)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'nbss'), tcp4(40033, 139),
         tcpinfo(1, 1 + len(NBSS_REQ), 1, TH_PUSH | TH_ACK, version=2), end(), NBSS_REQ)
    cap.section('C')

    # ---- D: every tag ----------------------------------------------------
    cap.section('D')
    # deprecated OPTIONS_LENGTH and LINKTYPE tags are unknown to the dissector
    body = name_tlv(DISSECTOR_NAME, 'dns') + l4_tlvs(C4, S4, PT_UDP, 40040, 53) + end()
    epdu(cap, tlv(OPTIONS_LENGTH, u32(len(body))), tlv(LINKTYPE, u32(1)), body, DNS_QUERY)
    # unknown tags, reserved and past the last one
    epdu(cap, tlv(1, b'\x01\x02'), tlv(27, u32(7)), tlv(41, b'unknown'), tlv(0xffff, b''),
         name_tlv(DISSECTOR_NAME, 'data'), end(), b'payload after unknown tags')
    # name with and without padding nulls, a zero length name ("" is not found)
    epdu(cap, tlv(DISSECTOR_NAME, b'dns\0\0\0\0\0'), l4_tlvs(C4, S4, PT_UDP, 40041, 53), end(), DNS_QUERY)
    epdu(cap, tlv(DISSECTOR_NAME, b''), end(), b'no dissector name')
    # a dissector that does not exist, a heuristic that does not exist, a
    # table that does not exist, a value that is not in the table
    epdu(cap, name_tlv(DISSECTOR_NAME, 'no_such_dissector'), end(), b'not dissected')
    epdu(cap, name_tlv(HEUR_DISSECTOR_NAME, 'no_such_heuristic'), end(), b'not dissected')
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'no.such.table'), tlv(TABLE_NUM_VAL, u32(1)), end(), b'not dissected')
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'), tlv(TABLE_NUM_VAL, u32(1)), end(), b'not in table')
    # a table without a value tag (value 0), and the ethertype table
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'), end(), b'no value tag: udp.port 0')
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'ethertype'), tlv(TABLE_NUM_VAL, u32(0x0800)), end(),
         ipv4_udp(DNS_QUERY))
    # the last name tag wins; a table tag after a name tag
    epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'),
         tlv(TABLE_NUM_VAL, u32(53)), l4_tlvs(C4, S4, PT_UDP, 40042, 53), end(), DNS_QUERY)
    # every port type the dissector maps
    for pt in (PT_NONE, PT_SCTP, PT_TCP, PT_UDP, PT_DCCP, PT_IPX, PT_DDP, PT_IDP,
               PT_USB, PT_I2C, PT_IBQP, PT_BLUETOOTH):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), l4_tlvs(C4, S4, pt, 1000 + pt, 2000 + pt, 100 + pt),
             end(), b'port type %d' % pt)
    # IPv6 addresses, a padded IPv4 address
    epdu(cap, name_tlv(DISSECTOR_NAME, 'dns'), l4_tlvs(C6, S6, PT_UDP, 40043, 53), end(), DNS_QUERY)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(IPV4_SRC, bytes(C4) + b'\0' * 4),
         tlv(IPV4_DST, bytes(S4) + b'\0' * 4), end(), b'padded address tags')
    # SS7 point codes, every standard
    for std, ni in ((1, 2), (2, 0), (3, 3), (4, 1)):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'),
             tlv(SS7_OPC, u32(0x1234 + std) + u16(std) + u8(ni) + b'\0'),
             tlv(SS7_DPC, u32(0x0567 + std) + u16(std) + u8(ni) + b'\0'),
             tlv(COL_PROT_TEXT, b'SS7'), tlv(COL_INFO_TEXT, b'SS7 standard %d' % std), end(), b'\x83\x01')
    # DVB-CI events: the two data transfer directions (the exported CI+ SAC
    # message), and the other events (no addresses set)
    for evt in (0xff, 0xfe):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'ciplus_sac_msg'), tlv(DVBCI_EVT, u8(evt)), end(), sac_msg())
    for evt in (0xfd, 0xfc, 0xfb, 0x00):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(DVBCI_EVT, u8(evt)), end(), b'dvb-ci event')
    # column texts, with a dissector that sets its own (kept) and none
    epdu(cap, name_tlv(DISSECTOR_NAME, 'dns'), l4_tlvs(C4, S4, PT_UDP, 40044, 53),
         tlv(COL_PROT_TEXT, b'MyProto\0'), tlv(COL_INFO_TEXT, 'Information text é'.encode() + b'\0\0'),
         end(), DNS_QUERY)
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'udp.port'), tlv(TABLE_NUM_VAL, u32(53)),
         tlv(COL_PROT_TEXT, b'TableProto'), tlv(COL_INFO_TEXT, b'table info'), end(), DNS_QUERY)
    epdu(cap, name_tlv(HEUR_DISSECTOR_NAME, 'sip_udp'), tlv(COL_PROT_TEXT, b'HeurProto'),
         tlv(COL_INFO_TEXT, b'heuristic info'), end(), SIP_OPTIONS)
    epdu(cap, tlv(COL_PROT_TEXT, b'Column only'), tlv(COL_INFO_TEXT, b'no dissector tag'), end(), b'metadata')
    # P2P and link directions
    for d in (0, 1, -1):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(P2P_DIRECTION, i32(d)), end(), b'p2p')
    for d in (0, 1, -1):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(LINK_DIRECTION, i32(d)), end(), b'link')
    # user data PDU (the "data" dissector unless the preference says otherwise)
    epdu(cap, tlv(USER_DATA_PDU, b''), end(), HTTP_REQ)
    # 3GPP identities: CGI, ECGI, NCGI (MCC 001 MNC 01; MCC 262 MNC 01)
    plmn1, plmn2 = b'\x00\xf1\x10', b'\x62\xf2\x10'
    epdu(cap, tlv(TGPP_ID, u8(0) + plmn1 + u16(0x1234) + u16(0x5678)), name_tlv(DISSECTOR_NAME, 'data'), end(), b'cgi')
    epdu(cap, tlv(TGPP_ID, u8(1) + plmn2 + u32(0xabcdef1 << 4)), name_tlv(DISSECTOR_NAME, 'data'), end(), b'ecgi')
    epdu(cap, tlv(TGPP_ID, u8(2) + plmn1 + bytes.fromhex('123456789f')), name_tlv(DISSECTOR_NAME, 'data'), end(), b'ncgi')
    # ... with tags too short, an empty one and an unknown identity type:
    # "Unexpected tag length" and "Unrecognized tag" warnings
    epdu(cap, tlv(TGPP_ID, u8(0) + plmn1 + u16(1)), name_tlv(DISSECTOR_NAME, 'data'), end(), b'short cgi')
    epdu(cap, tlv(TGPP_ID, u8(1) + plmn2 + u16(2)), name_tlv(DISSECTOR_NAME, 'data'), end(), b'short ecgi')
    epdu(cap, tlv(TGPP_ID, u8(2) + plmn1 + u32(3)), name_tlv(DISSECTOR_NAME, 'data'), end(), b'short ncgi')
    epdu(cap, tlv(TGPP_ID, b''), name_tlv(DISSECTOR_NAME, 'data'), end(), b'empty 3gpp id')
    epdu(cap, tlv(TGPP_ID, u8(7) + b'\0' * 7), name_tlv(DISSECTOR_NAME, 'data'), end(), b'unknown 3gpp id type')
    # 3GPP UE identity: an IMSI (associated) and others
    epdu(cap, tlv(TGPP_UE_ID, b'IMSI\0' + b'001010123456789\0'), name_tlv(DISSECTOR_NAME, 'data'), end(), b'imsi')
    epdu(cap, tlv(TGPP_UE_ID, b'IMSI\0' + b'310410987654321'), name_tlv(DISSECTOR_NAME, 'data'), end(), b'imsi, no null')
    epdu(cap, tlv(TGPP_UE_ID, b'SUPI\0' + b'imsi-001010000000001\0'), name_tlv(DISSECTOR_NAME, 'data'), end(), b'supi')
    epdu(cap, tlv(TGPP_UE_ID, b'\0'), name_tlv(DISSECTOR_NAME, 'data'), end(), b'empty ue id')
    # TCP information of the 19 octets the format describes, reassembled
    epdu(cap, name_tlv(DISSECTOR_NAME, 'http-over-tcp'), tcp4(40045, 80),
         tcpinfo(100, 100 + len(HTTP_REQ), 50, TH_PUSH | TH_ACK, reassembled=1, pad=False), end(), HTTP_REQ)
    # unsupported TCP information versions (0 and 0xffff); warning only
    epdu(cap, name_tlv(DISSECTOR_NAME, 'http-over-tcp'), tcp4(40046, 80),
         tlv(TCP_INFO_DATA, u16(0) + bytes(18)), end(), HTTP_REQ)
    epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(TCP_INFO_DATA, u16(0xffff)), end(), b'tcp info version 65535')
    # only the end-of-options tag, without and with a payload (a PDU without
    # it runs off the end: see the malformed capture)
    epdu(cap, end())
    epdu(cap, end(), b'no dissector tag at all')
    cap.section('D')

    cap.write(f'{out}/exported_pdu-coverage.pcap')
    src.write(f'{out}/exported_pdu-tcp-source.pcap')
    return cap


# --------------------------------------------------------------------------
# Malformed capture: exceptions and dissector bug reports

def build_malformed(out):
    cap = Pcap(252)
    # the original AMR-WB frame of the reproducer: its 23.85 kbit/s frame is
    # 40 octets, not 60 (AMR reports it as malformed)
    epdu(cap, tlv(DISSECTOR_NAME, b'amr-wb'),
         tlv(TCP_INFO_DATA, struct.pack('>HIIIBHH', 1, 1, 2, 3, 0, 0x18, 0)), end(), bytes([0xf0, 0x44]) + b'\x00' * 40)
    # port types the dissector does not map: DISSECTOR_ASSERT (packet-exported_pdu.c:217)
    for pt in (PT_NCP, PT_EXCHG, PT_SBCCS, PT_TIPC, PT_TDMOP, PT_IWARP_MPA, PT_MCTP, 99):
        epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(PORT_TYPE, u32(pt)), end(), b'port type %d' % pt)
    # no end-of-options tag: the tags run off the end of the packet
    epdu(cap, name_tlv(DISSECTOR_NAME, 'data'))
    # a tag longer than the packet
    epdu(cap, name_tlv(DISSECTOR_NAME, 'data'), tlv(COL_INFO_TEXT, b'abc', length=100))
    # fixed size tags cut short by the end of the packet
    epdu(cap, tlv(IPV4_SRC, b'\x0a\x01', length=2))
    epdu(cap, tlv(IPV6_DST, b'\x20\x01', length=2))
    epdu(cap, tlv(SS7_OPC, u32(1), length=4))
    epdu(cap, tlv(TCP_INFO_DATA, u16(1) + u32(1), length=6))
    epdu(cap, tlv(TGPP_ID, u8(2) + b'\0\0', length=9))
    # 3GPP UE identity: a type with no null in the packet
    epdu(cap, tlv(TGPP_UE_ID, b'IMSI'))
    cap.write(f'{out}/exported_pdu-coverage-malformed.pcap')
    # a truncated frame appended by hand: snap length cut
    data = name_tlv(DISSECTOR_NAME, 'dns') + end() + DNS_QUERY
    with open(f'{out}/exported_pdu-coverage-malformed.pcap', 'ab') as fh:
        fh.write(struct.pack('<IIII', 1800000000, 0, len(data) - 10, len(data)) + data[:-10])


# --------------------------------------------------------------------------
# Bug reproducers (each crashes or aborts tshark; not for the tree)

def build_bugs(out):
    # 1. A dissector table tag that names a string table: find_uint_dtbl_entry()
    #    reaches ws_assert_not_reached() (epan/packet.c:1280) and tshark aborts.
    cap = Pcap(252)
    epdu(cap, name_tlv(DISSECTOR_TABLE_NAME, 'media_type'), tlv(TABLE_NUM_VAL, u32(0)), end(), b'text')
    cap.write(f'{out}/exported_pdu-bug-strtable.pcap')

    # 2. PROXY v1 PDUs as "tshark -U 'OSI layer 4'" writes them: the PROXY
    #    heuristic, then the conversation's "proxy_v1" with TCP information.
    #    proxy_v1 is not in tcp.port, so it now gets NULL and hands it to
    #    decode_tcp_ports(); exporting this file again crashes in
    #    exp_pdu_tcp_dissector_data_populate_data() (packet-tcp.c:1758).
    cap = Pcap(252)
    src = Pcap(1)
    x = Source(src, cap)
    p = Conn(x, 40050, 12345)
    p.cli(b'PROXY TCP4 192.0.2.1 198.51.100.1 56324 80\r\n', ('heur', 'proxy_tcp'))
    p.cli(HTTP_REQ2, ('name', 'proxy_v1'))
    cap.write(f'{out}/exported_pdu-bug-reexport.pcap')

    # 3. The rtmpt_tcp heuristic dereferences the TCP information without a
    #    NULL check (packet-rtmpt.c:2779); with it enabled, an exported PDU
    #    naming it without a TCP information tag crashes tshark.
    cap = Pcap(252)
    epdu(cap, name_tlv(HEUR_DISSECTOR_NAME, 'rtmpt_tcp'), l4_tlvs(S4, C4, PT_TCP, 1935, 40051), end(), RTMP_S0S1S2[:16])
    cap.write(f'{out}/exported_pdu-bug-rtmpt-heur.pcap')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = build_main(out)
    build_malformed(out)
    build_bugs(out)
    for name, (a, b) in cap.marks.items():
        print(f'section {name}: frames {a}-{b}')


if __name__ == '__main__':
    main()
