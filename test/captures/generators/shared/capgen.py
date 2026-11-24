# Building blocks for the synthetic coverage capture generators.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Checksums, link/network/transport headers and pcap/pcapng writers.

Every function takes the values that differ between generators as
arguments, so that a generator states its addresses, ports and
timestamps instead of relying on a private copy of a helper with other
defaults. Keyword arguments are preferred at call sites.
"""

import struct

# Documentation addresses (RFC 5737, RFC 3849) and locally administered MACs.
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP4_A = '192.0.2.1'
IP4_B = '192.0.2.2'
IP6_A = '2001:db8::1'
IP6_B = '2001:db8::2'

# Link-layer header types used by the generators.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_WIRESHARK_UPPER_PDU = 252

TS_BASE = 1700000000


# ---------------------------------------------------------------- checksums

def inet_checksum(data, initial=0):
    """RFC 1071 Internet checksum (IPv4, ICMP, UDP, TCP)."""
    if len(data) % 2:
        data += b'\0'
    s = initial + sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC32C = _crc32c_table()


def crc32c(data, crc=0):
    """CRC-32C (Castagnoli), as used by SCTP and iSCSI."""
    crc ^= 0xffffffff
    for b in data:
        crc = _CRC32C[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc ^ 0xffffffff


# ---------------------------------------------------------------- addresses

def ip4(addr):
    """'192.0.2.1' or bytes -> 4 bytes."""
    if isinstance(addr, (bytes, bytearray)):
        return bytes(addr)
    return bytes(int(x) for x in addr.split('.'))


def ip6(addr):
    """'2001:db8::1' or bytes -> 16 bytes."""
    if isinstance(addr, (bytes, bytearray)):
        return bytes(addr)
    import ipaddress
    return ipaddress.IPv6Address(addr).packed


def mac(addr):
    """'02:00:00:00:00:01' or bytes -> 6 bytes."""
    if isinstance(addr, (bytes, bytearray)):
        return bytes(addr)
    return bytes.fromhex(addr.replace(':', '').replace('-', ''))


# ---------------------------------------------------------------- link layer

def eth(payload, ethertype, dst=MAC_B, src=MAC_A, vlan=None):
    """Ethernet II frame; vlan is a VLAN ID or a list of them (802.1Q)."""
    tags = b''
    if vlan is not None:
        for vid in (vlan if isinstance(vlan, (list, tuple)) else [vlan]):
            tags += struct.pack('!HH', 0x8100, vid)
    return mac(dst) + mac(src) + tags + struct.pack('!H', ethertype) + payload


def eth8023(payload, dst=MAC_B, src=MAC_A):
    """IEEE 802.3 frame with a length field (LLC follows in payload)."""
    return mac(dst) + mac(src) + struct.pack('!H', len(payload)) + payload


def llc(payload, dsap, ssap, control=0x03):
    return bytes([dsap, ssap, control]) + payload


def snap(payload, pid, oui=0):
    return llc(oui.to_bytes(3, 'big') + struct.pack('!H', pid) + payload, 0xaa, 0xaa)


# ---------------------------------------------------------------- network layer

def ipv4(payload, proto, src=IP4_A, dst=IP4_B, ident=1, ttl=64, flags_frag=0,
         tos=0, options=b'', checksum=True, total_length=None):
    """IPv4 header + payload. flags_frag is the 16-bit flags/fragment field
    (0x4000 = DF). checksum=False leaves the header checksum 0."""
    ihl = 5 + len(options) // 4
    tl = total_length if total_length is not None else 4 * ihl + len(payload)
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, tos, tl, ident, flags_frag, ttl, proto, 0,
                    ip4(src), ip4(dst)) + options
    if checksum:
        h = h[:10] + struct.pack('!H', inet_checksum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh, src=IP6_A, dst=IP6_B, hlim=64, tclass=0, flow=0, plen=None):
    pl = plen if plen is not None else len(payload)
    return struct.pack('!IHBB16s16s', (6 << 28) | (tclass << 20) | flow, pl, nh, hlim,
                       ip6(src), ip6(dst)) + payload


def _pseudo4(src, dst, proto, length):
    return ip4(src) + ip4(dst) + struct.pack('!BBH', 0, proto, length)


def _pseudo6(src, dst, nh, length):
    return ip6(src) + ip6(dst) + struct.pack('!IxxxB', length, nh)


def l4_checksum(segment, proto, src, dst):
    """Checksum of a UDP/TCP/ICMPv6 segment (with its checksum field 0)
    over the IPv4 or IPv6 pseudo-header, chosen by the address length."""
    v4 = (':' not in src) if isinstance(src, str) else len(src) == 4
    if v4:
        ph = _pseudo4(src, dst, proto, len(segment))
    else:
        ph = _pseudo6(src, dst, proto, len(segment))
    return inet_checksum(ph + segment)


# ---------------------------------------------------------------- transport

def udp(payload, sport, dport, src=None, dst=None, length=None):
    """UDP header + payload. The checksum is computed when src and dst
    (the IP addresses) are given, else it is 0."""
    ln = length if length is not None else 8 + len(payload)
    seg = struct.pack('!HHHH', sport, dport, ln, 0) + payload
    if src is not None and dst is not None:
        c = l4_checksum(seg, 17, src, dst) or 0xffff
        seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    return seg


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def tcp(payload, sport, dport, seq=0, ack=0, flags=TCP_PSH | TCP_ACK, win=65535,
        options=b'', urg=0, src=None, dst=None):
    """TCP header + payload; checksum as for udp()."""
    off = 5 + len(options) // 4
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      off << 4, flags, win, 0, urg) + options + payload
    if src is not None and dst is not None:
        seg = seg[:16] + struct.pack('!H', l4_checksum(seg, 6, src, dst)) + seg[18:]
    return seg


class TcpFlow:
    """Both directions of one TCP connection with sequence tracking.

    flow = TcpFlow(sport=40000, dport=80)
    frames += flow.handshake()
    frames.append(flow.send(b'GET / ...'))       # client -> server
    frames.append(flow.recv(b'HTTP/1.1 200'))    # server -> client
    Each call returns a complete Ethernet/IPv4 (or IPv6) frame.
    """

    def __init__(self, sport, dport, src=IP4_A, dst=IP4_B, isn_c=1000, isn_s=5000,
                 smac=MAC_A, dmac=MAC_B, v6=False, checksum=False, ip_ident=1):
        self.sport, self.dport, self.src, self.dst = sport, dport, src, dst
        self.seq = [isn_c, isn_s]
        self.smac, self.dmac, self.v6, self.checksum = smac, dmac, v6, checksum
        self.ident = ip_ident

    def _frame(self, d, payload, flags):
        sp, dp = (self.sport, self.dport) if d == 0 else (self.dport, self.sport)
        s, t = (self.src, self.dst) if d == 0 else (self.dst, self.src)
        sm, dm = (self.smac, self.dmac) if d == 0 else (self.dmac, self.smac)
        ck = dict(src=s, dst=t) if self.checksum else {}
        seg = tcp(payload, sp, dp, self.seq[d], self.seq[1 - d] if flags & TCP_ACK else 0,
                  flags, **ck)
        self.seq[d] += len(payload) + (1 if flags & (TCP_SYN | TCP_FIN) else 0)
        if self.v6:
            return eth(ipv6(seg, 6, s, t), 0x86dd, dst=dm, src=sm)
        self.ident += 1
        return eth(ipv4(seg, 6, s, t, ident=self.ident - 1), 0x0800, dst=dm, src=sm)

    def handshake(self):
        return [self._frame(0, b'', TCP_SYN), self._frame(1, b'', TCP_SYN | TCP_ACK),
                self._frame(0, b'', TCP_ACK)]

    def send(self, payload, flags=TCP_PSH | TCP_ACK):
        return self._frame(0, payload, flags)

    def recv(self, payload, flags=TCP_PSH | TCP_ACK):
        return self._frame(1, payload, flags)

    def close(self):
        return [self._frame(0, b'', TCP_FIN | TCP_ACK), self._frame(1, b'', TCP_FIN | TCP_ACK),
                self._frame(0, b'', TCP_ACK)]


def sctp(chunks, sport, dport, vtag, checksum=True):
    """SCTP common header + chunks, with the CRC-32C checksum."""
    pkt = struct.pack('!HHII', sport, dport, vtag, 0) + chunks
    if checksum:
        pkt = pkt[:8] + struct.pack('<I', crc32c(pkt)) + pkt[12:]
    return pkt


def sctp_data(payload, tsn, ppid, sid=0, ssn=0, flags=0x03):
    """One SCTP DATA chunk (padded to 4 bytes)."""
    c = struct.pack('!BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppid) + payload
    return c + b'\0' * (-len(c) % 4)


# ---------------------------------------------------------------- exported PDU

EXP_PDU_TAG_END_OF_OPT = 0
EXP_PDU_TAG_DISSECTOR_NAME = 12
EXP_PDU_TAG_HEUR_DISSECTOR_NAME = 13
EXP_PDU_TAG_DISSECTOR_TABLE_NAME = 14
EXP_PDU_TAG_COL_PROT_TEXT = 20
EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL = 32


def exp_pdu_tag(tag, value):
    """One exported-PDU TLV, the value padded to 4 bytes."""
    return struct.pack('!HH', tag, len(value) + (-len(value) % 4)) + value + b'\0' * (-len(value) % 4)


def exported_pdu(payload, proto=None, heur=None, table=None, table_value=None, extra=b''):
    """Wireshark upper PDU (LINKTYPE_WIRESHARK_UPPER_PDU): payload handed to
    a named dissector (proto), heuristic (heur) or table (table, table_value)."""
    tags = b''
    if proto is not None:
        tags += exp_pdu_tag(EXP_PDU_TAG_DISSECTOR_NAME, proto.encode())
    if heur is not None:
        tags += exp_pdu_tag(EXP_PDU_TAG_HEUR_DISSECTOR_NAME, heur.encode())
    if table is not None:
        tags += exp_pdu_tag(EXP_PDU_TAG_DISSECTOR_TABLE_NAME, table.encode())
        if table_value is not None:
            tags += exp_pdu_tag(EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL, struct.pack('!I', table_value))
    return tags + extra + struct.pack('!HH', EXP_PDU_TAG_END_OF_OPT, 0) + payload


# ---------------------------------------------------------------- capture files

def ts_seconds(i):
    """Frame i at TS_BASE + i seconds."""
    return TS_BASE + i, 0


def write_pcap(path, frames, linktype=LINKTYPE_ETHERNET, snaplen=262144, ts=ts_seconds,
               nsec=False, endian='<'):
    """Write a pcap file.

    frames: bytes, or (bytes, original_length) for a frame cut to fewer
    bytes than it had on the wire.
    ts: function from the frame index to (seconds, fraction) where the
    fraction is in microseconds (nanoseconds when nsec is set).
    """
    magic = 0xa1b23c4d if nsec else 0xa1b2c3d4
    with open(path, 'wb') as f:
        f.write(struct.pack(endian + 'IHHiIII', magic, 2, 4, 0, 0, snaplen, linktype))
        for i, fr in enumerate(frames):
            orig = None
            if isinstance(fr, tuple):
                fr, orig = fr
            sec, frac = ts(i)
            f.write(struct.pack(endian + 'IIII', sec, frac, len(fr),
                                len(fr) if orig is None else orig))
            f.write(fr)


def _pad4(b):
    return b + b'\0' * (-len(b) % 4)


def pcapng_option(code, value):
    return struct.pack('<HH', code, len(value)) + _pad4(value)


def pcapng_block(btype, body):
    ln = 12 + len(body)
    return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)


class Pcapng:
    """Little-endian pcapng writer.

    w = Pcapng()
    eth_if = w.interface(LINKTYPE_ETHERNET)
    w.packet(eth_if, frame, ts=(sec, usec), comment='...')
    w.secrets(0x544c534b, b'CLIENT_RANDOM ...')   # Decryption Secrets Block
    w.write(path)
    """

    def __init__(self, shb_options=b''):
        self.blocks = [pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
                                    + (shb_options + struct.pack('<I', 0) if shb_options else b''))]
        self.n_if = 0

    def interface(self, linktype, snaplen=262144, options=b'', tsresol=None):
        opts = options
        if tsresol is not None:
            opts += pcapng_option(9, bytes([tsresol]))
        if opts:
            opts += struct.pack('<I', 0)
        self.blocks.append(pcapng_block(1, struct.pack('<HHI', linktype, 0, snaplen) + opts))
        self.n_if += 1
        return self.n_if - 1

    def packet(self, iface, data, ts=(TS_BASE, 0), orig_len=None, comment=None, options=b''):
        """Enhanced Packet Block. ts is (seconds, fraction) in the
        interface's resolution (microseconds by default)."""
        sec, frac = ts
        t = sec * 1000000 + frac
        opts = options
        if comment is not None:
            opts += pcapng_option(1, comment.encode())
        if opts:
            opts += struct.pack('<I', 0)
        body = struct.pack('<IIIII', iface, t >> 32, t & 0xffffffff, len(data),
                           len(data) if orig_len is None else orig_len) + _pad4(data) + opts
        self.blocks.append(pcapng_block(6, body))

    def secrets(self, secrets_type, data):
        """Decryption Secrets Block (e.g. 0x544c534b TLS key log)."""
        self.blocks.append(pcapng_block(10, struct.pack('<II', secrets_type, len(data)) + _pad4(data)))

    def raw_block(self, btype, body):
        self.blocks.append(pcapng_block(btype, body))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


def write_pcapng(path, frames, linktype=LINKTYPE_ETHERNET, ts=ts_seconds):
    """Single-interface pcapng; frames as for write_pcap()."""
    w = Pcapng()
    w.interface(linktype)
    for i, fr in enumerate(frames):
        orig = None
        if isinstance(fr, tuple):
            fr, orig = fr
        w.packet(0, fr, ts=ts(i), orig_len=orig)
    w.write(path)


def read_pcap(path):
    """Frames of a pcap file (bytes only), either byte order and resolution."""
    with open(path, 'rb') as f:
        d = f.read()
    e = '<' if d[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off, out = 24, []
    while off + 16 <= len(d):
        incl = struct.unpack(e + 'I', d[off + 8:off + 12])[0]
        out.append(d[off + 16:off + 16 + incl])
        off += 16 + incl
    return out


SECRETS_TLS_KEYLOG = 0x544c534b


def pcap_with_secrets(pcap_path, keylog_path, out_path, secrets_type=SECRETS_TLS_KEYLOG):
    """Write out_path, a pcapng file with the frames of the pcap file
    pcap_path (microsecond timestamps) and a Decryption Secrets Block
    holding keylog_path, as `editcap --inject-secrets tls,<keylog>` does."""
    with open(pcap_path, 'rb') as f:
        d = f.read()
    e = '<' if d[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    snaplen, linktype = struct.unpack(e + 'II', d[16:24])
    with open(keylog_path, 'rb') as f:
        secrets = f.read()
    w = Pcapng()
    w.secrets(secrets_type, secrets)
    w.interface(linktype, snaplen=snaplen)
    off = 24
    while off + 16 <= len(d):
        sec, usec, incl, orig = struct.unpack(e + 'IIII', d[off:off + 16])
        w.packet(0, d[off + 16:off + 16 + incl], ts=(sec, usec), orig_len=orig)
        off += 16 + incl
    w.write(out_path)
