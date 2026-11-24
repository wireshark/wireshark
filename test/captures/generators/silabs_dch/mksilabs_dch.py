# Generates test/captures/silabs_dch_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# --- pcap helpers (synthetic addresses only) ---
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64, flags_frag=0, options=b''):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ihl = 5 + len(options) // 4
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags_frag, ttl, proto, 0, s, d) + options
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]

def eth(payload, ethertype=0x0800, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst) + u)

def tcp(sport, dport, payload, seq=1, ack=1, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst) + t)

def ipv6(nxt, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)

def write(fn, pkts, linktype=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def exported_pdu(name, payload, tag=12):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', tag, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

class Flow:
    '''TCP connection with a handshake and tracked sequence numbers.'''
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', cisn=1000, sisn=5000, hs=False):
        self.cp, self.sp, self.c, self.s = cport, sport, client, server
        self.cseq, self.sseq = cisn, sisn
        self.pk = []
        if hs:
            self.pk.append(tcp(cport, sport, b'', self.cseq, 0, client, server, 0x02)); self.cseq += 1
            self.pk.append(tcp(sport, cport, b'', self.sseq, self.cseq, server, client, 0x12)); self.sseq += 1
            self.pk.append(tcp(cport, sport, b'', self.cseq, self.sseq, client, server, 0x10))
    def c2s(self, data):
        self.pk.append(tcp(self.cp, self.sp, data, self.cseq, self.sseq, self.c, self.s)); self.cseq += len(data)
    def s2c(self, data):
        self.pk.append(tcp(self.sp, self.cp, data, self.sseq, self.cseq, self.s, self.c)); self.sseq += len(data)

def tpkt(payload):
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload

def cotp_dt(payload, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + payload)

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t
_CRC_T = _crc32c_table()

def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _CRC_T[(c ^ b) & 0xff] ^ (c >> 8)
    return (~c) & 0xffffffff

def sctp_data(sport, dport, payload, ppi=0, tsn=1, sid=0, ssn=0, vtag=0x11223344, src='192.0.2.1', dst='192.0.2.2', flags=3):
    '''SCTP packet with one DATA chunk (B and E flags set by default).'''
    pad = (-len(payload)) % 4
    chunk = struct.pack('!BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppi) + payload + b'\0' * pad
    hdr = struct.pack('!HHII', sport, dport, vtag, 0)
    cs = crc32c(hdr + chunk)
    hdr = struct.pack('!HHI', sport, dport, vtag) + struct.pack('<I', cs)
    pkt = hdr + chunk
    return eth(ipv4(132, pkt, src, dst) + pkt)

def write_pcapng(fn, pkts, linktypes=(1,), snap=262144):
    '''pkts: list of (interface index, bytes). One IDB per link-layer type.'''
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, snap))
    for i, (ifc, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(fn, 'wb').write(out)
# --- end helpers ---
# Generator for the Silabs Debug Channel coverage captures: python3 mksilabs_dch.py <outdir>
# Silicon Labs debug channel frames use pcap/pcapng link-layer type 298.
# The main capture is a pcapng file with two interfaces (so that the BLE
# connection tracking, keyed by interface, sees both).
import zlib
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def kermit(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc & 0xffff

def fcs(data, n):
    if n == 2: return struct.pack('<H', kermit(data))
    if n == 4: return struct.pack('<I', zlib.crc32(data) & 0xffffffff)
    return b''

def mac_data(seq, payload=b'\x04', n=2):
    '''IEEE 802.15.4 MAC command frame, by default a data request (short
    addresses, PAN id compression).'''
    f = struct.pack('<HBHHH', 0x8863, seq, 0x1234, 0x0001, 0x0002) + payload
    return f + fcs(f, n)

def mac_ack(seq, n=2):
    f = struct.pack('<HB', 0x0002, seq)
    return f + fcs(f, n)

def dch(efr, ver=3, mtype=0x2a, seq=1, ts=0x1122334455):
    if ver > 2:
        h = struct.pack('<H', ver) + struct.pack('<Q', ts) + struct.pack('<HIH', mtype, 0x00000001, seq)
    else:
        h = struct.pack('<H', ver) + struct.pack('<Q', ts)[:6] + struct.pack('<HB', mtype, seq & 0xff)
    return h + efr

def efr(proto, rx, ota, *, rssi=0x40, sync=None, cfg=b'', chan=5, err=0, ver=1, ant=0, hwstart=0xf8, hwend=None):
    '''EFR32 PTI payload: hw start, OTA payload, hw end, [RSSI] [syncword]
    [radio config], radio info, status, appended info config.'''
    if hwend is None: hwend = 0xf9 if rx else 0xfd
    var = (bytes([rssi]) if rx else b'') + (sync if sync is not None else b'') + cfg
    appended = (0x40 if rx else 0) | (len(var) << 3) | ver
    radioinfo = (ant << 7) | (0x40 if sync is not None else 0) | (chan & 0x3f)
    return bytes([hwstart]) + ota + bytes([hwend]) + var + bytes([radioinfo, (err << 4) | proto, appended])

def phr_fsk(length):          # 16 bit SUN FSK PHR: length (11 bits) bit reversed
    v = 0
    for i in range(16):
        if length & (1 << i): v |= 1 << (15 - i)
    return struct.pack('<H', v)

def rev16(v):
    r = 0
    for i in range(16):
        if v & (1 << i): r |= 1 << (15 - i)
    return r

AA_ADV = 0x8e89bed6
def ble_adv(pdu_type, payload, tx=0):
    return bytes([pdu_type | (tx << 6), len(payload)]) + payload
def ble_data(llid, payload=b'', nesn=0, sn=0):
    return bytes([llid | (nesn << 2) | (sn << 3), len(payload)]) + payload
def ble_crc(pdu, init):
    '''24 bit BLE CRC over the PDU, as the BTLE dissector checks it.'''
    state = init
    for byte in pdu:
        for i in range(8):
            fb = ((state >> 23) & 1) ^ ((byte >> i) & 1)
            state = (state << 1) & 0xffffff
            if fb: state ^= 0x00065b
    rev = lambda b: int('{:08b}'.format(b)[::-1], 2)
    return bytes([rev((state >> 16) & 0xff), rev((state >> 8) & 0xff), rev(state & 0xff)])

CRCINIT = 0x332211            # the CRC init of the connections made by connect_ind()
CRC3 = b'\xaa\xbb\xcc'
MACI, MACA = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
def connect_ind(aa):
    return ble_adv(5, MACI + MACA + struct.pack('<I', aa) + b'\x11\x22\x33' + b'\x03' + struct.pack('<HHHH', 1, 24, 0, 72) + b'\xff\xff\xff\xff\x1f' + b'\x0a')

def ble(ifc, rx, pdu, aa, rssi=0x30, cfg=b'', chan=12, ver=1):
    sync = struct.pack('<I', aa)
    crc = ble_crc(pdu, 0x555555 if aa == AA_ADV else CRCINIT)
    return (ifc, dch(efr(3, rx, pdu + crc, rssi=rssi, sync=sync, cfg=cfg, chan=chan, ver=ver)))

frames = []
def F(ifc, d): frames.append((ifc, d))

# ---- debug channel header: version 2 and 3, message types that are not decoded
F(0, dch(b'\x01\x02\x03', ver=3, mtype=0x0001))
F(0, dch(b'\x01\x02\x03', ver=2, mtype=0x0002, seq=7))
F(0, dch(b'\x01\x02\x03', ver=3, mtype=0x7777))
F(0, dch(b'\x01\x02\x03', ver=3, mtype=0x000a))

# ---- BLE: data PDUs before and after the CONNECT_IND of their access address
# (the reproducer of the second pass inconsistency), roles from the CONNECT_IND
AA1, AA2 = 0x50123456, 0x60abcdef
F(0, ble(0, 1, ble_data(1), AA1, cfg=b'\x01')[1])             # frame 5: data PDU on AA1 before its CONNECT_IND
F(0, ble(0, 0, ble_data(1), AA1)[1])                          # TX
F(0, ble(0, 1, connect_ind(AA1), AA_ADV)[1])                  # RX CONNECT_IND: the device is the peripheral
F(0, ble(0, 1, ble_data(1, nesn=1, sn=1), AA1)[1])            # RX data from the central
F(0, ble(0, 0, ble_data(2, b'\x01\x02', nesn=0, sn=1), AA1)[1])   # TX data (L2CAP start)
F(0, ble(0, 1, ble_data(3, b'\x13', nesn=1, sn=0), AA1, cfg=b'\x02')[1])       # LL control, radio config with BLE PHY id
F(0, ble(0, 0, connect_ind(AA2), AA_ADV)[1])                  # TX CONNECT_IND: the device is the central
F(0, ble(0, 0, ble_data(1), AA2)[1])
F(0, ble(0, 1, ble_data(1, nesn=1), AA2)[1])
F(0, ble(0, 1, connect_ind(AA2), AA_ADV)[1])                  # the same access address again, other role
F(0, ble(0, 0, ble_data(1), AA2)[1])
# advertising PDUs (default BTLE path): ADV_IND, SCAN_REQ
F(0, ble(0, 1, ble_adv(0, MACA + b'\x02\x01\x06'), AA_ADV)[1])
F(0, ble(0, 0, ble_adv(3, MACI + MACA), AA_ADV)[1])
# on the second interface: a data PDU for AA1 (unknown there), then a CONNECT_IND
F(1, ble(1, 1, ble_data(1), AA1)[1])
F(1, ble(1, 0, connect_ind(AA1), AA_ADV)[1])
F(1, ble(1, 0, ble_data(1), AA1)[1])
# BLE without a syncword (RX, RSSI only): nothing is handed to BTLE
F(0, dch(efr(3, 1, ble_data(1) + CRC3, rssi=0x20, chan=3)))
# BLE with the two byte radio config; version 2 RSSI (no offset)
F(0, ble(0, 1, ble_data(1), AA1, cfg=b'\x00\x05', ver=2)[1])
# BLE TX with config
F(0, ble(0, 0, ble_data(1, nesn=1, sn=1), AA1, cfg=b'\x01', chan=20)[1])

# ---- 802.15.4 based protocols: Zigbee (5), Thread (2), custom (8) on RAIL
# radio config byte: bit 7 two byte PHR, bit 6 soft modem, bit 4 external, bits 2-0 id
def rcfg(phr2=0, soft=0, ext=0, rid=0): return bytes([(phr2 << 7) | (soft << 6) | (ext << 4) | rid])
m = mac_data(1)
F(0, dch(efr(5, 1, bytes([len(m)]) + m, cfg=rcfg(0, 0, 0, 0), chan=4)))            # RX, 1 octet PHR, OQPSK 2.4 GHz
F(0, dch(efr(5, 0, bytes([len(m)]) + m, cfg=rcfg(0, 0, 1, 0), chan=15)))           # TX
F(0, dch(efr(2, 1, struct.pack('<H', len(m)) + m, cfg=rcfg(1, 0, 0, 1), chan=0, ant=1)))       # 2 octet PHR, BPSK 868
F(0, dch(efr(8, 1, struct.pack('<H', len(m)) + m, cfg=rcfg(1, 0, 0, 2), chan=9)))   # BPSK 915
ack = mac_ack(9)
F(0, dch(efr(5, 1, bytes([len(ack)]) + ack, cfg=rcfg(0, 0, 0, 3), chan=2)))      # unknown radio config id, ACK frame
for rid, ch in ((5, 3), (5, 30), (5, 40), (5, 63), (6, 7), (4, 9), (7, 10)):
    F(0, dch(efr(5, 1, bytes([len(m)]) + m, cfg=rcfg(0, 0, 0, rid), chan=ch)))
F(0, dch(efr(2, 1, bytes([len(m)]) + m, cfg=rcfg(0, 0, 0, 0) + b'\x04', chan=6)))     # radio config with PHY id
F(0, dch(efr(8, 0, bytes([len(m)]) + m, cfg=rcfg(0, 0, 0, 0) + b'\x03', chan=6)))     # TX with config extension
F(0, dch(efr(5, 1, bytes([len(m)]) + m, sync=b'\x00\x00\x00\x00', cfg=rcfg(0, 0, 0, 0), chan=11)))   # with a syncword
F(0, dch(efr(5, 1, bytes([len(m)]) + m, chan=11)))                                # RX with RSSI only: no radio config
F(0, dch(efr(5, 0, bytes([len(m)]) + m)))                                          # TX without anything
F(0, dch(efr(2, 1, struct.pack('<I', len(m)) + m, cfg=rcfg(0, 1, 0, 0), chan=1)))  # soft modem: 4 octet PHR
F(0, dch(efr(5, 1, bytes([len(m)]) + m, cfg=rcfg(0, 0, 0, 0), chan=4, err=3)))     # error code in the status

# ---- Wi-SUN on RAIL (7): FSK PHR, mode switch PHR, OFDM PHR, garbage byte, raw
L = len(mac_data(1, b'\x04', 4))
ws_fsk = phr_fsk(L) + mac_data(1, b'\x04', 4)
F(0, dch(efr(7, 1, ws_fsk, cfg=rcfg(1, 0, 0, 1) + b'\x08', chan=3)))                 # PHY mode id 8 (FSK #5)
F(0, dch(efr(7, 1, b'\x0b' + ws_fsk, cfg=rcfg(1, 0, 0, 0) + b'\x01', chan=4)))        # with the 0x0b garbage byte
F(0, dch(efr(7, 1, b'\x00' + ws_fsk, cfg=rcfg(1, 0, 0, 2) + b'\x03', chan=5)))        # with a 0x00 garbage byte
ws_ms = struct.pack('<H', int('1000000100000011', 2))                                # mode switch PHR (bit 0 set)
F(0, dch(efr(7, 1, ws_ms, cfg=rcfg(1, 0, 0, 0) + b'\x02', chan=6)))
F(0, dch(efr(7, 1, b'\x0b' + ws_ms, cfg=rcfg(1, 0, 0, 0) + b'\x02', chan=6)))
body = mac_data(5, b'\x04', 0)
N = 4 + len(body)
ws_ofdm = b'\x00' + struct.pack('<I', rev16(N << 5) << 6)[:3] + body
F(0, dch(efr(7, 1, ws_ofdm, cfg=rcfg(0, 1, 0, 0) + b'\x22', chan=7)))                  # OFDM, PHY mode id 0x22
F(0, dch(efr(7, 1, b'\x66\x77' + mac_data(1, b'\x04', 4), cfg=rcfg(1, 0, 0, 0) + b'\x01', chan=8)))   # PHR that matches nothing
F(0, dch(efr(7, 1, b'\x22\x00\x00\x00' + mac_data(5, b'\x04', 4), cfg=rcfg(0, 1, 0, 0) + b'\x22', chan=7)))            # 4 octet PHR that is not OFDM
F(0, dch(efr(7, 0, ws_fsk, cfg=rcfg(1, 0, 0, 1) + b'\x08', chan=3)))                      # TX

# ---- protocols the dissector does not decode: payload shown as unsupported
for proto in (0, 1, 4, 6, 9, 10):
    cfgb = rcfg(0, 0, 0, 1) + (b'\x03' if proto == 1 else b'')
    F(0, dch(efr(proto, 1, b'\x05payl', cfg=cfgb, chan=2)))
F(0, dch(efr(6, 1, b'\x05payl', cfg=b'\x03', chan=2)))                                # Z-Wave radio config (region id)
F(0, dch(efr(0, 0, b'\x05payl', chan=2)))
F(0, dch(efr(0, 1, b'')))                                                               # no OTA payload
# hardware start / end values: DMP protocol switch, aborts
F(0, dch(efr(5, 1, bytes([len(m)]) + m, cfg=rcfg(), hwstart=0xf0)))
F(0, dch(efr(5, 1, bytes([len(m)]) + m, cfg=rcfg(), hwend=0xfa)))
F(0, dch(efr(5, 0, bytes([len(m)]) + m, cfg=rcfg(), hwstart=0xfc, hwend=0xfe)))

write_pcapng(os.path.join(outdir, 'silabs-dch-coverage.pcapng'), frames, linktypes=(298, 298))

# ---- malformed capture
bad = []
def B(d): bad.append((0, d))
B(dch(b'\xf8\x00\x00\x00\x00\x07'))                                                    # TX, variable length 0 but with version bits
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x68'))                                                # RX with variable length 5 (valid) and no data
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x40'))                                                # RX with variable length 0: invalid
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x60'))                                                # RX with variable length 4: invalid
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x30'))                                                # TX with variable length 6
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x38'))                                                # TX with variable length 7: invalid
B(dch(b'\xf8\xf9\x00\x00\x00\x00\x18'))                                                # TX with variable length 3: invalid
B(dch(b'\x01\x02')[:5]); B(b'\x03\x00\x00')
B(dch(efr(5, 1, bytes([len(m)]) + m[:6], cfg=rcfg())))                                  # frame cut short
B(dch(efr(5, 1, bytes([40]) + m, cfg=rcfg())))                                          # PHR longer than the frame
B(dch(efr(5, 1, b'', cfg=rcfg())))
B(dch(efr(7, 1, b'\x0b\x01\x02', cfg=rcfg(1, 0, 0, 0) + b'\x01')))
B(dch(efr(7, 1, b'\x00\x01\x02\x03', cfg=rcfg(0, 1, 0, 0) + b'\x22')))
B(ble(0, 1, ble_data(1)[:1], AA1)[1])
B(ble(0, 1, connect_ind(AA1)[:20], AA_ADV)[1])
B(ble(0, 1, ble_adv(5, MACI + MACA + struct.pack('<I', AA1) + b'\x11\x22\x33\x03'), AA_ADV)[1])    # CONNECT_IND with 20 octet payload
B(dch(efr(3, 1, b'', sync=struct.pack('<I', AA1))))
B(dch(efr(3, 1, b'\x01', sync=struct.pack('<I', AA1))))
B(dch(efr(3, 1, b'\x01\x20' + b'\x00' * 4 + CRC3, sync=struct.pack('<I', AA1))))
B(dch(efr(2, 1, b'\x40\x00', cfg=rcfg(), chan=1)))
B(dch(b'\xf8' + b'\x00' * 3 + b'\x4a'))                                                # RX, 1 octet var length 1 with too little data
write_pcapng(os.path.join(outdir, 'silabs-dch-coverage-malformed.pcapng'), bad, linktypes=(298,))
