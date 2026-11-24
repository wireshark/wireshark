# Generates test/captures/signal_pdu_coverage.pcapng.gz
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

def write_pcapng(fn, pkts, linktypes=(1,), snap=262144, names=None):
    '''pkts: list of (interface index, bytes). One IDB per link-layer type.'''
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for i, lt in enumerate(linktypes):
        opts = b''
        if names:
            n = names[i].encode()
            opts = struct.pack('<HH', 2, len(n)) + n + b'\0' * ((-len(n)) % 4) + struct.pack('<HH', 0, 0)
        out += blk(1, struct.pack('<HHI', lt, 0, snap) + opts)
    for i, (ifc, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(fn, 'wb').write(out)
# --- end helpers ---
# Generator for the Signal PDU coverage captures: python3 mksignal_pdu.py <outdir>
# Signal PDU only decodes what its UATs describe, so this script also writes
# the configuration: cfg/ (the profile used for the main capture and the
# malformed one) and cfg/profiles/bad*/ (one invalid UAT record each, to
# reach the checks of the UAT update callbacks).
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def uat_line(rec):
    return ','.join('"%s"' % f for f in rec) + '\n'

def write_uat(d, name, recs):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), 'w') as f:
        f.write('# Generated by mksignal_pdu.py\n')
        for r in recs:
            f.write(uat_line(r))

def sig(pid, n, pos, name, filt, dt, be, base, enc, scaler='1', offset='0', mux='FALSE', muxv='-1',
        hidden='FALSE', asum='FALSE', aavg='FALSE', aint='FALSE'):
    return (pid, n, pos, name, filt, dt, be, base, enc, scaler, offset, mux, muxv, hidden, asum, aavg, aint)

SIGNALS = []
def pdu(pid, *specs):
    n = len(specs)
    for i, s in enumerate(specs):
        SIGNALS.append(sig(pid, n, i, *s))

# 1: every numeric type, shortened and unaligned values (19 octets: CAN FD)
pdu('1',
    ('Counter', 'counter', 'uint', 'FALSE', 8, 8),
    ('Speed', 'speed', 'uint', 'TRUE', 16, 16),
    ('Scaled', 'scaled', 'uint', 'FALSE', 8, 8, '2', '10'),
    ('Temp', 'temp', 'int', 'FALSE', 8, 8),
    ('Short', 'short', 'uint', 'TRUE', 16, 12),
    ('Nibble', 'nibble', 'uint', 'FALSE', 8, 4),
    ('FloatBE', 'float_be', 'float', 'TRUE', 32, 32),
    ('DoubleLE', 'double_le', 'float', 'FALSE', 64, 64))
# 2: multiplexer with signals of the selected multiplex value
pdu('2',
    ('Selector', 'sel', 'uint', 'FALSE', 8, 8, '1', '0', 'TRUE'),
    ('Alpha', 'alpha', 'uint', 'TRUE', 16, 16, '1', '0', 'FALSE', '0'),
    ('Beta', 'beta', 'int', 'FALSE', 16, 16, '1', '0', 'FALSE', '1'),
    ('Gamma', 'gamma', 'uint', 'FALSE', 8, 8, '1', '0', 'FALSE', '2'),
    ('Common', 'common', 'uint', 'FALSE', 8, 8))
# 3: strings of every type
pdu('3',
    ('Text', 'text', 'string', 'FALSE', 8, 32),
    ('TextZ', 'textz', 'stringz', 'FALSE', 8, 0),
    ('TextLen', 'textlen', 'uint_string', 'FALSE', 8, 8),
    ('UtfText', 'utftext', 'utf_string', 'FALSE', 8, 24),
    ('Utf16Text', 'utf16text', 'utf_string', 'FALSE', 16, 32),
    ('Utf16Z', 'utf16z', 'utf_stringz', 'FALSE', 16, 0),
    ('UtfLen', 'utflen', 'utf_uint_string', 'TRUE', 8, 16),
    ('Utf16Len', 'utf16len', 'utf_uint_string', 'FALSE', 16, 8))
# 4: aggregation, hidden signal, value names, signed value names
pdu('4',
    ('Level', 'level', 'uint', 'FALSE', 8, 8, '1', '0', 'FALSE', '-1', 'FALSE', 'TRUE', 'TRUE', 'TRUE'),
    ('Hidden', 'hidden', 'uint', 'FALSE', 8, 8, '1', '0', 'FALSE', '-1', 'TRUE'),
    ('State', 'state', 'uint', 'FALSE', 8, 8),
    ('Delta', 'delta', 'int', 'FALSE', 8, 8, '1', '0', 'FALSE', '-1', 'FALSE', 'FALSE', 'TRUE'),
    ('Gain', 'gain', 'uint', 'FALSE', 8, 8, '4', '1', 'FALSE', '-1', 'FALSE', 'FALSE', 'FALSE', 'TRUE'))
# 5: a short message used on every transport
for p in ('6', '7', '8', '9', 'a', 'b', 'c', 'd'):
    pdu(p, ('Count', 'count', 'uint', 'FALSE', 8, 8), ('Value', 'value', 'uint', 'TRUE', 16, 16))
# 0xe: a string that follows a 4 bit signal (not byte aligned: only in the malformed capture)
pdu('e', ('Nib', 'nib', 'uint', 'FALSE', 8, 4), ('Str', 'str', 'string', 'FALSE', 8, 16))

MESSAGES = [('1', 'Basic'), ('2', 'Mux'), ('3', 'Strings'), ('4', 'Aggregates'), ('5', 'Unconfigured'),
            ('6', 'OverCAN'), ('7', 'OverLIN'), ('8', 'OverFlexRay'), ('9', 'OverPduTransport'),
            ('a', 'OverSomeIp'), ('b', 'OverDlt'), ('c', 'OverUds'), ('d', 'OverIsobus'), ('e', 'Unaligned')]
VALUES = [  # id, pos, number of names, start, end, name
    ('4', 2, 3, '0', '0', 'Off'), ('4', 2, 3, '1', '1', 'On'), ('4', 2, 3, '2', 'ff', 'Error'),
    ('1', 3, 1, '0', '0', 'Zero'),
]
CAN_MAP = [('100', '0', '1'), ('80000101', '0', '2'), ('102', '0', '3'), ('103', '0', '4'), ('104', '0', '5'),
           ('105', '0', '6'), ('106', '2', '6'), ('80000107', '2', '2'), ('109', '0', 'e')]
LIN_MAP = [('10', '0', '7'), ('11', '3', '6')]
FR_MAP = [('0', '0', 'a', '8'), ('1', '5', '14', '6')]       # channel (0 = A, 1 = B), cycle, frame id (hex: 10 and 20), message
PDUT_MAP = [('1000', '9'), ('1001', '4')]
SOMEIP_MAP = [('1234', '1', '1', '0', 'a'), ('1234', '2', '1', '2', '6')]   # service, method, version, type, message
IPDUM_MAP = [('2000', '6')]
# the AUTOSAR I-PduM configuration that delivers PDU 0x2000 to Signal PDU: message 1 has one PDU of 24 bits at bit 0
IPDUM_MESSAGES = [('1', 1, 0, '2000', 'Pdu_Sp', 0, 24, 65535)]
IPDUM_CAN = [('108', '0', '1')]
DLT_MAP = [('ECU1', '1', 'b')]
UDS_MAP = [('ffffffff', '22', 'FALSE', 'f190', 'c'), ('7e0', '62', 'TRUE', 'f190', 'c')]
ISOBUS_MAP = [('f004', '0', 'd')]
CAN_IF = [('ffffffff', 'can1', '2')]
LIN_IF = [('ffffffff', 'lin1', '3')]

def write_profile(d, signals=SIGNALS, bad=None):
    '''Writes all UAT files; bad = (file name, record) replaces that table by one invalid record.'''
    tables = {
        'Signal_PDU_identifiers': MESSAGES, 'Signal_PDU_signal_list': signals, 'Signal_PDU_signal_values': VALUES,
        'Signal_PDU_Binding_CAN': CAN_MAP, 'Signal_PDU_Binding_LIN': LIN_MAP,
        'Signal_PDU_Binding_FlexRay': FR_MAP, 'Signal_PDU_Binding_PDU_Transport': PDUT_MAP,
        'Signal_PDU_Binding_SOMEIP': SOMEIP_MAP, 'Signal_PDU_Binding_AUTOSAR_IPduM': IPDUM_MAP,
        'Signal_PDU_Binding_DLT': DLT_MAP, 'Signal_PDU_Binding_UDS': UDS_MAP, 'Signal_PDU_Binding_ISOBUS': ISOBUS_MAP,
        'CAN_interface_mapping': CAN_IF, 'LIN_interface_mapping': LIN_IF,
        'AUTOSAR_IPDUM_Messages': IPDUM_MESSAGES, 'AUTOSAR_IPDUM_Binding_CAN': IPDUM_CAN,
    }
    if bad:
        tables[bad[0]] = [bad[1]]
    for name, recs in tables.items():
        write_uat(d, name, recs)
    with open(os.path.join(d, 'preferences'), 'w') as f:
        f.write('# Generated by mksignal_pdu.py\npdu_transport.udp.port: 50000\n')
    with open(os.path.join(d, 'decode_as_entries'), 'w') as f:
        f.write('decode_as_entry: udp.port,30509,(none),SOME/IP\n')

write_profile(os.path.join(outdir, 'cfg'))

# One invalid record per profile: reaches the checks in the UAT update callbacks
S = lambda *a, **k: sig('1', 1, 0, *a, **k)
BAD = [
    ('Signal_PDU_identifiers', ('1', '')),
    ('Signal_PDU_identifiers', ('1', 'a.b')),
    ('Signal_PDU_identifiers', ('1', 'a b')),
    ('Signal_PDU_identifiers', ('1', 'a\x01b')),
    ('Signal_PDU_signal_values', ('1', 0, 1, '0', '0', '')),
    ('Signal_PDU_signal_values', ('1', 0, 1, '5', '2', 'Backwards')),
    ('Signal_PDU_signal_values', ('1', 65535, 1, '0', '0', 'Far')),
]
for nm, args in (
        ('scaler nan', ('N', 'f', 'uint', 'FALSE', 8, 8, 'nan', '0')),
        ('offset nan', ('N', 'f', 'uint', 'FALSE', 8, 8, '1', 'nan')),
        ('pos big', None), ('params big', None), ('pos beyond', None),
        ('empty name', ('', 'f', 'uint', 'FALSE', 8, 8)),
        ('empty filter', ('N', '', 'uint', 'FALSE', 8, 8)),
        ('filter dot', ('N', 'a.b', 'uint', 'FALSE', 8, 8)),
        ('filter char', ('N', 'a b', 'uint', 'FALSE', 8, 8)),
        ('filter byte', ('N', 'a\x01b', 'uint', 'FALSE', 8, 8)),
        ('type', ('N', 'f', 'double', 'FALSE', 8, 8)),
        ('uint 12', ('N', 'f', 'uint', 'FALSE', 12, 12)),
        ('int 12', ('N', 'f', 'int', 'FALSE', 12, 12)),
        ('float short', ('N', 'f', 'float', 'FALSE', 32, 16)),
        ('float 16', ('N', 'f', 'float', 'FALSE', 16, 16)),
        ('float scaled', ('N', 'f', 'float', 'FALSE', 32, 32, '2', '0')),
        ('float mux', ('N', 'f', 'float', 'FALSE', 32, 32, '1', '0', 'TRUE')),
        ('string scaled', ('N', 'f', 'string', 'FALSE', 8, 8, '2', '0')),
        ('string mux', ('N', 'f', 'string', 'FALSE', 8, 8, '1', '0', 'TRUE')),
        ('string 16', ('N', 'f', 'string', 'FALSE', 16, 8)),
        ('utf 32', ('N', 'f', 'utf_string', 'FALSE', 32, 8)),
        ('stringz enc', ('N', 'f', 'stringz', 'FALSE', 8, 8)),
        ('uint_string enc', ('N', 'f', 'uint_string', 'FALSE', 8, 12)),
        ('agg string', ('N', 'f', 'string', 'FALSE', 8, 8, '1', '0', 'FALSE', '-1', 'FALSE', 'TRUE')),
        ):
    if nm == 'pos big': rec = sig('1', 65535, 65535, 'N', 'f', 'uint', 'FALSE', 8, 8)
    elif nm == 'params big': rec = sig('1', 65535, 0, 'N', 'f', 'uint', 'FALSE', 8, 8)
    elif nm == 'pos beyond': rec = sig('1', 2, 2, 'N', 'f', 'uint', 'FALSE', 8, 8)
    else: rec = sig('1', 1, 0, *args)
    BAD.append(('Signal_PDU_signal_list', rec))
BAD += [
    ('Signal_PDU_Binding_SOMEIP', ('10000', '1', '1', '0', '1')),
    ('Signal_PDU_Binding_SOMEIP', ('1', '10000', '1', '0', '1')),
    ('Signal_PDU_Binding_SOMEIP', ('1', '1', '100', '0', '1')),
    ('Signal_PDU_Binding_SOMEIP', ('1', '1', '1', '100', '1')),
    ('Signal_PDU_Binding_CAN', ('40000100', '0', '1')),
    ('Signal_PDU_Binding_CAN', ('20000100', '0', '1')),
    ('Signal_PDU_Binding_CAN', ('800', '0', '1')),
    ('Signal_PDU_Binding_FlexRay', ('1', '100', '1', '1')),
    ('Signal_PDU_Binding_FlexRay', ('1', '0', '10000', '1')),
    ('Signal_PDU_Binding_LIN', ('40', '0', '1')),
    ('Signal_PDU_Binding_LIN', ('1', '10000', '1')),
    ('Signal_PDU_Binding_DLT', ('ABCDE', '1', '1')),
    ('Signal_PDU_Binding_UDS', ('ffffffff', '22', 'FALSE', '10000', '1')),
    ('Signal_PDU_Binding_UDS', ('ffffffff', '100', 'FALSE', '1', '1')),
    ('Signal_PDU_Binding_ISOBUS', ('40000', '0', '1')),
]
for i, (name, rec) in enumerate(BAD):
    write_profile(os.path.join(outdir, 'cfg', 'profiles', 'bad%02d' % i), bad=(name, rec))
with open(os.path.join(outdir, 'cfg', 'profiles', 'bad-list.txt'), 'w') as f:
    for i, (name, rec) in enumerate(BAD):
        f.write('bad%02d %s %r\n' % (i, name, rec))
# a profile without the signal list (messages named only)
write_profile(os.path.join(outdir, 'cfg', 'profiles', 'nosignals'), signals=[])

# ------------------------------------------------------------------ frames
LINKTYPE_ETHERNET, LINKTYPE_FLEXRAY, LINKTYPE_LIN, LINKTYPE_CAN_SOCKETCAN = 1, 210, 212, 227
CAN_EFF_FLAG, CAN_RTR_FLAG = 0x80000000, 0x40000000

def can(canid, data):
    return struct.pack('>IBBBB', canid, len(data), 0, 0, 0) + data.ljust(8, b'\0')
def canfd(canid, data):
    return struct.pack('>IBBBB', canid, len(data), 0x04, 0, 0) + data
def flexray(channel_b, fid, cc, payload):
    pl = len(payload) // 2
    hdr0 = 0x20 | ((fid >> 8) & 0x07)
    rest = (pl << 17) | (0x123 << 6) | cc
    return (bytes([0x01 | (0x80 if channel_b else 0), 0x00, hdr0, fid & 0xff]) + rest.to_bytes(3, 'big') + payload + b'\x00\x00\x00')
def lin_pid(fid):
    b = [(fid >> i) & 1 for i in range(6)]
    return fid | ((b[0] ^ b[1] ^ b[2] ^ b[4]) << 6) | ((1 ^ (b[1] ^ b[3] ^ b[4] ^ b[5])) << 7)
def lin(fid, payload):
    chk = (~(sum(payload) + lin_pid(fid)) % 255) & 0xff
    hdr = bytes([1, 0, 0, 0, (len(payload) << 4) | 0x02, lin_pid(fid), chk, 0])
    return hdr + payload.ljust(8 if len(payload) > 4 else 4, b'\0')
def pdu_transport(pdu_id, payload):
    return struct.pack('>II', pdu_id, len(payload)) + payload
def someip(service, method, mtype, payload, ver=1, session=1):
    return struct.pack('>HHIHHBBBB', service, method, 8 + len(payload), 1, session, 1, ver, mtype, 0) + payload

def basic(counter, speed=0x1234, scaled=5, temp=-3, short=0xabc, nib=0x7, fbe=0x40490fdb, dle=0x3ff0000000000000):
    return (bytes([counter]) + struct.pack('>H', speed) + bytes([scaled, temp & 0xff]) +
            bytes([short >> 4, ((short & 0xf) << 4) | nib]) + struct.pack('>I', fbe) + struct.pack('<Q', dle))

frames = []
def F(ifc, d): frames.append((ifc, d))
CAN0, CAN1, FR0, LIN0, LIN1, ETH = 0, 1, 2, 3, 4, 5

# --- CAN: basic message (CAN FD, numeric types), multiplexer, strings, aggregates
F(CAN0, canfd(0x100, basic(1)))
F(CAN0, canfd(0x100, basic(2, speed=0xffff, scaled=0, temp=127, short=0xfff, nib=0xf, fbe=0xbf800000, dle=0x4000000000000000)))
F(CAN0, canfd(0x100, basic(3, temp=-128, short=0, nib=0)))
F(CAN0, can(CAN_EFF_FLAG | 0x101, bytes([0, 0x12, 0x34, 0x77, 0])))             # mux 0: Alpha
F(CAN0, can(CAN_EFF_FLAG | 0x101, bytes([1, 0xff, 0xfe, 0x77, 0])))             # mux 1: Beta (signed)
F(CAN0, can(CAN_EFF_FLAG | 0x101, bytes([2, 0x42, 0, 0x77, 0])))                # mux 2: Gamma
F(CAN0, can(CAN_EFF_FLAG | 0x101, bytes([9, 0x42, 0, 0x77, 0])))                # unknown mux value: only the common signal
STR = (b'ABCD' + b'zero\0' + bytes([3]) + b'xyz' + 'äb'.encode() + 'wx'.encode('utf-16-be') + 'uz'.encode('utf-16-be') + b'\0\0' +
       struct.pack('>H', 4) + b'abcd' + bytes([4]) + 'ab'.encode('utf-16-le'))
F(CAN0, canfd(0x102, STR))
F(CAN0, canfd(0x102, b'ABCD' + b'\0' + bytes([0]) + b'abc' + b'\0\0\0\0' + b'\0\0' + struct.pack('>H', 0) + bytes([0])))
for i, (lvl, hid, st, dl, gain) in enumerate(((10, 1, 0, 5, 1), (20, 2, 1, -3, 2), (30, 3, 2, 0, 3), (40, 4, 0x80, 8, 4), (50, 5, 7, -8, 5))):
    F(CAN0, can(0x103, bytes([lvl, hid, st, dl & 0xff, gain])))                  # aggregation, value names
# the same message on a bus that has its own mapping
F(CAN1, can(0x106, bytes([5, 0x01, 0x02])))
F(CAN0, can(0x106, bytes([6, 0x01, 0x02])))                                      # bus 0: no mapping
F(CAN1, can(CAN_EFF_FLAG | 0x107, bytes([2, 0x42, 0, 0, 0])))
F(CAN0, can(0x105, bytes([7, 0x03, 0x04, 0xaa])))                                # trailing octets after the signals
F(CAN0, can(0x108, bytes([13, 0x12, 0x34, 0, 0, 0, 0, 0])))                     # I-PduM message 1 -> PDU 0x2000 -> Signal PDU 6
F(CAN0, can(0x7ff, bytes([1, 2])))                                               # not mapped
F(CAN0, struct.pack('>IBBBB', 0x100 | CAN_RTR_FLAG, 8, 0, 0, 0) + b'\0' * 8)     # RTR: not for Signal PDU
F(CAN0, can(0x104, b'\x01\x02\x03'))                                             # message without signals: unconfigured
# --- LIN, FlexRay, PDU Transport over UDP, SOME/IP over UDP
F(LIN0, lin(0x10, bytes([8, 0x0a, 0x0b])))
F(LIN1, lin(0x11, bytes([9, 0x0c, 0x0d])))
F(LIN0, lin(0x11, bytes([9, 0x0c, 0x0d])))                                       # other bus: not mapped
F(FR0, flexray(False, 10, 0, bytes([1, 2, 3, 0])))
F(FR0, flexray(True, 20, 5, bytes([4, 5, 6, 0])))
F(FR0, flexray(False, 10, 1, bytes([4, 5, 6, 0])))                               # other cycle: not mapped
F(ETH, udp(50001, 50000, pdu_transport(0x1000, bytes([10, 0x11, 0x22])) + pdu_transport(0x1001, bytes([55, 3, 7, 0x80, 1]))))
F(ETH, udp(50001, 50000, pdu_transport(0x1002, bytes([1, 2]))))                  # not mapped
F(ETH, udp(30509, 30509, someip(0x1234, 1, 0, bytes([11, 0x44, 0x55]))))
F(ETH, udp(30509, 30509, someip(0x1234, 2, 2, bytes([12, 0x66, 0x77]))))
F(ETH, udp(30509, 30509, someip(0x1234, 3, 0, bytes([12, 0x66, 0x77]))))         # not mapped

write_pcapng(os.path.join(outdir, 'signal-pdu-coverage.pcapng'), frames,
             linktypes=(LINKTYPE_CAN_SOCKETCAN, LINKTYPE_CAN_SOCKETCAN, LINKTYPE_FLEXRAY, LINKTYPE_LIN, LINKTYPE_LIN, LINKTYPE_ETHERNET),
             names=('can0', 'can1', 'fr0', 'lin0', 'lin1', 'eth0'))

# ------------------------------------------------------------ malformed
bad = []
def B(ifc, d): bad.append((ifc, d))
B(CAN0, can(0x100, bytes([1, 2])))                                               # truncated numeric signals
B(CAN0, canfd(0x100, basic(1)[:11]))                                             # cut in the middle of the shortened value
B(CAN0, can(0x102, b'AB'))                                                       # truncated string
B(CAN0, canfd(0x102, b'ABCD' + b'no terminator'))                                # stringz without terminator
B(CAN0, canfd(0x102, b'ABCD' + b'z\0' + bytes([40]) + b'short'))                 # length prefix longer than the data
B(CAN0, can(0x103, bytes([1, 2, 3])))                                            # aggregate message cut short
B(CAN0, can(0x101 | CAN_EFF_FLAG, b'\x01'))
B(CAN0, can(0x109, b'\x05AB'))                                                 # a string after a 4 bit signal: unaligned
write_pcapng(os.path.join(outdir, 'signal-pdu-coverage-malformed.pcapng'), bad,
             linktypes=(LINKTYPE_CAN_SOCKETCAN, LINKTYPE_CAN_SOCKETCAN), names=('can0', 'can1'))
# a frame for the profile that has no signal list, and for the bad profiles
write_pcapng(os.path.join(outdir, 'signal-pdu-coverage-config.pcapng'),
             [(0, can(0x100, bytes([1, 2, 3, 4]))), (0, can(0x101 | CAN_EFF_FLAG, bytes([1, 2, 3, 4])))],
             linktypes=(LINKTYPE_CAN_SOCKETCAN,), names=('can0',))
