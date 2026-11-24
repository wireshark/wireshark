# Helper module for the rtps capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the RTPS reproducers (group s1, batch 34).
# Synthetic addresses only.
import struct

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport=7410, dport=7411, src='192.0.2.1', dst='192.0.2.2'):
    ip_s = bytes(int(x) for x in src.split('.'))
    ip_d = bytes(int(x) for x in dst.split('.'))
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    tot = 20 + len(udp)
    assert tot <= 65535, tot
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, 1, 0, 64, 17, 0, ip_s, ip_d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + udp

GUID_PREFIX = bytes.fromhex('0a0b0c0d0e0f101112131415')

def rtps_header(prefix=GUID_PREFIX):
    return b'RTPS' + b'\x02\x03' + b'\x01\x01' + prefix

def data_submsg(writer_id, payload, reader_id=0, flags=0x05):
    """DATA (0x15), little endian, D flag, no inline QoS."""
    body = struct.pack('<HH', 0, 16) + struct.pack('>II', reader_id, writer_id)
    body += struct.pack('<iI', 0, 1) + payload
    assert len(body) <= 0xffff
    return struct.pack('<BBH', 0x15, flags, len(body)) + body

def align(b, n=4):
    return b + b'\0' * ((-len(b)) % n)

def phdr(pid, ln):
    return struct.pack('<HH', pid, ln)

def cdr_string(s):
    raw = s.encode() + b'\0'
    return align(struct.pack('<I', len(raw)) + raw)

def type_id_long(tid):
    # disc > 13, pad to 8 (relative to the start of the containing value), u64
    return struct.pack('<H', 0x0e) + b'\0' * 6 + struct.pack('<Q', tid)

def library_type(tid, name, flags=0x0001):
    # parameter header + [flags u16][type id at +2 (disc, pad, u64)][name]
    val = struct.pack('<H', flags) + type_id_long(tid)[:0]
    val = struct.pack('<HH', flags, 0x0e) + b'\0' * 4 + struct.pack('<Q', tid) + cdr_string(name)
    out = phdr(0, len(val)) + val
    out += phdr(0, 4) + struct.pack('<I', 0)          # annotation seq, 0 entries
    return out

def member(member_id, tid, name='m', flags=0):
    val = struct.pack('<HH', flags, 0) + struct.pack('<I', member_id)
    val += struct.pack('<H', 0x0e) + b'\0' * 6 + struct.pack('<Q', tid)
    val += cdr_string(name)
    out = phdr(0, len(val)) + val
    out += phdr(0, 4) + struct.pack('<I', 0)          # annotations
    return out

def struct_element(tid, member_tids, name='S', base=0):
    body = library_type(tid, name)
    body += phdr(0, 4) + struct.pack('<HH', 0, base)  # base type (primitive id)
    mem = b''.join(member(i + 1, t) for i, t in enumerate(member_tids))
    body += phdr(0, 4 + len(mem)) + struct.pack('<I', len(member_tids)) + mem
    body = align(body)
    el = phdr(0, 4) + struct.pack('<I', 22)           # kind STRUCTURE
    el += phdr(1, len(body)) + body
    el += struct.pack('<HH', 0x3f02, 0)               # PID_LIST_END
    return el

def element(kind, body):
    body = align(body)
    el = phdr(0, 4) + struct.pack('<I', kind)
    el += phdr(1, len(body)) + body
    el += struct.pack('<HH', 0x3f02, 0)
    return el

def type_object(elements, top_tid):
    lib = struct.pack('<I', len(elements)) + b''.join(elements)
    lib = align(lib)
    to = phdr(0, len(lib)) + lib
    tid = type_id_long(top_tid)
    to += phdr(1, len(tid)) + tid
    to += struct.pack('<HH', 0x3f02, 0)
    return to

def discovery_publication(typeobj):
    """DATA from the builtin publications writer, PL_CDR_LE with PID_TYPE_OBJECT."""
    assert len(typeobj) <= 0xffff
    pl = struct.pack('>HH', 0x0003, 0)
    pl += struct.pack('<HH', 0x0072, len(align(typeobj))) + align(typeobj)
    pl += struct.pack('<HH', 0x0001, 0)               # PID_SENTINEL
    return rtps_header() + data_submsg(0x000003c2, pl)

INSTANCE_STATE_DATA_RESPONSE_TID = 0x9d6d4c879b0e6aa9

def meta_group_data(payload):
    """DATA from a writer whose kind is ENTITYID_NORMAL_META_GROUP_WRITER (0x8c),
    which the dissector maps to the builtin InstanceStateDataResponse type."""
    pl = struct.pack('>HH', 0x0001, 0) + payload      # CDR_LE
    return rtps_header() + data_submsg(0x0000018c, pl)

def export_pdu_pcap(path, records):
    """records: list of (dissector_name, payload); linktype 252 (Exported PDU)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, (name, payload) in enumerate(records):
            n = name.encode()
            tlv = struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0)
            fr = tlv + payload
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)
