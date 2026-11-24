#!/usr/bin/env python3
# Generates test/captures/ieee17221_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic IEEE 1722.1 (AVDECC: ADP, AECP, ACMP) captures.
# Usage: mk17221.py <outdir> [-v]
# Writes ieee17221-coverage.pcap (Ethernet, ethertype 0x22f0 and UDP port
# 17220) and ieee17221-coverage-malformed.pcap. struct only; MACs are
# locally administered and IPs are 192.0.2.8/9. The AEM descriptor and AECP
# field offsets are the constants of packet-ieee17221.c, copied into OFF.
import struct
import sys
import os

OFF = {
    'AECP_AA_OFFSET_COUNT': 22,
    'ACMP_CONNECTION_COUNT_OFFSET': 46,
    'ACMP_CONTROLLER_GUID_OFFSET': 12,
    'ACMP_DEST_MAC_OFFSET': 40,
    'ACMP_FLAGS_OFFSET': 50,
    'ACMP_LISTENER_GUID_OFFSET': 28,
    'ACMP_LISTENER_UNIQUE_ID_OFFSET': 38,
    'ACMP_SEQUENCE_ID_OFFSET': 48,
    'ACMP_STREAM_ID_OFFSET': 4,
    'ACMP_TALKER_GUID_OFFSET': 20,
    'ACMP_TALKER_UNIQUE_ID_OFFSET': 36,
    'ACMP_VLAN_ID_OFFSET': 52,
    'ADP_ASSOC_ID_OFFSET': 56,
    'ADP_AS_GM_ID_OFFSET': 40,
    'ADP_AVAIL_INDEX_OFFSET': 36,
    'ADP_CONTROLLER_CAP_OFFSET': 32,
    'ADP_ENTITY_CAP_OFFSET': 20,
    'ADP_LISTENER_CAP_OFFSET': 30,
    'ADP_LISTENER_STREAM_SINKS_OFFSET': 28,
    'ADP_TALKER_CAP_OFFSET': 26,
    'ADP_TALKER_STREAM_SRCS_OFFSET': 24,
    'AECP_OFFSET_AS_PATH_COUNT': 26,
    'AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH': 28,
    'AECP_OFFSET_AUTH_KEY_KEY_LENGTH': 32,
    'AECP_OFFSET_AUTH_TOKEN_TOKEN_LENGTH': 24,
    'AECP_OFFSET_AVB_INFO_FLAGS': 41,
    'AECP_OFFSET_AVB_INFO_MSRP_MAPPINGS_COUNT': 42,
    'AECP_OFFSET_COUNTERS_DESCRIPTOR_TYPE': 24,
    'AECP_OFFSET_COUNTERS_VALID': 28,
    'AECP_OFFSET_DESCRIPTOR_DESCRIPTOR_TYPE': 28,
    'AECP_OFFSET_STREAM_FORMAT_STREAM_FORMAT': 28,
    'AUDIO_CLUSTER_OFFSET_OBJECT_NAME': 4,
    'AUDIO_MAP_OFFSET_MAPPINGS_OFFSET': 4,
    'AUDIO_MAP_OFFSET_NUMBER_OF_MAPPINGS': 6,
    'AUDIO_UNIT_OFFSET_OBJECT_NAME': 4,
    'AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT': 142,
    'AUDIO_UNIT_OFFSET_SAMPLE_RATES_OFFSET': 140,
    'AVB_INTERFACE_OFFSET_OBJECT_NAME': 4,
    'CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_COUNT': 74,
    'CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_OFFSET': 72,
    'CLOCK_DOMAIN_OFFSET_OBJECT_NAME': 4,
    'CLOCK_SOURCE_OFFSET_OBJECT_NAME': 4,
    'CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS': 74,
    'CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS_COUNT': 70,
    'CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS_OFFSET': 72,
    'CONTROL_OFFSET_CONTROL_VALUE_TYPE': 80,
    'CONTROL_OFFSET_NUMBER_OF_VALUES': 96,
    'CONTROL_OFFSET_VALUES_OFFSET': 94,
    'ENTITY_OFFSET_CONFIGURATIONS_COUNT': 308,
    'ENTITY_OFFSET_ENTITY_NAME': 48,
    'EXTERNAL_PORT_OFFSET_PORT_FLAGS': 6,
    'INTERNAL_PORT_OFFSET_PORT_FLAGS': 6,
    'JACK_OFFSET_JACK_FLAGS': 70,
    'JACK_OFFSET_OBJECT_NAME': 4,
    'LOCALE_OFFSET_LOCALE_IDENTIFIER': 4,
    'MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT': 4,
    'MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET': 6,
    'STREAM_OFFSET_CURRENT_FORMAT': 74,
    'STREAM_OFFSET_FORMATS_OFFSET': 82,
    'STREAM_OFFSET_NUMBER_OF_FORMATS': 84,
    'STREAM_OFFSET_OBJECT_NAME': 4,
    'STREAM_OFFSET_STREAM_FLAGS': 72,
    'STREAM_PORT_OFFSET_PORT_FLAGS': 6,
    'VIDEO_UNIT_OFFSET_OBJECT_NAME': 4,
}
def O(name):
    return OFF[name]

def pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

SRC = bytes.fromhex('020000000002')
ADP_DST = bytes.fromhex('91e0f0010000')
ACMP_DST = bytes.fromhex('91e0f0010001')
def eth(avtp, dst=ADP_DST):
    return dst + SRC + struct.pack('!H', 0x22F0) + avtp

def ipsum(h):
    s = sum(struct.unpack('!10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp(avtp, seq=None, sport=40000, dport=17220):
    payload = (struct.pack('!I', seq) if seq is not None else b'') + avtp
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 8]), bytes([192, 0, 2, 9]))
    ip = ip[:10] + struct.pack('!H', ipsum(ip)) + ip[12:]
    return bytes.fromhex('01005e000109') + SRC + b'\x08\x00' + ip + u

EID = bytes.fromhex('02000000000200ff')
EID2 = bytes.fromhex('02000000000300aa')
CTRL = bytes.fromhex('0200000000040001')

def put(buf, off, size, val):
    buf[off:off + size] = int(val).to_bytes(size, 'big')

# ------------------------------------------------------------------ ADP
def adp(msg=0, valid_time=10, ent_cap=0, talk_cap=0, lis_cap=0, ctl_cap=0, avail=1,
        srcs=2, sinks=2, size=68, entity=EID):
    b = bytearray(size)
    b[0] = 0xfa
    b[1] = msg & 0xf
    put(b, 2, 2, (valid_time << 11) | 56)
    b[4:12] = entity
    b[12:20] = bytes.fromhex('001b92fffe000001')
    put(b, O('ADP_ENTITY_CAP_OFFSET'), 4, ent_cap)
    put(b, O('ADP_TALKER_STREAM_SRCS_OFFSET'), 2, srcs)
    put(b, O('ADP_TALKER_CAP_OFFSET'), 2, talk_cap)
    put(b, O('ADP_LISTENER_STREAM_SINKS_OFFSET'), 2, sinks)
    put(b, O('ADP_LISTENER_CAP_OFFSET'), 2, lis_cap)
    put(b, O('ADP_CONTROLLER_CAP_OFFSET'), 4, ctl_cap)
    put(b, O('ADP_AVAIL_INDEX_OFFSET'), 4, avail)
    b[O('ADP_AS_GM_ID_OFFSET'):O('ADP_AS_GM_ID_OFFSET') + 8] = bytes.fromhex('001b92fffe0000aa')
    b[O('ADP_ASSOC_ID_OFFSET'):O('ADP_ASSOC_ID_OFFSET') + 8] = bytes.fromhex('0000000000001234')
    return bytes(b)

# ------------------------------------------------------------------ ACMP
def acmp(msg=0, status=0, flags=0, vlan=2, size=56, count=1):
    b = bytearray(size)
    b[0] = 0xfc
    b[1] = msg & 0xf
    put(b, 2, 2, (status << 11) | 44)
    b[O('ACMP_STREAM_ID_OFFSET'):O('ACMP_STREAM_ID_OFFSET') + 8] = bytes.fromhex('0200000000020001')
    b[O('ACMP_CONTROLLER_GUID_OFFSET'):O('ACMP_CONTROLLER_GUID_OFFSET') + 8] = CTRL
    b[O('ACMP_TALKER_GUID_OFFSET'):O('ACMP_TALKER_GUID_OFFSET') + 8] = EID
    b[O('ACMP_LISTENER_GUID_OFFSET'):O('ACMP_LISTENER_GUID_OFFSET') + 8] = EID2
    put(b, O('ACMP_TALKER_UNIQUE_ID_OFFSET'), 2, 1)
    put(b, O('ACMP_LISTENER_UNIQUE_ID_OFFSET'), 2, 2)
    b[O('ACMP_DEST_MAC_OFFSET'):O('ACMP_DEST_MAC_OFFSET') + 6] = bytes.fromhex('91e0f000fe01')
    put(b, O('ACMP_CONNECTION_COUNT_OFFSET'), 2, count)
    put(b, O('ACMP_SEQUENCE_ID_OFFSET'), 2, 77)
    put(b, O('ACMP_FLAGS_OFFSET'), 2, flags)
    put(b, O('ACMP_VLAN_ID_OFFSET'), 2, vlan)
    return bytes(b)

# ------------------------------------------------------------------ AECP
def aecp_hdr(mtype, status, length, cmd=None, u=0, seq=1, size=24):
    b = bytearray(size)
    b[0] = 0xfb
    b[1] = mtype & 0xf
    put(b, 2, 2, (status << 11) | length)
    b[4:12] = EID
    b[12:20] = CTRL
    put(b, 20, 2, seq)
    if cmd is not None:
        put(b, 22, 2, (u << 15) | cmd)
    return b

def aem(cmd, resp=False, status=0, size=200, u=0, sets=(), seq=1):
    '''An AEM command/response: header, then size-24 bytes of body; sets is a
    list of (offset, size, value) for the body fields.'''
    b = aecp_hdr(1 if resp else 0, status, size - 12, cmd, u, seq, size)
    for off, sz, val in sets:
        put(b, off, sz, val)
    return bytes(b)

# ------------------------------------------------------------------ descriptors
ARR = 320   # array base inside a descriptor (past every fixed part)
def descriptor(dtype, idx=0, size=700, sets=(), names=()):
    d = bytearray(size)
    put(d, 0, 2, dtype)
    put(d, 2, 2, idx)
    for off, sz, val in sets:
        put(d, off, sz, val)
    for off, txt in names:
        d[off:off + len(txt)] = txt.encode()
    return bytes(d)

def stream_format(sf=0, subtype=0x20, fmt=0x10, fdf_evt=0, dbs=2, version=0, iidc=False):
    '''8 byte stream format: version(1 bit) subtype(7) | sf(1)..., fields per the
    offsets of the dissector'''
    b = bytearray(8)
    b[0] = (version << 7) | subtype
    if subtype == 0x00:                     # IEC 61883/IIDC
        b[1] = (sf << 7) | (fmt & 0x7f)
        if sf == 0:
            b[2] = 1; b[3] = 2; b[4] = 3        # IIDC format / mode / rate
        else:
            b[1] = 0x80 | fmt
            if fmt == 0x20:                     # 61883-6
                b[2] = fdf_evt & 0x7
                b[3] = 4
                b[4] = dbs
                b[5] = 0xc0
                b[6] = 0x01; b[7] = 0x02
            elif fmt == 0x01:                   # 61883-8
                b[2] = 1; b[3] = 2; b[4] = 3
    return bytes(b)

def build(outdir, verbose=False):
    fr = []; notes = []
    def add(label, f):
        fr.append(f); notes.append(label)

    # =================================================================== ADP
    add('ADP ENTITY_AVAILABLE, all capabilities',
        eth(adp(0, ent_cap=0x7ff, talk_cap=0xe201, lis_cap=0xe201, ctl_cap=3)))
    add('ADP ENTITY_DEPARTING', eth(adp(1)))
    add('ADP ENTITY_DISCOVER (entity id 0)', eth(adp(2, entity=bytes(8), size=68)))
    add('ADP available, no capabilities', eth(adp(0, ent_cap=0, talk_cap=0, lis_cap=0, ctl_cap=0, valid_time=31)))
    add('ADP message type 3 (unknown)', eth(adp(3)))
    add('ADP over UDP', udp(adp(0, ent_cap=0x08), seq=1))

    # =================================================================== ACMP
    for m in range(0, 14):
        add('ACMP message type %d' % m, eth(acmp(m), dst=ACMP_DST))
    for st in (1, 5, 12, 15, 31):
        add('ACMP status %d' % st, eth(acmp(1, status=st), dst=ACMP_DST))
    add('ACMP flags all', eth(acmp(0, flags=0x7f), dst=ACMP_DST))
    add('ACMP over UDP', udp(acmp(6), seq=2))

    # =================================================================== AEM commands / responses
    # every command type as a command and as a response (status 0). The
    # body is 176 zero bytes plus the descriptor type/index where the
    # command has them.
    cmds = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x39, 0x3b, 0x3c, 0x3d, 0x3e, 0x40, 0x43, 0x44,
            0x45, 0x46, 0x49, 0x4a, 0x7fff, 0x4b, 0x47, 0x48]
    for c in cmds:
        sets = [(24, 2, 5), (26, 2, 1)]       # descriptor type STREAM_INPUT, index 1
        # READ/WRITE_DESCRIPTOR carry a descriptor: they get real ones below
        if c != 0x05:
            add('AEM command 0x%04x' % c, eth(aem(c, sets=sets), dst=bytes.fromhex('020000000001')))
        if c not in (0x04, 0x05):
            add('AEM response 0x%04x' % c, eth(aem(c, resp=True, sets=sets), dst=bytes.fromhex('020000000001')))
    # unsolicited response (u flag)
    add('AEM response with u flag', eth(aem(0x07, resp=True, u=1, sets=[(26, 2, 3)])))
    # non-zero status: READ_DESCRIPTOR response with a status shows type/index only
    add('AEM READ_DESCRIPTOR response, status NO_SUCH_DESCRIPTOR',
        eth(aem(0x04, resp=True, status=2, size=40, sets=[(O('AECP_OFFSET_DESCRIPTOR_DESCRIPTOR_TYPE'), 2, 5)])))
    # AUTH commands whose key/token lengths matter
    add('AUTH_ADD_KEY command with a key',
        eth(aem(0x37, sets=[(O('AECP_OFFSET_AUTH_KEY_KEY_LENGTH'), 2, 16)], size=80)))
    add('AUTH_GET_KEY response with a key',
        eth(aem(0x3a, resp=True, sets=[(O('AECP_OFFSET_AUTH_KEY_KEY_LENGTH'), 2, 16)], size=80)))
    add('AUTH_GET_KEY command (no key)', eth(aem(0x3a, size=60)))
    add('AUTH_DELETE_KEY command', eth(aem(0x38, size=60)))
    add('AUTH_ADD_TOKEN command, 8 bytes',
        eth(aem(0x3f, sets=[(O('AECP_OFFSET_AUTH_TOKEN_TOKEN_LENGTH'), 4, 8)], size=48)))
    add('AUTH_ADD_TOKEN response', eth(aem(0x3f, resp=True, size=48)))
    add('AUTH_DELETE_TOKEN', eth(aem(0x40, size=40)))
    add('AUTHENTICATE with token',
        eth(aem(0x41, sets=[(O('AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH'), 2, 8)], size=64)))
    add('DEAUTHENTICATE with token',
        eth(aem(0x42, sets=[(O('AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH'), 2, 4)], size=64)))
    # GET_AVB_INFO response with MSRP mappings; GET_AS_PATH with sequence
    add('GET_AVB_INFO response, 3 MSRP mappings',
        eth(aem(0x27, resp=True, size=70,
                sets=[(O('AECP_OFFSET_AVB_INFO_MSRP_MAPPINGS_COUNT'), 2, 3),
                      (O('AECP_OFFSET_AVB_INFO_FLAGS'), 1, 7)])))
    add('GET_AS_PATH response, 2 clock identities',
        eth(aem(0x28, resp=True, size=48, sets=[(O('AECP_OFFSET_AS_PATH_COUNT'), 2, 2)])))
    # GET_COUNTERS response for the descriptor types with counters
    for dt in (0x00, 0x09, 0x24, 0x05, 0x06):
        add('GET_COUNTERS response, descriptor type %d' % dt,
            eth(aem(0x29, resp=True, size=164,
                    sets=[(O('AECP_OFFSET_COUNTERS_DESCRIPTOR_TYPE'), 2, dt),
                          (O('AECP_OFFSET_COUNTERS_VALID'), 4, 0xffffffff)])))
    add('GET_COUNTERS command', eth(aem(0x29, size=60)))
    # stream formats in GET/SET_STREAM_FORMAT responses
    for label, sf in (('61883-6 AM824', stream_format(1, 0x00, 0x20, 0, 2)),
                      ('61883-6 other FDF event', stream_format(1, 0x00, 0x20, 1, 2)),
                      ('61883-8', stream_format(1, 0x00, 0x01)),
                      ('61883 other fmt', stream_format(1, 0x00, 0x05)),
                      ('IIDC', stream_format(0, 0x00)),
                      ('MMA', stream_format(0, 0x01)),
                      ('AVTP audio', stream_format(0, 0x02)),
                      ('AVTP video', stream_format(0, 0x03)),
                      ('experimental', stream_format(0, 0x7f)),
                      ('unknown subtype', stream_format(0, 0x30)),
                      ('version 1', stream_format(0, 0x00, version=1))):
        add('GET_STREAM_FORMAT response: ' + label,
            eth(aem(0x09, resp=True, size=40, sets=[(O('AECP_OFFSET_STREAM_FORMAT_STREAM_FORMAT'), 8, int.from_bytes(sf, 'big'))])))
    add('SET_STREAM_FORMAT command', eth(aem(0x08, size=40)))
    add('GET_STREAM_FORMAT command (no format)', eth(aem(0x09, size=40)))

    # =================================================================== READ_DESCRIPTOR responses
    def read_desc(d, status=0):
        body = bytearray(28 - 24) + bytearray(d)   # configuration index (2) + reserved (2) + descriptor
        h = aecp_hdr(1, status, 12 + len(body) + 0, 0x04, 0, 9, 24)
        return bytes(h) + bytes(body)
    D_ = descriptor
    ent_sets = [(O('ENTITY_OFFSET_CONFIGURATIONS_COUNT'), 2, 1)]
    descs = []
    descs.append(('entity', D_(0x00, 0, 320, ent_sets, [(O('ENTITY_OFFSET_ENTITY_NAME'), 'Synthetic entity')])))
    descs.append(('configuration', D_(0x01, 0, 400, [(O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS_COUNT'), 2, 6),
                                                    (O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS_OFFSET'), 2, O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS')),
                                                    (O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS'), 2, 2),
                                                    (O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS') + 2, 2, 1),
                                                    (O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS') + 4, 2, 5),
                                                    (O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS') + 6, 2, 2)])))
    # sample rates: pull 0..4 and 5 (unknown multiplier), base frequency 48000
    sr = [(0 << 29) | 48000, (1 << 29) | 48000, (2 << 29) | 44100, (3 << 29) | 48000,
          (4 << 29) | 48000, (5 << 29) | 96000]
    sets = [(O('AUDIO_UNIT_OFFSET_SAMPLE_RATES_OFFSET'), 2, ARR),
            (O('AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT'), 2, len(sr))]
    sets += [(ARR + 4 * i, 4, v) for i, v in enumerate(sr)]
    descs.append(('audio unit', D_(0x02, 0, 400, sets, [(O('AUDIO_UNIT_OFFSET_OBJECT_NAME'), 'Audio unit')])))
    descs.append(('video unit', D_(0x03, 0, 400, [], [(O('VIDEO_UNIT_OFFSET_OBJECT_NAME'), 'Video unit')])))
    descs.append(('sensor unit', D_(0x04, 0, 400)))
    stream_sets = [(O('STREAM_OFFSET_FORMATS_OFFSET'), 2, ARR), (O('STREAM_OFFSET_NUMBER_OF_FORMATS'), 2, 3),
                   (O('STREAM_OFFSET_STREAM_FLAGS'), 2, 0x0007),
                   (O('STREAM_OFFSET_CURRENT_FORMAT'), 8, int.from_bytes(stream_format(1, 0x00, 0x20, 0, 2), 'big')),
                   (ARR, 8, int.from_bytes(stream_format(1, 0x00, 0x20, 0, 2), 'big')),
                   (ARR + 8, 8, int.from_bytes(stream_format(0, 0x00), 'big')),
                   (ARR + 16, 8, int.from_bytes(stream_format(1, 0x00, 0x01), 'big'))]
    descs.append(('stream input', D_(0x05, 0, 400, stream_sets, [(O('STREAM_OFFSET_OBJECT_NAME'), 'Stream in')])))
    descs.append(('stream output', D_(0x06, 0, 400, stream_sets, [(O('STREAM_OFFSET_OBJECT_NAME'), 'Stream out')])))
    descs.append(('jack input', D_(0x07, 0, 200, [(O('JACK_OFFSET_JACK_FLAGS'), 2, 3)], [(O('JACK_OFFSET_OBJECT_NAME'), 'Jack in')])))
    descs.append(('jack output', D_(0x08, 0, 200, [(O('JACK_OFFSET_JACK_FLAGS'), 2, 1)])))
    descs.append(('avb interface', D_(0x09, 0, 200, [], [(O('AVB_INTERFACE_OFFSET_OBJECT_NAME'), 'eth0')])))
    descs.append(('clock source', D_(0x0a, 0, 200, [], [(O('CLOCK_SOURCE_OFFSET_OBJECT_NAME'), 'Clock')])))
    descs.append(('memory object', D_(0x0b, 0, 200)))
    descs.append(('locale', D_(0x0c, 0, 200, [], [(O('LOCALE_OFFSET_LOCALE_IDENTIFIER'), 'en-US')])))
    descs.append(('strings', D_(0x0d, 0, 470, [], [(4, 'string0'), (68, 'string1')])))
    descs.append(('stream port input', D_(0x0e, 0, 200, [(O('STREAM_PORT_OFFSET_PORT_FLAGS'), 2, 7)])))
    descs.append(('stream port output', D_(0x0f, 0, 200)))
    descs.append(('external port input', D_(0x10, 0, 200, [(O('EXTERNAL_PORT_OFFSET_PORT_FLAGS'), 2, 7)])))
    descs.append(('external port output', D_(0x11, 0, 200)))
    descs.append(('internal port input', D_(0x12, 0, 200, [(O('INTERNAL_PORT_OFFSET_PORT_FLAGS'), 2, 7)])))
    descs.append(('internal port output', D_(0x13, 0, 200)))
    descs.append(('audio cluster', D_(0x14, 0, 200, [], [(O('AUDIO_CLUSTER_OFFSET_OBJECT_NAME'), 'Cluster')])))
    descs.append(('audio map', D_(0x17, 0, 400, [(O('AUDIO_MAP_OFFSET_MAPPINGS_OFFSET'), 2, ARR),
                                                (O('AUDIO_MAP_OFFSET_NUMBER_OF_MAPPINGS'), 2, 3)])))
    descs.append(('clock domain', D_(0x24, 0, 400, [(O('CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_OFFSET'), 2, ARR),
                                                   (O('CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_COUNT'), 2, 3),
                                                   (ARR, 2, 0), (ARR + 2, 2, 1), (ARR + 4, 2, 2)],
                               [(O('CLOCK_DOMAIN_OFFSET_OBJECT_NAME'), 'Domain')])))
    descs.append(('matrix signal', D_(0x1e, 0, 400, [(O('MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT'), 2, 3),
                                                    (O('MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET'), 2, ARR)])))
    descs.append(('signal selector', D_(0x1b, 0, 200)))
    descs.append(('mixer', D_(0x1c, 0, 200)))
    descs.append(('matrix', D_(0x1d, 0, 200)))
    # controls: every value type group
    for vt, label in ((0x00, 'linear int8'), (0x01, 'linear uint8'), (0x02, 'linear int16'),
                      (0x03, 'linear uint16'), (0x04, 'linear int32'), (0x05, 'linear uint32'),
                      (0x06, 'linear int64'), (0x07, 'linear uint64'), (0x08, 'linear float'),
                      (0x09, 'linear double'), (0x0a, 'selector int8'), (0x0b, 'selector uint8'),
                      (0x0c, 'selector int16'), (0x0d, 'selector uint16'), (0x0e, 'selector int32'),
                      (0x0f, 'selector uint32'), (0x10, 'selector int64'), (0x11, 'selector uint64'),
                      (0x12, 'selector float'), (0x13, 'selector double'), (0x14, 'string'),
                      (0x15, 'bode plot'), (0x16, 'array uint8'), (0x1f, 'utf8'), (0x3ffe, 'vendor'),
                      (0xfffe, 'vendor (0xfffe)'), (0x0020, 'bode (0x20)')):
        csets = [(O('CONTROL_OFFSET_CONTROL_VALUE_TYPE'), 2, vt),
                 (O('CONTROL_OFFSET_VALUES_OFFSET'), 2, ARR),
                 (O('CONTROL_OFFSET_NUMBER_OF_VALUES'), 2, 2 if vt != 0x15 else 1)]
        if vt == 0xfffe:
            csets.append((ARR + 8, 4, 4))
        descs.append(('control ' + label, D_(0x1a, 0, 700, csets, [(ARR, 'abc')] if vt == 0x14 else [])))
    descs.append(('control block', D_(0x25, 0, 100)))
    descs.append(('unknown descriptor type 0x0100', D_(0x0100, 0, 100)))
    descs.append(('signal splitter', D_(0x1f, 0, 100)))
    for label, d in descs:
        add('READ_DESCRIPTOR response: ' + label, eth(read_desc(d)))
    add('WRITE_DESCRIPTOR command (stream input)', eth(bytes(aecp_hdr(0, 0, 12 + 4 + len(descs[5][1]), 0x05, 0, 4, 24)) + bytes(4) + descs[5][1]))
    add('WRITE_DESCRIPTOR response (audio unit)', eth(bytes(aecp_hdr(1, 0, 12 + 4 + len(descs[2][1]), 0x05, 0, 4, 24)) + bytes(4) + descs[2][1]))
    add('READ_DESCRIPTOR command', eth(aem(0x04, size=32, sets=[(O('AECP_OFFSET_DESCRIPTOR_DESCRIPTOR_TYPE'), 2, 5)])))
    add('READ_DESCRIPTOR response over UDP', udp(read_desc(descs[0][1]), seq=3))

    # =================================================================== Address access, vendor unique
    aa = bytearray(aecp_hdr(2, 0, 38, None, 0, 5, 24))
    put(aa, O('AECP_AA_OFFSET_COUNT'), 2, 1)      # one TLV: mode 1, length 8
    aa += struct.pack('!H', (1 << 12) | 8) + bytes.fromhex('0000000012345678') + bytes(8)
    add('AECP address access command', eth(bytes(aa)))
    aa[1] = 3
    add('AECP address access response', eth(bytes(aa)))
    vu = bytearray(aecp_hdr(6, 0, 20, None, 0, 6, 22)) + bytes.fromhex('001bc50bc2aa') + bytes(12)
    add('AECP vendor unique command', eth(bytes(vu)))
    vu[1] = 7
    add('AECP vendor unique response', eth(bytes(vu)))
    for mt in (4, 5, 14, 15):
        add('AECP message type %d (AVC / extended, nothing dissected)' % mt,
            eth(bytes(aecp_hdr(mt, 0, 12, None, 0, 7, 40))))
    add('AEM over UDP', udp(aem(0x07, resp=True, sets=[]), seq=4))
    pcap(os.path.join(outdir, 'ieee17221-coverage.pcap'), fr)

    # =================================================================== malformed
    mal = []
    mal.append(eth(adp(0)[:30]))                                       # truncated ADP
    mal.append(eth(acmp(0)[:30], dst=ACMP_DST))                        # truncated ACMP
    mal.append(eth(aem(0x04, resp=True, size=26)))                     # truncated read descriptor
    mal.append(eth(aem(0x08, resp=True, size=30)))                     # stream format cropped
    mal.append(eth(aem(0x29, resp=True, size=100, sets=[(O('AECP_OFFSET_COUNTERS_DESCRIPTOR_TYPE'), 2, 5)])))  # counters cropped
    mal.append(eth(bytes([0xfb, 0])))                                  # AECP header only
    # audio unit with a sample rate array beyond the descriptor
    bad = D_(0x02, 0, 160, [(O('AUDIO_UNIT_OFFSET_SAMPLE_RATES_OFFSET'), 2, 150),
                          (O('AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT'), 2, 200)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x05, 0, 120, [(O('STREAM_OFFSET_FORMATS_OFFSET'), 2, 100), (O('STREAM_OFFSET_NUMBER_OF_FORMATS'), 2, 50)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x1a, 0, 400, [(O('CONTROL_OFFSET_CONTROL_VALUE_TYPE'), 2, 0x08), (O('CONTROL_OFFSET_VALUES_OFFSET'), 2, 390),
                          (O('CONTROL_OFFSET_NUMBER_OF_VALUES'), 2, 60000)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x1a, 0, 400, [(O('CONTROL_OFFSET_CONTROL_VALUE_TYPE'), 2, 0x15), (O('CONTROL_OFFSET_VALUES_OFFSET'), 2, 320),
                          (O('CONTROL_OFFSET_NUMBER_OF_VALUES'), 2, 65535)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x1a, 0, 400, [(O('CONTROL_OFFSET_CONTROL_VALUE_TYPE'), 2, 0xfffe), (O('CONTROL_OFFSET_VALUES_OFFSET'), 2, 320),
                          (320 + 8, 4, 0xffffff00)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x01, 0, 100, [(O('CONFIGURATION_OFFSET_DESCRIPTOR_COUNTS_COUNT'), 2, 60000)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x17, 0, 100, [(O('AUDIO_MAP_OFFSET_MAPPINGS_OFFSET'), 2, 90), (O('AUDIO_MAP_OFFSET_NUMBER_OF_MAPPINGS'), 2, 40000)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x24, 0, 100, [(O('CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_COUNT'), 2, 30000), (O('CLOCK_DOMAIN_OFFSET_CLOCK_SOURCES_OFFSET'), 2, 90)])
    mal.append(eth(read_desc(bad)))
    bad = D_(0x1e, 0, 100, [(O('MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT'), 2, 50000), (O('MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET'), 2, 90)])
    mal.append(eth(read_desc(bad)))
    mal.append(eth(aem(0x3f, sets=[(O('AECP_OFFSET_AUTH_TOKEN_TOKEN_LENGTH'), 4, 0xffff0000)], size=48)))   # huge token length
    mal.append(eth(aem(0x37, sets=[(O('AECP_OFFSET_AUTH_KEY_KEY_LENGTH'), 2, 2000)], size=80)))             # key beyond packet
    mal.append(eth(aem(0x41, sets=[(O('AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH'), 2, 2000)], size=64)))      # token beyond packet
    mal.append(eth(aem(0x27, resp=True, size=50, sets=[(O('AECP_OFFSET_AVB_INFO_MSRP_MAPPINGS_COUNT'), 2, 60000)])))
    mal.append(eth(aem(0x28, resp=True, size=40, sets=[(O('AECP_OFFSET_AS_PATH_COUNT'), 2, 60000)])))
    mal.append(eth(bytes(aecp_hdr(6, 0, 20, None, 0, 6, 24))))                                              # vendor unique cropped
    mal.append(eth(bytes(aecp_hdr(2, 0, 12, None, 0, 6, 28))))                                              # address access cropped
    mal.append(eth(bytes([0xf9, 0, 0, 0] + [0] * 20)))                                                       # subtype 0xf9, not 1722.1
    mal.append(udp(adp(0)[:20], seq=5))
    pcap(os.path.join(outdir, 'ieee17221-coverage-malformed.pcap'), mal)
    if verbose:
        for i, n in enumerate(notes, 1):
            print(i, n)
        print('main frames:', len(fr), 'malformed frames:', len(mal))

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build(out, '-v' in sys.argv)
