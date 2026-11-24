#!/usr/bin/env python3
# Generates test/captures/sysdig_event_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Sysdig event coverage captures.  Usage: mksysdig_event.py <outdir> [-v]
# The pcapng files hold only a section header and Sysdig event blocks (0x204, 0x208, 0x216, 0x217, 0x221,
# 0x222). EVENTS maps an event type to the parameter types of its tree entry in packet-sysdig-event.c
# (S string, B bytes, 1/2/4/8 integers of that many octets, N none); it was extracted from the dissector
# source and is only used to make well-formed parameters.
import struct
import sys
import os

EVENTS = {
    0: '22',
    1: '2',
    2: 'S44',
    3: '8S4448',
    4: '8',
    5: '8',
    6: '84',
    7: '8B',
    10: '4',
    11: '8',
    13: '8SS888S8',
    15: '8SS888S8444',
    18: 'B44',
    21: '8B',
    22: '8B',
    23: '8B8',
    24: '84',
    27: '8B1',
    30: '84B',
    35: '8BB',
    36: '8B',
    43: '88888',
    45: '88BBB4',
    53: '84BBB',
    56: '4',
    58: 'S4',
    59: '8S448',
    61: '8888',
    62: '84',
    64: '8B8',
    67: '8S',
    78: '8',
    80: 'B8',
    81: '8B',
    86: '88B',
    90: '88',
    98: 'S4',
    100: 'S',
    102: '8S44',
    104: 'SS',
    106: '8S8S',
    110: '8S',
    112: '848',
    117: '84B',
    120: '88',
    126: '841',
    128: '8B',
    130: '8B',
    132: '88B',
    134: 'B',
    136: '11',
    138: '1',
    140: 'B',
    141: '888',
    143: '888B',
    144: '8B',
    145: '888888B',
    146: '8',
    148: '4',
    150: '8B',
    151: '88B',
    152: '888444',
    155: '8SS888S888444',
    157: '8SS888S888444444',
    158: '8',
    159: '8444',
    160: '884488',
    161: '8444',
    162: '884488',
    164: '88',
    166: '8884',
    168: 'B8',
    169: '8BB',
    170: '888',
    173: '8SS888S888444S',
    175: '8SS',
    177: '88S8S',
    179: '8SS',
    181: '8S8S',
    186: '88B18',
    188: '8888',
    189: '88',
    190: '2141',
    191: '8SS88888BBBB11',
    192: '444',
    194: '444',
    196: '48',
    198: '4',
    200: '4',
    205: '4',
    209: '4',
    211: '8444',
    213: '8444',
    215: '8SS888S888444SS',
    217: '8SS888S888444S444',
    223: '8SS888S888444SB444888',
    228: 'S4SS',
    231: '8SS888S888444SBS',
    232: '88B',
    234: '88',
    240: '84',
    242: '84',
    244: '44',
    247: '8B144',
    250: '4',
    251: '84222222',
    252: '4424',
    254: 'BBB',
    256: '4',
    257: '8SSS',
    259: '8S',
    260: 'S',
    262: '444',
    264: '4',
    268: '8BS',
    276: '4',
    280: 'SS',
    283: '8SS888S888444SBS4',
    286: 'SSSS',
    288: 'S',
    290: '884',
    293: '8SS888S888444SBS48448888BB4S',
    294: '88',
    296: '8',
    297: 'B',
    298: '88',
    303: '88S4',
    305: '88S4',
    307: '88S4448',
    311: '88S8S4',
    313: '88S4',
    315: '8S4',
    317: '884',
    319: '88S8S4',
    321: '84',
    322: '4B',
    326: '8S444',
    327: '88S44448',
    328: '884',
    330: '8S4',
    332: '888',
    333: '888',
    337: '884S48',
    339: '84444444',
    341: '88444B',
    343: '88B84',
    345: '888',
    353: '8888',
    354: '44SSSS',
    358: '4SS',
    363: '888',
    365: '8884',
    367: '88',
    371: '8884',
    373: '88BSBS4',
    374: '4',
    379: '8S44',
    383: '8844',
    385: '88S444',
    393: '88884',
    395: '82',
    396: '8',
    398: '84',
    401: '8BS8',
    402: '4SB',
    405: '8S4',
    407: '8884',
    409: '884',
    411: '8B8S',
    413: '88S4',
    415: '8S44',
    417: '88S44',
    419: '88S4',
    421: '88B',
    425: '8S4',
    427: '844',
    429: '844',
}


BT_EVENT, BT_EVF, BT_EVENT_V2, BT_EVF_V2, BT_V2_LARGE, BT_EVF_V2_LARGE = 0x204, 0x208, 0x216, 0x217, 0x221, 0x222
SYSCALL_NAMES = None

def block(btype, body, e='<'):
    body += b'\0' * ((-len(body)) % 4)
    tl = 12 + len(body)
    return struct.pack(e + 'II', btype, tl) + body + struct.pack(e + 'I', tl)

def shb(e='<'):
    return block(0x0A0D0D0A, struct.pack(e + 'IHHq', 0x1A2B3C4D, 1, 0, -1), e)

def param_bytes(code, n, i, e='<'):
    """a deterministic value for a parameter of type code (n: event number, i: parameter index)"""
    if code == 'S':
        return ('/tmp/f%d_%d\x00' % (n, i)).encode()
    if code == 'B':
        return bytes(((n * 7 + i * 3 + k) & 0xff) for k in range(5 + (n + i) % 4))
    if code == 'N':
        return b''
    size = int(code)
    mask = (1 << (8 * size)) - 1
    return struct.pack(e + {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size], ((n * 31 + i * 17 + 3) * 0x01010101) & mask)

def event(btype, etype, params, nparams=None, tid=1000, ts=1700000000000000000, cpu=0, flags=0, e='<', lens=None):
    """params: list of byte strings"""
    large = btype in (BT_V2_LARGE, BT_EVF_V2_LARGE)
    v2 = btype in (BT_EVENT_V2, BT_EVF_V2, BT_V2_LARGE, BT_EVF_V2_LARGE)
    evf = btype in (BT_EVF, BT_EVF_V2, BT_EVF_V2_LARGE)
    lsz = 4 if large else 2
    if lens is None:
        lens = [len(p) for p in params]
    data = b''.join(struct.pack(e + ('I' if large else 'H'), l) for l in lens) + b''.join(params)
    hdr_len = 22 + (4 if v2 else 0)
    pre = struct.pack(e + 'H', cpu) + (struct.pack(e + 'I', flags) if evf else b'')
    hdr = struct.pack(e + 'QQIH', ts, tid, hdr_len + len(data), etype)
    if v2:
        hdr += struct.pack(e + 'I', len(params) if nparams is None else nparams)
    return block(btype, pre + hdr + data, e)

def std_event(btype, etype, e='<', tid=1000, ts=1700000000000000000):
    codes = EVENTS[etype]
    params = [param_bytes(c, etype, i, e) for i, c in enumerate(codes)]
    if etype == 0:     # generic: the syscall id and the native id
        params = [struct.pack(e + 'H', 2 + (ts % 7)), struct.pack(e + 'H', 60)]
    return event(btype, etype, params, tid=tid, ts=ts, e=e, cpu=etype % 4, flags=etype & 0xff)

out = []
marks = []
def mark(name):
    marks.append((len(out) - 1, name))   # events so far (excluding the section header)

out.append(shb())
mark('little endian section')
ts = 1700000000000000000
n = 0
def put(blk):
    global n
    out.append(blk)
    n += 1

for btype in (BT_EVENT_V2, BT_V2_LARGE):
    mark('every event type with a tree entry as block 0x%x' % btype)
    for etype in sorted(EVENTS):
        put(std_event(btype, etype, ts=ts + etype, tid=2000 + etype))
mark('flags blocks (0x217, 0x222) for some event types')
for btype in (BT_EVF_V2, BT_EVF_V2_LARGE):
    for etype in sorted(EVENTS)[::7]:
        put(std_event(btype, etype, ts=ts + 5000 + etype))
mark('version 1 blocks (0x204, 0x208): event header only, no parameter tree')
for btype in (BT_EVENT, BT_EVF):
    for etype in sorted(EVENTS)[::9]:
        put(std_event(btype, etype, ts=ts + 6000 + etype))

mark('event type names, ids and edge cases')
put(event(BT_EVENT_V2, 0, [struct.pack('<H', 3), struct.pack('<H', 3)]))                  # generic enter with a known id
put(event(BT_EVENT_V2, 0, [struct.pack('<H', 442), struct.pack('<H', 442)]))              # the last syscall id
put(event(BT_EVENT_V2, 0, [struct.pack('<H', 60000), struct.pack('<H', 0)]))              # unknown id
put(event(BT_EVENT_V2, 1, [struct.pack('<H', 3)]))
put(event(BT_EVENT_V2, 9999, []))                                                         # unknown event type, no params
put(event(BT_EVENT_V2, 9999, [b'abc', b'de'], nparams=2))                                 # unknown event type with params
put(event(BT_EVENT_V2, 4, [struct.pack('<q', 3)], nparams=0))                             # known type, nparams 0
put(event(BT_EVENT_V2, 4, [struct.pack('<q', 3)] + [b'xx'] * 4))                           # more parameters than the event has: ignored
put(event(BT_V2_LARGE, 4, [struct.pack('<q', 3)] + [b'xx'] * 4))
put(event(BT_EVENT_V2, 3, [struct.pack('<q', 3), b'/etc/passwd\x00', struct.pack('<i', 2), struct.pack('<I', 0o644), struct.pack('<I', 0), struct.pack('<Q', 1)]))   # open exit
put(event(BT_EVENT_V2, 3, [struct.pack('<q', 3), b'a\x00', struct.pack('<i', 2), struct.pack('<I', 0o644), struct.pack('<I', 0), struct.pack('<Q', 1)][:3]))      # fewer parameters
# a read exit whose data starts with an ELF header: the ELF dissector is called on it
elf = b'\x7fELF\x02\x01\x01\x00' + b'\0' * 8 + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 0, 64, 0, 0)
put(event(BT_EVENT_V2, 8, [struct.pack('<q', len(elf)), elf]))
put(event(BT_EVENT_V2, 8, [struct.pack('<q', 4), b'\x7fELF']))                           # ELF magic, header cut short
put(event(BT_EVENT_V2, 8, [struct.pack('<q', 0), b'']))
# a plugin event (the Falco events plugin takes it when it is loaded)
put(event(BT_EVENT_V2, 322, [struct.pack('<I', 999), struct.pack('<I', 0), b'payload']))
put(event(BT_V2_LARGE, 322, [struct.pack('<I', 999), struct.pack('<I', 0), b'payload']))
# the Info column parameters: strings with control characters, a one octet string, a terminating NUL
put(event(BT_EVENT_V2, 3, [struct.pack('<q', 7), b'/tmp/with\tcontrol\nchars\x00', struct.pack('<i', 0), struct.pack('<I', 0), struct.pack('<I', 0), struct.pack('<Q', 0)]))
put(event(BT_EVENT_V2, 3, [struct.pack('<q', 7), b'\x00', struct.pack('<i', 0), struct.pack('<I', 0), struct.pack('<I', 0), struct.pack('<Q', 0)]))
put(event(BT_V2_LARGE, 3, [struct.pack('<q', 7), b'/large/open\x00', struct.pack('<i', 0), struct.pack('<I', 0), struct.pack('<I', 0), struct.pack('<Q', 0)]))
# the fix of "Sysdig Event: Clamp the number of parameters": more parameters than the data can hold
put(event(BT_EVENT_V2, 4, [struct.pack('<q', 3)], nparams=5, lens=[8, 0, 0, 0, 0]))
put(event(BT_V2_LARGE, 4, [struct.pack('<q', 3)], nparams=5, lens=[8, 0, 0, 0, 0]))

mark('big endian section')
out.append(shb('>'))
for btype in (BT_EVENT_V2, BT_V2_LARGE):
    for etype in sorted(EVENTS)[::5]:
        put(std_event(btype, etype, e='>', ts=ts + 9000 + etype))
put(event(BT_EVENT_V2, 3, [struct.pack('>q', 3), b'/be/open\x00', struct.pack('>i', 2), struct.pack('>I', 0), struct.pack('>I', 0), struct.pack('>Q', 1)], e='>'))

# ---------------- malformed
mal = [shb()]
# the reproducer of the CPU blow-up: nparams 0xffffffff with two octets of data
for _ in range(4):
    mal.append(event(BT_EVENT_V2, 4, [], nparams=0xffffffff, lens=[8]) [0:0] + block(0x216, struct.pack('<H', 0) + struct.pack('<QQIHI', ts, 1234, 26 + 2, 4, 0xffffffff) + b'\x08\x00'))
mal.append(block(0x221, struct.pack('<H', 0) + struct.pack('<QQIHI', ts, 1234, 26 + 4, 4, 0xffffffff) + b'\x08\x00\x00\x00'))
# parameter lengths past the end of the event
mal.append(event(BT_EVENT_V2, 3, [b'/x\x00'], nparams=6, lens=[8, 3, 4, 4, 4, 8]))
mal.append(event(BT_V2_LARGE, 3, [b'/x\x00'], nparams=6, lens=[8, 3, 4, 4, 4, 8]))
mal.append(event(BT_EVENT_V2, 8, [b'\x01'], nparams=2, lens=[8, 500]))
mal.append(event(BT_EVENT_V2, 0, [b'\x01'], nparams=2, lens=[2, 2]))
mal.append(event(BT_EVENT_V2, 3, [b''], nparams=1, lens=[0]))
mal.append(event(BT_EVENT_V2, 3, [], nparams=3, lens=[]))
mal.append(event(BT_EVENT_V2, 3, [struct.pack('<q', 3), b'\xff\xfe\xfd\x00', b'a', b'b', b'c', b'd'], lens=[8, 4, 1, 1, 1, 1]))
mal.append(event(BT_EVENT, 3, [struct.pack('<q', 3)]))
mal.append(event(BT_EVF, 3, [b'']))
mal.append(event(BT_EVENT_V2, 4, [], nparams=0))                                # known type, nparams 0, no data: the Info column parameters throw

if len(sys.argv) < 2:
    sys.exit('usage: mksysdig_event.py <outdir> [-v]')
outdir = sys.argv[1]
open(os.path.join(outdir, 'sysdig-event-coverage.pcapng'), 'wb').write(b''.join(out))
open(os.path.join(outdir, 'sysdig-event-coverage-malformed.pcapng'), 'wb').write(b''.join(mal))
if '-v' in sys.argv:
    for k, name in marks:
        print(k, name)
    print('events', n, 'malformed', len(mal) - 1)
