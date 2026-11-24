#!/usr/bin/env python3
# Generates the trdp captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Builds trdp-coverage.pcap, trdp-coverage-malformed.pcap, trdp_custom.xml and the invalid
# XML files used by runcov.sh. The telegrams of the main capture are generated from the
# shipped dictionary (iec_61375-2-3.xml of the source tree).
import struct
import sys
import zlib
import xml.etree.ElementTree as ET
from pcaplib import Flow, write, udp

XML = os.environ.get('TRDP_XML', os.path.join(SRCDIR, 'resources/protocols/trdp/iec_61375-2-3.xml'))
SIZES = {'BITSET8': 1, 'BOOL8': 1, 'ANTIVALENT8': 1, 'CHAR8': 1, 'UTF16': 2, 'INT8': 1, 'INT16': 2, 'INT32': 4, 'INT64': 8,
         'UINT8': 1, 'UINT16': 2, 'UINT32': 4, 'UINT64': 8, 'REAL32': 4, 'REAL64': 8, 'TIMEDATE32': 4, 'TIMEDATE48': 6,
         'TIMEDATE64': 8, 'UUID': 16}
INTS = ('UINT8', 'UINT16', 'UINT32', 'INT8', 'INT16', 'INT32')

class Dict:
    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.ds = {}
        for d in root.iter('data-set'):
            self.ds[d.get('id')] = [(e.get('name'), e.get('type'), int(e.get('array-size', '1')), e.get('unit', ''),
                                     e.get('scale'), e.get('bits')) for e in d.findall('element')]
        self.tg = []
        for t in root.iter('telegram'):
            self.tg.append((int(t.get('com-id')), t.get('name'), t.get('data-set-id')))

class Enc:
    """Encodes a dataset of the dictionary with deterministic values."""
    def __init__(self, d, nonzero_trailer=False):
        self.d, self.n, self.nz, self.zero = d, 0, nonzero_trailer, False
    def val(self, t, unit, name):
        self.n += 1
        n = self.n
        if unit == 'hide0' or self.zero:
            return 0
        if unit == 'version':
            return 0x0100
        if t == 'ANTIVALENT8':
            return 1 + (n & 1)
        if t == 'BOOL8':
            return n & 1
        if unit in ('ssc', 'sc32'):
            return (0x1000 + n) if self.nz else 0
        return (n * 7 + 3) & 0x3f
    def basic(self, t, unit, name, idx):
        le = t.endswith('_LE')
        if le:
            t = t[:-3]
        e = '<' if le else '>'
        v = self.val(t, unit, name)
        if t in ('BITSET8', 'BOOL8', 'ANTIVALENT8', 'UINT8', 'INT8'):
            return bytes([v & 0xff])
        if t == 'CHAR8':
            return bytes([0x41 + (idx + self.n) % 26])
        if t == 'UTF16':
            return struct.pack(e + 'H', 0x41 + (idx + self.n) % 26)
        if t in ('INT16', 'UINT16'):
            return struct.pack(e + 'H', v)
        if t in ('INT32', 'UINT32'):
            return struct.pack(e + 'I', v)
        if t in ('INT64', 'UINT64'):
            return struct.pack(e + 'Q', v)
        if t == 'REAL32':
            return struct.pack(e + 'f', v + 0.5)
        if t == 'REAL64':
            return struct.pack(e + 'd', v + 0.25)
        if t == 'TIMEDATE32':
            return struct.pack('>i', 1700000000 + v)
        if t == 'TIMEDATE48':
            return struct.pack('>iH', 1700000000 + v, 0x8000 + v)
        if t == 'TIMEDATE64':
            return struct.pack('>ii', 1700000000 + v, 123456 + v)
        if t == 'UUID':
            return bytes(((self.n * 13 + i) & 0xff) for i in range(16))
        raise ValueError(t)
    def dataset(self, name, depth=0):
        out = bytearray()
        prev = None                 # (offset, size, type) of the previous integer element
        for ename, t, arr, unit, scale, bits in self.d.ds[name]:
            count = arr
            if arr == 0:
                if prev is None:
                    raise ValueError('variable array without a length element in ' + name)
                count = 2 if depth == 0 and (self.n % 3) else 1
                off, size, pt = prev
                out[off:off + size] = count.to_bytes(size, 'big')
            bt = t[:-3] if t.endswith('_LE') else t
            if bt in SIZES:
                if bt in ('CHAR8', 'UTF16'):
                    for i in range(count):
                        out += self.basic(t, unit, ename, i)
                    prev = None
                else:
                    for i in range(count):
                        start = len(out)
                        out += self.basic(t, unit, ename, i)
                    prev = (start, SIZES[bt], t) if (bt in INTS and not t.endswith('_LE')) and count == 1 else None
            else:
                for i in range(count):
                    if unit == 'fold0':
                        self.zero = True
                    out += self.dataset(t, depth + 1)
                    self.zero = False
                prev = None
        return bytes(out)

def crc_fcs(h):
    return struct.pack('<I', zlib.crc32(h) & 0xffffffff)

def pd(comid, typ=b'Pd', data=b'', seq=1, ver=0x0100, etb=0, optrn=0, dslen=None, reply_comid=0, reply_ip=0, fcs=True):
    dslen = len(data) if dslen is None else dslen
    h = struct.pack('>IH2sIIII', seq, ver, typ, comid, etb, optrn, dslen) + struct.pack('>III', 0, reply_comid, reply_ip)
    h += crc_fcs(h) if fcs else b'\0\0\0\0'
    pad = (-len(data)) % 4
    return h + data + b'\0' * pad

def md(comid, typ=b'Mn', data=b'', seq=1, ver=0x0100, etb=0, optrn=0, dslen=None, status=0, sid=b'\x11' * 16, timeout=0,
       src=b'src.example', dst=b'dst.example', fcs=True):
    dslen = len(data) if dslen is None else dslen
    h = struct.pack('>IH2sIIII', seq, ver, typ, comid, etb, optrn, dslen) + struct.pack('>I16sI32s32s', status, sid, timeout, src, dst)
    h += crc_fcs(h) if fcs else b'\0\0\0\0'
    pad = (-len(data)) % 4
    return h + data + b'\0' * pad

def main(out):
    d = Dict(XML)
    fr = []
    tg_ds = [(c, n, s) for c, n, s in d.tg if s]
    tg_none = [(c, n, s) for c, n, s in d.tg if not s]
    seq = 0
    # PD: every telegram with a dataset, types Pd and Pp alternating; PD request without data for the others
    for k, (c, n, s) in enumerate(tg_ds):
        seq += 1
        data = Enc(d).dataset(s)
        typ = (b'Pd', b'Pp', b'Pe')[k % 3]
        fr.append(udp(40000 + k % 5, 17224, pd(c, typ, data, seq, etb=7, optrn=9, reply_comid=c + 1 if k % 3 == 1 else 0,
                                              reply_ip=0xc0000201 if k % 3 == 1 else 0)))
    for k, (c, n, s) in enumerate(tg_none):
        seq += 1
        fr.append(udp(40010, 17224, pd(c, b'Pr', b'', seq, reply_comid=c + 1, reply_ip=0xc0000202)))
    # MD over UDP: the same datasets with every MD type
    mtypes = (b'Mn', b'Mr', b'Mp', b'Mq', b'Mc', b'Me')
    for k, (c, n, s) in enumerate(tg_ds):
        if k % 2:
            continue
        seq += 1
        fr.append(udp(40020, 17225, md(c, mtypes[k // 2 % 6], Enc(d).dataset(s), seq, status=k, timeout=5000000,
                                      sid=bytes(range(k, k + 16)))))
    for k, (c, n, s) in enumerate(tg_none):
        seq += 1
        fr.append(udp(40021, 17225, md(c, b'Mr', b'', seq)))
    # unknown comId with data (raw user data), a comId with an empty dataset length
    fr.append(udp(40030, 17224, pd(99999, b'Pd', bytes(range(20)), 900)))
    fr.append(udp(40030, 17224, pd(99998, b'Pd', b'', 901)))
    # MD over TCP 17225: several MDs, reassembly, two in one segment
    f = Flow(40040, 17225)
    pdus = [md(c, mtypes[k % 6], Enc(d).dataset(s), 100 + k) for k, (c, n, s) in enumerate(tg_ds[:12])]
    fr.append(f.seg(pdus[0]))
    fr.append(f.seg(pdus[1] + pdus[2]))
    a = pdus[3]; fr.append(f.seg(a[:130])); fr.append(f.seg(a[130:]))                  # the dissector needs the 116 octet MD header in the first segment
    fr.append(f.seg(pdus[4] + pdus[5][:120])); fr.append(f.seg(pdus[5][120:]))
    for p in pdus[6:]:
        fr.append(f.seg(p, client=len(fr) % 2 == 0))
    # the batch 37 reproducer: two MDs (comId 1 with a non-zero VDP trailer) over TCP; the second starts in the first segment
    def etb_pdu(trailer_nonzero, s):
        data = struct.pack('>HHBBBBIII', 0x0100, 0, 1, 0, 1, 0, 1, 2, 3) + bytes([1] * 10) + bytes([1, 0, 0, 0, 0, 0])
        data += struct.pack('>IHHII', 0, 0, 0x0100, s, 0x11223344) if trailer_nonzero else bytes(16)
        return md(1, b'Mn', data, s, status=0, timeout=0, src=b'src', dst=b'dst')
    g = Flow(40041, 17225)
    a, b = etb_pdu(True, 5), etb_pdu(True, 6)
    seg1 = a + b[:100]
    fr.append(g.seg(seg1)); fr.append(g.seg(b[100:]))
    # a PD ETBCTRL with a sequential safe sequence counter (ssc 7, 8) and a skip (ssc 20)
    for s in (7, 8, 20):
        data = struct.pack('>HHBBBBIII', 0x0100, 0, 1, 0, 1, 0, 1, 2, 3) + bytes([1] * 10) + bytes([1, 0, 0, 0, 0, 0]) + struct.pack('>IHHII', 0, 0, 0x0100, s, 0)
        fr.append(udp(40050, 17224, pd(1, b'Pd', data, 200 + s, optrn=5)))
    write(os.path.join(out, 'trdp-coverage.pcap'), fr)
    print('main frames', len(fr), 'telegrams with data', len(tg_ds), 'without', len(tg_none))

    # malformed / warning-only input
    m = []
    etb = struct.pack('>HHBBBBIII', 0x0100, 0, 1, 0, 1, 0, 1, 2, 3) + bytes([1] * 10) + bytes([1, 0, 0, 0, 0])
    m.append(udp(41000, 17224, pd(1, b'Pd', etb + b'\0' + bytes(16), 1, dslen=0xFFFFFFF0)))             # datasetLength 0xFFFFFFF0
    m.append(udp(41000, 17224, pd(1, b'Pd', etb + b'\xff' + bytes(40), 2, dslen=52 + 4 * 255)))        # count of 255 on a short packet
    m.append(udp(41000, 17224, pd(101, b'Pd', struct.pack('>HH', 0x0100, 0xffff) + bytes(60), 3)))      # nested var arrays with a huge count
    m.append(udp(41000, 17224, pd(0, b'Pd', b'', 4)))                                                  # process comId 0
    m.append(udp(41000, 17224, pd(1, b'Xx', b'', 5)))                                                  # unknown type
    m.append(udp(41000, 17224, pd(1, b'Pd', etb[:30], 6)))                                             # short data
    m.append(udp(41000, 17224, pd(1, b'Pd', Enc(d).dataset('ETBCTRL_TELEGRAM'), 7, fcs=False)))        # header checksum
    m.append(udp(42000, 17224, pd(2000, b'Pd', bytes(200), 301)))                                      # all zero (custom dictionary): invalid ANTIVALENT8
    m.append(udp(41000, 17224, b'\0' * 20))                                                            # shorter than the header
    m.append(udp(41000, 17224, pd(1, b'Pd', Enc(d, True).dataset('ETBCTRL_TELEGRAM'), 8)))             # non-zero SDT trailer
    bad = bytearray(Enc(d).dataset('ETBCTRL_TELEGRAM')); bad[29] = 7                                   # an invalid ANTIVALENT8 value
    m.append(udp(41000, 17224, pd(1, b'Pd', bytes(bad), 9)))
    nz = bytearray(Enc(d).dataset('ETBCTRL_TELEGRAM')); nz[2] = 5                                      # a reserved element that is not zero
    m.append(udp(41000, 17224, pd(1, b'Pd', bytes(nz), 10)))
    p = pd(1, b'Pd', Enc(d).dataset('ETBCTRL_TELEGRAM'), 11)
    m.append(udp(41000, 17224, p[:-2] + b'\x01\x02'[:2]))                                              # padding not zero (when padded)
    m.append(udp(41000, 17224, pd(5, b'Pd', Enc(d).dataset('CSTINFO')[:40], 12, dslen=500)))           # length beyond the data
    t = Flow(41010, 17225)
    m.append(t.seg(md(1, b'Mn', b'', 1, dslen=0)[:60]))                                                # MD header cut short
    m.append(t.seg(b'\0' * 70, client=False))
    # SDT trailers (comId 2004 of trdp_custom.xml, run with trdp.configfile): the safety code is made up, so the
    # check fails; the safe sequence counter is sequential, repeated, and wraps
    for k, ssc in enumerate((10, 11, 11, 0xfffffff8, 3)):
        trailer = struct.pack('>IHHII', 0, 0, 0x0100, ssc, 0x1234567 + k)
        a, b = ('192.0.2.1', '192.0.2.2') if k < 4 else ('192.0.2.2', '192.0.2.1')
        m.append(udp(43000, 17224, pd(2004, b'Pd', struct.pack('>I', k) + trailer, 400 + k, optrn=77), src=a, dst=b))
    write(os.path.join(out, 'trdp-coverage-malformed.pcap'), m)

    custom_xml(out)
    # frames for the telegrams of the custom dictionary (trdp_custom.xml, preference trdp.configfile)
    cd = Dict(os.path.join(out, 'trdp_custom.xml'))
    cf = []
    cseq = 0
    for k, (c, n, s) in enumerate(cd.tg):
        if not s or s not in cd.ds or s == 'SAFE':      # SAFE has a connection: its frames are in the malformed capture
            continue
        for nz in (False, True):
            cseq += 1
            cf.append(udp(42000, 17224, pd(c, b'Pd', Enc(cd, nz).dataset(s), cseq, optrn=3)))
            cseq += 1
            cf.append(udp(42001, 17225, md(c, b'Mr', Enc(cd, nz).dataset(s), cseq)))
    # an element-less dataset (numeric id) and a comId from the custom file whose data is all zero
    cf.append(udp(42000, 17224, pd(2005, b'Pd', b'\x01\x02', 300)))
    write(os.path.join(out, 'trdp-coverage-custom.pcap'), cf)
    print('custom frames', len(cf))

def custom_xml(out):
    xml = '''<?xml version="1.0" encoding="UTF-8"?>
<device xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" host-name="custom" leader-name="custom" type="train">
 <bus-interface-list>
  <bus-interface network-id="1" name="custom" host-ip="192.0.2.1" leader-ip="192.0.2.2">
   <pd-com-parameter timeout-value="100000"/>
   <md-com-parameter confirm-timeout="1000000" reply-timeout="5000000"/>
   <telegram com-id="2000" name="All types" data-set-id="ALLTYPES">
    <pd-parameter cycle="100000" timeout="300000"/>
    <md-parameter confirm-timeout="2000000" reply-timeout="3000000"/>
    <source uri="devA.anyVeh.lCst.lClTrn.lTrn" id="1"><sdt-parameter smi1="2000" smi2="2001" udv="1"/></source>
    <destination uri="devB.anyVeh.lCst.lClTrn.lTrn" id="2"><sdt-parameter smi1="2000" udv="1" cmthr="3"/></destination>
   </telegram>
   <telegram com-id="2001" name="Strings" data-set-id="STRINGS"/>
   <telegram com-id="2002" name="Nested arrays" data-set-id="NESTEDARR"/>
   <telegram com-id="2003" name="Little endian" data-set-id="LITTLE"/>
   <telegram com-id="2004" name="Safe data" data-set-id="SAFE">
    <destination uri="192.0.2.2" name="to peer"><sdt-parameter smi1="2004" udv="1"/></destination>
    <source uri1="192.0.2.2" name="from peer"><sdt-parameter smi1="2004" smi2="2005" udv="1"/></source>
   </telegram>
   <telegram com-id="2005" data-set-id="1501"/>
  </bus-interface>
 </bus-interface-list>
 <data-set-list>
  <data-set id="INNER"><element name="a" type="UINT8"/><element name="b" type="INT16" scale="0.5" offset="10" unit="V"/></data-set>
  <data-set id="ALLTYPES">
   <element name="flag" type="BOOL8"/>
   <element name="bits" type="BITSET8" bits="alpha,beta,gamma,delta"/>
   <element name="bits2" type="BITSET8"/>
   <element name="anti" type="ANTIVALENT8"/>
   <element name="i8" type="INT8"/><element name="i16" type="INT16"/><element name="i32" type="INT32" scale="0.001" unit="s"/><element name="i64" type="INT64" offset="5"/>
   <element name="u8" type="UINT8"/><element name="u16" type="UINT16" unit="version"/><element name="u32" type="UINT32" scale="2.5" offset="1" unit="mV"/><element name="u64" type="UINT64"/>
   <element name="z8" type="UINT8" unit="hide0"/><element name="zi" type="INT16" unit="hide0"/>
   <element name="r32" type="REAL32" scale="2" offset="1"/><element name="r64" type="REAL64"/>
   <element name="t32" type="TIMEDATE32"/><element name="t48" type="TIMEDATE48"/><element name="t64" type="TIMEDATE64"/>
   <element name="uuid" type="UUID"/>
   <element name="inner" type="INNER"/>
   <element name="arr" type="UINT16" array-size="3"/>
   <element name="cnt" type="UINT8"/><element name="vararr" type="UINT16" array-size="0"/>
   <element name="cnt2" type="UINT16"/><element name="varnest" type="INNER" array-size="0"/>
   <element name="zero" type="INNER" unit="fold0"/>
  </data-set>
  <data-set id="STRINGS">
   <element name="c8" type="CHAR8" array-size="8"/><element name="u16" type="UTF16" array-size="4"/>
   <element name="clen" type="UINT8"/><element name="cvar" type="CHAR8" array-size="0"/>
   <element name="ulen" type="UINT8"/><element name="uvar" type="UTF16" array-size="0"/>
   <element name="c1" type="CHAR8"/>
  </data-set>
  <data-set id="NESTEDARR">
   <element name="n" type="UINT8"/><element name="list" type="MID" array-size="0"/>
  </data-set>
  <data-set id="MID"><element name="m" type="UINT8"/><element name="in" type="INNER" array-size="2"/></data-set>
  <data-set id="LITTLE">
   <element name="a" type="UINT16_LE"/><element name="b" type="UINT32_LE"/><element name="c" type="UINT64_LE"/>
   <element name="d" type="INT16_LE"/><element name="e" type="INT32_LE"/><element name="f" type="INT64_LE"/>
   <element name="g" type="REAL32_LE"/><element name="h" type="REAL64_LE"/><element name="i" type="UUID_LE"/><element name="j" type="UTF16_LE" array-size="2"/>
  </data-set>
  <data-set id="SAFE">
   <element name="x" type="UINT32"/><element name="trailer" type="VDP_TRAILER"/>
  </data-set>
  <data-set id="VDP_TRAILER">
   <element name="reserved01" type="UINT32" unit="hide0"/><element name="reserved02" type="UINT16" unit="hide0"/>
   <element name="userDataVersion" type="UINT16" unit="version"/><element name="safeSequCount" type="UINT32" unit="ssc"/>
   <element name="safetyCode" type="UINT32" unit="sc32"/>
  </data-set>
  <data-set id="1501"><element type="UINT8"/><element type="UINT8"/></data-set>
 </data-set-list>
</device>
'''
    open(os.path.join(out, 'trdp_custom.xml'), 'w').write(xml)
    bad = {
        'trdp_bad_syntax.xml': '<device><data-set-list><data-set id="A"><element name="x" type="UINT8"></data-set-list></device>',
        'trdp_bad_type.xml': '<device><data-set-list><data-set id="A"><element name="x" type="NOSUCHTYPE"/></data-set></data-set-list></device>',
        'trdp_bad_array.xml': '<device><data-set-list><data-set id="A"><element name="x" type="UINT8" array-size="abc"/></data-set></data-set-list></device>',
        'trdp_bad_scale.xml': '<device><data-set-list><data-set id="A"><element name="x" type="UINT8" scale="x" offset="y"/></data-set></data-set-list></device>',
        'trdp_recursive.xml': '<device><data-set-list><data-set id="A"><element name="x" type="B"/></data-set><data-set id="B"><element name="y" type="A"/></data-set></data-set-list>'
                              '<bus-interface-list><bus-interface name="i"><telegram com-id="3000" data-set-id="A"/></bus-interface></bus-interface-list></device>',
        'trdp_unknown_ds.xml': '<device><bus-interface-list><bus-interface name="i"><telegram com-id="3001" data-set-id="NOPE"/></bus-interface></bus-interface-list></device>',
        'trdp_bad_comid.xml': '<device><bus-interface-list><bus-interface name="i"><telegram com-id="abc" data-set-id="X"/></bus-interface></bus-interface-list></device>',
        'trdp_dup_same.xml': '<device><data-set-list><data-set id="D"><element name="x" type="UINT8"/></data-set><data-set id="D"><element name="x" type="UINT8"/></data-set></data-set-list>'
                             '<bus-interface-list><bus-interface name="i"><telegram com-id="3002" data-set-id="D"/><telegram com-id="3002" data-set-id="D"/></bus-interface></bus-interface-list></device>',
        'trdp_dup_comid.xml': '<device><data-set-list><data-set id="D"><element name="x" type="UINT8"/></data-set></data-set-list>'
                              '<bus-interface-list><bus-interface name="i"><telegram com-id="3003" data-set-id="D"/><telegram com-id="3003" name="other" data-set-id="D"/></bus-interface></bus-interface-list></device>',
        'trdp_extra_par.xml': '<device><bus-interface-list><bus-interface name="i"><pd-com-parameter timeout-value="1"/><pd-com-parameter timeout-value="2"/>'
                              '<telegram com-id="3004"><pd-parameter timeout="1" cycle="2"/><pd-parameter timeout="1" cycle="2"/></telegram></bus-interface></bus-interface-list></device>',
        'trdp_bad_bit.xml': '<device><data-set-list><data-set id="A"><element name="x" type="BITSET8"><bit name="a" position="9"/></element></data-set></data-set-list></device>',
        'trdp_deep.xml': '<device><data-set-list>' + ''.join('<data-set id="L%d"><element name="x" type="L%d"/></data-set>' % (i, i + 1) for i in range(20)) +
                         '<data-set id="L20"><element name="x" type="UINT8"/></data-set></data-set-list>'
                         '<bus-interface-list><bus-interface name="i"><telegram com-id="3005" data-set-id="L0"/></bus-interface></bus-interface-list></device>',
        'trdp_empty.xml': '',
    }
    # two different datasets with the same id: tshark crashes (double g_propagate_error in XML_translate_dataset);
    # kept as a reproducer and not run by runcov.sh
    open(os.path.join(out, 'trdp_dup_conflict_crash.xml'), 'w').write('<device><data-set-list><data-set id="D"><element name="x" type="UINT8"/></data-set>'
        '<data-set id="D"><element name="x" type="UINT16"/></data-set></data-set-list></device>')
    os.makedirs(os.path.join(out, 'badxml'), exist_ok=True)
    for name, text in bad.items():
        open(os.path.join(out, 'badxml', name), 'w').write(text)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
