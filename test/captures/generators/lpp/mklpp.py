#!/usr/bin/env python3
# Generates test/captures/lpp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LPP coverage captures. Usage: mklpp.py <outdir>

lpp-coverage.pcap (Exported PDU, DLT 252): LPP messages (unaligned PER)
for the "lpp" dissector, LPP messages whose EPDU carries an LPPe message
(the "lppe" dissector), and LTE RRC BCCH-DL-SCH SystemInformation messages
with posSIBs whose assistance data goes to
dissect_lpp_AssistanceDataSIBelement_r15_PDU.
lpp-coverage-malformed.pcap: PDUs that only malformed input reaches.
The messages are encoded from the type tree read out of the generated
packet-lpp.c and packet-lppe.c (perschema.py); framing is built here with
struct.  All values are made up; there is no key material (the
cipheringKeyData of the reproducer holds placeholder bytes)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import random
from perschema import PerSchema, Bits

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.environ.get('WS_DISS', os.path.join(SRCDIR, 'epan/dissectors'))
sc = PerSchema([D + '/packet-lpp.c', D + '/packet-lppe.c'], 'lppe?', seed=int(os.environ.get('SEED', '2801')))
R = sc.rng
sc.avoid_re = r'criticalExtensionsFuture|spare\d|messageClassExtension'
sc.force_re = r'LPP_MessageBody|_IEs$'
BADFILE = os.path.join(HERE, 'bad.txt')
BAD = set(int(x) for x in open(BADFILE).read().split()) if os.path.exists(BADFILE) else set()


def octets_of(w):
    """encode the bytes of a Bits as an unconstrained OCTET STRING"""
    b = w.tobytes()
    o = Bits()
    sc.uncon_len(o, len(b))
    for x in b:
        o.put(x, 8)
    return o


# EPDU: identifier 1 (LPPe) in most cases; the body is then an LPPe message
EPDU_ID = [1]


def h_epdu_id(s, w):
    v = 1 if R.random() < 0.75 else R.choice([2, 3, 17, 255, 256])
    EPDU_ID[0] = v
    w.put(v - 1, 8)


def h_epdu_body(s, w):
    if EPDU_ID[0] == 1:
        inner = lppe_msg()
        w.b += octets_of(inner).b
    else:
        n = R.choice([1, 3, 8])
        sc.uncon_len(w, n)
        for _ in range(n):
            w.put(R.randrange(256), 8)


sc.hooks['dissect_lpp_EPDU_ID'] = h_epdu_id
sc.hooks['dissect_lpp_EPDU_Body'] = h_epdu_body


def h_civic(s, w):
    """the civicLocation octets go to the XML dissector: a small
    pidf-lo civic address document"""
    parts = ['<country>AU</country>', '<A1>NSW</A1>', '<A3>Sydney</A3>', '<RD>Example</RD>',
             '<HNO>%d</HNO>' % R.randrange(1, 200), '<PC>2000</PC>']
    doc = ('<civicAddress xmlns="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr">'
           + ''.join(R.sample(parts, R.randrange(1, len(parts) + 1))) + '</civicAddress>').encode()
    if s.visit is not None:
        s.visit.add(('civic', len(doc) % 7))
    s.uncon_len(w, len(doc))
    w.octets(doc)


sc.hooks['dissect_lppe_T_civicLocation'] = h_civic


def h_bds_health(s, w):
    # BDS satellite health: the two special values and random bits
    v = R.choice([0x1ff, 0x100, R.randrange(512), R.randrange(512)])
    if s.visit is not None:
        s.visit.add(('bds', v if v in (0x1ff, 0x100) else 0))
    w.put(v, 9)


sc.hooks['dissect_lpp_T_bdsSvHealth_r12'] = h_bds_health


def tune():
    sc.opt_skip = R.choice([0.0, 0.1, 0.2, 0.35])
    sc.ext_prob = R.choice([0.1, 0.25, 0.4, 0.6])


def lppe_msg():
    tune()
    return sc.enc('dissect_lppe_OMA_LPPe_MessageExtension')


def lpp_msg():
    tune()
    return sc.enc('dissect_lpp_LPP_Message').tobytes()


def exported_pdu(name, payload):
    n = name.encode()
    n += b'\0' * (-len(n) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def pcap(recs):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
    for i, rec in enumerate(recs):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(rec), len(rec)) + rec
    return out


# ---- posSIBs in LTE RRC and NR RRC SystemInformation
def lpp_func_for_sib_types():
    """LPP_POS_SIB_TYPE_x -> dissect_lpp_<Type>, from the switch in lpp.cnf"""
    t = open(D + '/asn1/lpp/lpp.cnf').read()
    return {m_.group(1): 'dissect_lpp_' + m_.group(2)
            for m_ in re.finditer(r'case LPP_POS_SIB_TYPE_(\w+):\s*dissect_(\w+)_PDU\(', t)}


def rrc_pos_sibs(path, choice, setter_re):
    """the CHOICE of the posSIB items: [(is_root, lpp type)] in index order"""
    t = open(path).read()
    fn2type = {}
    for m_ in re.finditer(setter_re, t, re.S):
        fn2type[m_.group(1)] = m_.group(2)
    body = re.search(r'static const per_choice_t %s\[\] = \{(.*?)\n\};' % choice, t, re.S).group(1)
    out = []
    for m_ in re.finditer(r'\{\s*(\d+),\s*&\w+,\s*(ASN1_\w+)\s*,\s*(\w+)\s*\}', body):
        out.append((m_.group(2) == 'ASN1_EXTENSION_ROOT', fn2type[m_.group(3)]))
    return out


SIBFN = lpp_func_for_sib_types()
LTE_SIBS = rrc_pos_sibs(D + '/packet-lte-rrc.c', 'T_posSIB_TypeAndInfo_r15_item_choice',
                        r'\n(dissect_lte_rrc_T_posSib\w+)\(tvbuff_t(?:(?!\n\}\n).)*?private_data_set_pos_sib_type\(actx, LPP_POS_SIB_TYPE_(\w+)\)')
NR_SIBS = rrc_pos_sibs(D + '/packet-nr-rrc.c', 'T_posSIB_TypeAndInfo_r16_item_choice',
                       r'\n(dissect_nr_rrc_T_posSib\w+)\(tvbuff_t(?:(?!\n\}\n).)*?pos_sib_type = LPP_POS_SIB_TYPE_(\w+);')

SIB_CUR = {}


def h_sib_flag(flag, func):
    def h(s, w):
        SIB_CUR[flag] = True
        s._enc_plain('dissect_lpp_' + func, w)
    return h


def h_sib_elem(s, w):
    if SIB_CUR.get('ciphered') or SIB_CUR.get('segmented') or SIB_CUR['type'] is None:
        payload = bytes(R.randrange(256) for _ in range(R.choice([2, 6, 11])))     # placeholder octets
    else:
        inner = Bits()
        old = s.opt_skip
        s.opt_skip = 0.5
        s._enc_plain(SIBFN[SIB_CUR['type']], inner)
        s.opt_skip = old
        payload = inner.tobytes()
    s.uncon_len(w, len(payload))
    w.octets(payload)


sc.hooks['dissect_lpp_CipheringKeyData_r15'] = h_sib_flag('ciphered', 'CipheringKeyData_r15')
sc.hooks['dissect_lpp_SegmentationInfo_r15'] = h_sib_flag('segmented', 'SegmentationInfo_r15')
# placeholder bits, not key material
sc.fixed['dissect_lpp_BIT_STRING_SIZE_1_128'] = b'\xaa\xaa'
sc.hooks['dissect_lpp_T_assistanceDataElement_r15'] = h_sib_elem


def sib_element(typ, mode=None):
    """AssistanceDataSIBelement-r15 holding an element of LPP type typ; the
    ciphered / segmented variants (mode 'cipher', 'segment', 'both') carry
    placeholder octets instead (the dissector leaves them undecoded)"""
    SIB_CUR.clear()
    SIB_CUR['type'] = typ
    sc.never_re = r'CipheringKeyData_r15|SegmentationInfo_r15'
    sc.force_re = None
    if mode:
        sc.never_re = None
        sc.force_re = {'cipher': r'CipheringKeyData_r15', 'segment': r'SegmentationInfo_r15',
                       'both': r'CipheringKeyData_r15|SegmentationInfo_r15'}[mode]
    w = Bits()
    sc._enc_plain('dissect_lpp_AssistanceDataSIBelement_r15', w)
    sc.never_re = None
    sc.force_re = r'LPP_MessageBody|_IEs$'
    return w.tobytes()


def sib_item(choices, idx, elem):
    """one item of posSIB-TypeAndInfo: CHOICE alternative idx holding SIBpos"""
    nroot = sum(1 for r, t in choices if r)
    body = Bits()
    body.put(0, 1)                 # SIBpos ext bit
    body.put(0, 1)                 # lateNonCriticalExtension absent
    sc.uncon_len(body, len(elem))
    body.octets(elem)
    w = Bits()
    if idx < nroot:
        w.put(0, 1)
        w.put(idx, (nroot - 1).bit_length())
        w.b += body.b
    else:
        w.put(1, 1)
        w.put(0, 1)
        w.put(idx - nroot, 6)
        sc.open_type(w, body)
    return w


def lte_bcch(items):
    w = Bits()
    w.put(0, 1)                # BCCH-DL-SCH-MessageType: c1
    w.put(0, 1)                # systemInformation
    w.put(1, 1)                # criticalExtensionsFuture-r15
    w.put(0, 1)                # posSystemInformation-r15
    w.put(0, 1)                # lateNonCriticalExtension absent
    w.put(0, 1)                # nonCriticalExtension absent
    w.put(len(items) - 1, 5)   # SEQUENCE SIZE(1..32)
    for it in items:
        w.b += it.b
    return w.tobytes()


def nr_bcch(items):
    w = Bits()
    w.put(0, 1)                # c1
    w.put(0, 1)                # systemInformation
    w.put(1, 1)                # criticalExtensionsFuture-r16
    w.put(0, 1)                # posSystemInformation-r16
    w.put(0, 1)                # lateNonCriticalExtension absent
    w.put(0, 1)                # nonCriticalExtension absent
    w.put(len(items) - 1, 5)   # SEQUENCE SIZE(1..maxSIB=32)
    for it in items:
        w.b += it.b
    return w.tobytes()


def sib_frames():
    """LTE and NR posSystemInformation messages: every posSIB type, with
    valueTag / expirationTime (UTCTime) when the schema picks them, and a
    few ciphered / segmented elements"""
    recs = []
    for name, choices, mk in (('lte-rrc.bcch.dl.sch', LTE_SIBS, lte_bcch),
                              ('nr-rrc.bcch.dl.sch', NR_SIBS, nr_bcch)):
        items = []
        for idx, (root, typ) in enumerate(choices):
            tune()
            items.append(sib_item(choices, idx, sib_element(typ)))
        # one message with a few items, as many as fit (at most 32 items)
        for i in range(0, len(items), 8):
            recs.append(exported_pdu(name, mk(items[i:i + 8])))
        # ciphered and segmented elements: placeholder octets, left undecoded
        mixed = []
        for idx, mode in ((0, 'cipher'), (1, 'segment'), (7, 'both'), (2, None)):
            tune()
            mixed.append(sib_item(choices, idx, sib_element(choices[idx][1], mode)))
        recs.append(exported_pdu(name, mk(mixed)))
    return recs


def candidates(n):
    """n candidate LPP messages with the set of things each one touches"""
    cand = []
    for i in range(n):
        if str(i) == os.environ.get('TRACE'):
            sc.trace = []
        sc.visit = set()
        p = exported_pdu('lpp', lpp_msg())
        cand.append((p, sc.visit))
        if sc.trace is not None:
            open('/tmp/trace.txt', 'w').write('\n'.join(sc.trace))
            sc.trace = None
    sc.visit = None
    return cand


def select(cand, budget):
    """lazy greedy cover: most new keys per byte until the budget (bytes) is used"""
    import heapq
    chosen, seen, used = [], set(), 0
    heap = [(-len(c[1]) / len(c[0]), i) for i, c in enumerate(cand)]
    heapq.heapify(heap)
    while heap:
        neg, i = heapq.heappop(heap)
        new = len(cand[i][1] - seen)
        if new == 0:
            continue
        ratio = new / len(cand[i][0])
        if heap and ratio < -heap[0][0] - 1e-12:
            heapq.heappush(heap, (-ratio, i))
            continue
        if used + len(cand[i][0]) > budget:
            continue
        chosen.append(i)
        seen |= cand[i][1]
        used += len(cand[i][0])
    return sorted(chosen)


def repro_sib_element(ciphered):
    """AssistanceDataSIBelement-r15 of lpp_sib_cipher_flag_leak.py: placeholder
    cipher bits, a GNSS-ReferenceTime payload of zero octets"""
    w = Bits()
    w.put(0, 1)                # extension bit
    w.put(0, 1)                # valueTag absent
    w.put(0, 1)                # expirationTime absent
    w.put(1 if ciphered else 0, 1)   # cipheringKeyData
    w.put(0, 1)                # segmentationInfo absent
    if ciphered:
        w.put(0, 1)            # CipheringKeyData ext bit
        w.put(0x1234, 16)      # cipherSetID
        w.put(7, 7)            # d0 length-1 (8 bits)
        w.put(0xAA, 8)         # d0 placeholder bits (not real key material)
    payload = bytes(6)
    w.put(len(payload), 8)
    w.octets(payload)
    return w.tobytes()


def repro_frames():
    """the reproducer of "LPP: Reset the ciphered and segmented flags for each posSIB": frame 1 has
    two posSib1-1 entries, the first ciphered and the second not; frame 2
    only the second (unciphered) one. With the fix both decode the second
    entry as GNSS-ReferenceTime"""
    def entry(e):
        w = Bits()
        w.put(0, 1); w.put(0, 5)           # posSib1-1-r15
        w.put(0, 1); w.put(0, 1)           # SIBpos ext bit, late absent
        w.put(len(e), 8)
        w.octets(e)
        return w
    return [exported_pdu('lte-rrc.bcch.dl.sch', lte_bcch([entry(repro_sib_element(True)), entry(repro_sib_element(False))])),
            exported_pdu('lte-rrc.bcch.dl.sch', lte_bcch([entry(repro_sib_element(False))]))]


def malformed(cand, pick, recs):
    """frames that only malformed input reaches: the candidates that do not
    decode cleanly, truncations and bit flips of the main capture frames"""
    r = random.Random(2801)
    out = [cand[i][0] for i in sorted(BAD) if i < len(cand)][:40]
    hdr = lambda p: len(exported_pdu('lpp', b''))
    for p in recs[:150]:
        n = hdr(p)
        body = p[n:]
        if len(body) < 4:
            continue
        cut = r.randrange(1, len(body))
        out.append(p[:n] + body[:cut])
        q = bytearray(p)
        for _ in range(3):
            q[r.randrange(n, len(q))] ^= 1 << r.randrange(8)
        out.append(bytes(q))
    # the SIB frames: truncated, and a flipped extension / length bit
    for p in recs[150:]:
        n = len(exported_pdu('lte-rrc.bcch.dl.sch', b'')) if b'lte-rrc' in p[:30] else len(exported_pdu('nr-rrc.bcch.dl.sch', b''))
        body = p[n:]
        if len(body) < 8:
            continue
        out.append(p[:n] + body[:r.randrange(4, len(body))])
        q = bytearray(p)
        for _ in range(2):
            q[r.randrange(n + 2, len(q))] ^= 1 << r.randrange(8)
        out.append(bytes(q))
    # zero length and tiny messages
    for b in (b'', b'\x00', b'\xff', b'\xff\xff\xff'):
        out.append(exported_pdu('lpp', b))
    return out


NCAND = int(os.environ.get('NCAND', '4000'))
BUDGET = int(os.environ.get('BUDGET', '70000'))


def main(out, mode='final'):
    cand = candidates(NCAND)
    if mode == 'cand':
        open(os.path.join(out, 'lpp-cand.pcap'), 'wb').write(pcap([p for p, v in cand]))
        return
    good = [i for i in range(len(cand)) if i not in BAD]
    pick = [good[j] for j in select([cand[i] for i in good], BUDGET)]
    nlpp = len(pick)
    recs = [cand[i][0] for i in pick] + sib_frames() + repro_frames()
    open(os.path.join(out, 'layout.txt'), 'w').write('lpp %d\nsib %d\nrepro 2\n' % (nlpp, len(recs) - nlpp - 2))
    open(os.path.join(out, 'lpp-coverage.pcap'), 'wb').write(pcap(recs))
    print('main: %d frames of %d candidates (%d bad)' % (len(recs), len(cand), len(BAD)))
    open(os.path.join(out, 'lpp-coverage-malformed.pcap'), 'wb').write(pcap(malformed(cand, pick, recs)))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'final')
