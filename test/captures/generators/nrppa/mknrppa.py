#!/usr/bin/env python3
# Generates test/captures/nrppa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NRPPa coverage captures (Exported PDU "nrppa" and "ngap").

Usage: mknrppa.py <outdir>
Writes nrppa-coverage.pcap and nrppa-coverage-malformed.pcap.
Aligned PER written by hand with a small bit writer.
"""
import struct
import sys


class A:
    """Aligned PER writer."""
    def __init__(self):
        self.val = 0
        self.n = 0

    def put(self, v, n):
        if n:
            self.val = (self.val << n) | (v & ((1 << n) - 1))
            self.n += n
        return self

    def bits(self, s):
        return self.put(int(s, 2), len(s)) if s else self

    def align(self):
        self.put(0, (8 - self.n % 8) % 8)
        return self

    def rng(self, v, lo, hi, ext=False):
        """Constrained whole number (aligned variant)."""
        if ext:
            self.put(0, 1)
        r = hi - lo + 1
        v -= lo
        if r == 1:
            return self
        if r <= 255:
            return self.put(v, (r - 1).bit_length())
        if r == 256:
            return self.align().put(v, 8)
        if r <= 65536:
            return self.align().put(v, 16)
        nb = max(1, (v.bit_length() + 7) // 8)
        maxb = ((r - 1).bit_length() + 7) // 8
        self.put(nb - 1, (maxb - 1).bit_length())
        return self.align().put(v, 8 * nb)

    def enum(self, i, nroot, ext=True):
        if ext:
            self.put(0, 1)
        return self.put(i, (nroot - 1).bit_length())

    def ch(self, i, n, ext=False):
        if ext:
            self.put(0, 1)
        return self.put(i, (n - 1).bit_length())

    def length(self, n):
        self.align()
        return self.put(n, 8) if n < 128 else self.put(0x8000 | n, 16)

    def raw(self, data):
        self.align()
        return self.put(int.from_bytes(data, 'big'), 8 * len(data)) if data else self

    def bytes(self):
        pad = (8 - self.n % 8) % 8
        b = (self.val << pad).to_bytes((self.n + pad) // 8, 'big')
        return b if b else b'\0'

    def open(self, data):
        self.length(len(data))
        return self.raw(data)


def ie(a, id_, crit, content):
    a.rng(id_, 0, 65535).put(crit, 2).open(content)


def msg(ies):
    a = A()
    a.put(0, 1)                             # extension bit
    a.rng(len(ies), 0, 65535)
    for id_, crit, c in ies:
        ie(a, id_, crit, c)
    return a.bytes()


def pdu(kind, proc, crit, txid, body):
    a = A()
    a.put(0, 1).put(kind, 2)                # NRPPA-PDU CHOICE
    a.rng(proc, 0, 255).put(crit, 2)
    a.rng(txid, 0, 32767, ext=True)         # nrppatransactionID
    a.open(body)
    return a.bytes()


REJECT, IGNORE, NOTIFY = 0, 1, 2
INIT, SUCC, UNSUCC = 0, 1, 2


# ----------------------------------------------------------------- IEs
def ue_meas_id(v):
    return A().rng(v, 1, 15, ext=True).bytes()


def meas_id(v):
    return A().rng(v, 1, 65536, ext=True).bytes()


def report_char(v):
    return A().enum(v, 2).bytes()


def periodicity(v):
    return A().enum(v, 13).bytes()


def meas_quantities(vals):
    a = A()
    a.rng(len(vals), 1, 64)
    for v in vals:
        ie(a, 11, REJECT, A().put(0, 1).put(0, 1).enum(v, 6).bytes())   # item: ext, iE-Ext, value
    return a.bytes()


def cause_radio(v):
    return A().ch(0, 4).enum(v, 3).bytes()


def cause_protocol(v):
    return A().ch(1, 4).enum(v, 7).bytes()


def crit_diag():
    a = A()
    a.put(0, 1).bits('111110')
    a.rng(2, 0, 255).enum(0, 3, ext=False).enum(0, 3, ext=False)
    a.rng(77, 0, 32767, ext=True)
    a.rng(2, 1, 256)                        # two IE items
    for crit, iid, err in ((0, 2, 1), (1, 5, 0)):
        a.put(0, 1).put(0, 1)               # item ext bit, iE-Extensions
        a.put(crit, 2).rng(iid, 0, 65535).enum(err, 2)
    return a.bytes()


def ecid_result(measured=True):
    a = A()
    a.put(0, 1).bits('01' if measured else '00').bits('0')
    # servingCell-ID NG-RAN-CGI
    a.put(0, 1).bits('0')
    a.raw(bytes.fromhex('00f110'))
    a.ch(1, 3)                              # nR-CellID
    a.align().put(0x123456789, 36)
    a.raw(bytes.fromhex('000001'))          # TAC
    if measured:
        a.rng(3, 1, 64)                     # three results
        a.ch(0, 6).rng(300, 0, 719)         # AoA
        a.ch(1, 6).rng(1000, 0, 7690)       # TA type 1
        a.ch(2, 6).rng(7690, 0, 7690)       # TA type 2
    return a.bytes()


def cell_portion(v):
    return A().rng(v, 0, 4095, ext=True).bytes()


def trp_info_types(vals):
    a = A()
    a.rng(len(vals), 1, 64)
    for v in vals:
        ie(a, 57, REJECT, A().enum(v, 8).bytes())
    return a.bytes()


def srs_type_semi(setid):
    a = A()
    a.ch(0, 3).put(0, 1).put(0, 1).rng(setid, 0, 15, ext=True)
    return a.bytes()


def srs_type_aperiodic():
    a = A()
    a.ch(1, 3).put(0, 1).bits('00').put(0, 1)   # ext, trigger/ext absent, aperiodic enum ext
    return a.bytes()


def abort_tx(kind, setid=3):
    a = A().ch(kind, 3)
    if kind == 0:
        a.rng(setid, 0, 15, ext=True)
    return a.bytes()


def srs_chars():
    a = A()
    a.put(0, 1).bits('10000')               # numberOfTransmissions only
    a.rng(100, 0, 500, ext=True)
    a.enum(1, 3)                            # resourceType semi-persistent
    a.ch(0, 3).enum(2, 7)                   # bandwidth fR1 mHz20
    return a.bytes()


def activation_time():
    return A().raw(bytes.fromhex('e9a3f1c000000000')).bytes()


# ------------------------------------------------------------- frames
def frames():
    ok = []
    # ErrorIndication (0): Cause + CriticalityDiagnostics
    ok.append(pdu(INIT, 0, IGNORE, 1, msg([(0, IGNORE, cause_radio(1)), (1, IGNORE, crit_diag())])))
    ok.append(pdu(INIT, 0, IGNORE, 2, msg([(0, IGNORE, cause_protocol(3))])))
        # E-CID measurement initiation (2)
    ok.append(pdu(INIT, 2, REJECT, 10, msg([(2, REJECT, ue_meas_id(5)), (3, REJECT, report_char(1)),
                                            (4, REJECT, periodicity(4)),
                                            (5, REJECT, meas_quantities([0, 1, 2, 3, 4, 5]))])))
    ok.append(pdu(SUCC, 2, REJECT, 10, msg([(2, REJECT, ue_meas_id(5)), (6, REJECT, ue_meas_id(7)),
                                            (7, IGNORE, ecid_result(True)), (14, IGNORE, cell_portion(1234))])))
    ok.append(pdu(SUCC, 2, REJECT, 11, msg([(2, REJECT, ue_meas_id(6)), (6, REJECT, ue_meas_id(8)),
                                            (7, IGNORE, ecid_result(False))])))
    ok.append(pdu(UNSUCC, 2, REJECT, 12, msg([(2, REJECT, ue_meas_id(5)), (0, IGNORE, cause_radio(0)),
                                              (1, IGNORE, crit_diag())])))
    # failure indication (3), report (4), termination (5)
    ok.append(pdu(INIT, 3, IGNORE, 13, msg([(2, REJECT, ue_meas_id(5)), (6, REJECT, ue_meas_id(7)),
                                            (0, IGNORE, cause_protocol(0))])))
    ok.append(pdu(INIT, 4, IGNORE, 14, msg([(2, REJECT, ue_meas_id(5)), (6, REJECT, ue_meas_id(7)),
                                            (7, IGNORE, ecid_result(True))])))
    ok.append(pdu(INIT, 5, REJECT, 15, msg([(2, REJECT, ue_meas_id(5)), (6, REJECT, ue_meas_id(7))])))
    # Measurement abort (14)
    ok.append(pdu(INIT, 14, IGNORE, 16, msg([(39, REJECT, meas_id(40000)), (40, REJECT, meas_id(2))])))
    # positioning information exchange (9)
    ok.append(pdu(INIT, 9, REJECT, 17, msg([(12, IGNORE, srs_chars())])))
    # TRP information exchange (16)
    ok.append(pdu(INIT, 16, REJECT, 18, msg([(29, REJECT, trp_info_types([0, 1, 2, 3, 4, 5, 6, 7]))])))
    # positioning activation (17) and deactivation (18)
    ok.append(pdu(INIT, 17, REJECT, 19, msg([(44, REJECT, srs_type_semi(3)), (45, IGNORE, activation_time())])))
    ok.append(pdu(INIT, 17, REJECT, 20, msg([(44, REJECT, srs_type_aperiodic())])))
    ok.append(pdu(INIT, 18, IGNORE, 21, msg([(53, IGNORE, abort_tx(0))])))
    ok.append(pdu(INIT, 18, IGNORE, 22, msg([(53, IGNORE, abort_tx(1))])))
    return ok


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('>HH', 0, 0) + payload


def pcap(path, fr, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(fr):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def ngap_nrppa(proc, nrppa_pdu, amf=0x123456789a, ran=0x00ab12cd):
    """NGAP Uplink/DownlinkUEAssociatedNRPPaTransport carrying an NRPPa PDU."""
    def ngie(a, id_, crit, content):
        a.rng(id_, 0, 65535).put(crit, 2).open(content)
    body = A().put(0, 1).rng(4, 0, 65535)
    ngie(body, 10, REJECT, A().rng(amf, 0, 1099511627775).bytes())
    ngie(body, 85, REJECT, A().rng(ran, 0, 4294967295).bytes())
    ngie(body, 89, REJECT, A().length(2).raw(b'\x00\x01').bytes())
    ngie(body, 46, REJECT, A().length(len(nrppa_pdu)).raw(nrppa_pdu).bytes())
    a = A().put(0, 1).put(0, 2)             # NGAP-PDU: initiatingMessage
    a.rng(proc, 0, 255).put(IGNORE, 2).open(body.bytes())
    return a.bytes()


def main(out):
    fr = frames()
    ok = [exp_pdu('nrppa', p) for p in fr]
    # reached through NGAP (the NRPPa-PDU IE of the NRPPa transport messages)
    ok.append(exp_pdu('ngap', ngap_nrppa(50, fr[3])))
    ok.append(exp_pdu('ngap', ngap_nrppa(8, fr[4])))
    mal = [
        exp_pdu('nrppa', pdu(INIT, 1, IGNORE, 3, A().put(0, 1).rng(0, 0, 65535).bytes())),   # empty PrivateIE container
        exp_pdu('nrppa', fr[3][:20]),                                                      # truncated
        exp_pdu('nrppa', pdu(INIT, 2, REJECT, 10, msg([(5, REJECT, meas_quantities([0])[:1])]))),
        exp_pdu('nrppa', pdu(INIT, 99, REJECT, 10, msg([]))),                              # unknown procedure
        exp_pdu('nrppa', pdu(INIT, 2, REJECT, 10, msg([(999, REJECT, b'\x01\x02')]))),   # unknown IE
        exp_pdu('nrppa', fr[3] + b'\x00\x00'),                                          # trailing bytes
    ]
    pcap(out + '/nrppa-coverage.pcap', ok)
    pcap(out + '/nrppa-coverage-malformed.pcap', mal)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
