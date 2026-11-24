#!/usr/bin/env python3
# Generates test/captures/nr_rrc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NR RRC coverage captures (Exported PDU, DLT 252).

Usage: mknr_rrc.py <outdir>
Writes nr-rrc-coverage.pcap and nr-rrc-coverage-malformed.pcap.
Everything is built with a small unaligned-PER bit writer.
"""
import struct
import sys


class B:
    """Unaligned PER writer."""
    def __init__(self):
        self.val = 0
        self.n = 0

    def put(self, val, n):
        if n:
            self.val = (self.val << n) | (val & ((1 << n) - 1))
            self.n += n
        return self

    def bits(self, s):                     # '0101' string
        return self.put(int(s, 2), len(s)) if s else self

    def rng(self, v, lo, hi):              # constrained whole number
        r = hi - lo + 1
        return self.put(v - lo, (r - 1).bit_length())

    def enum(self, i, n):                  # ENUMERATED, no extension
        return self.put(i, (n - 1).bit_length())

    def ch(self, i, n, ext=False):         # CHOICE index
        if ext:
            self.put(0, 1)
        return self.put(i, (n - 1).bit_length())

    def length(self, n):                   # unconstrained length determinant
        if n < 128:
            return self.put(n, 8)
        return self.put(0x8000 | n, 16)

    def octets(self, data):                # OCTET STRING (unconstrained)
        self.length(len(data))
        return self.raw(data)

    def raw(self, data):
        return self.put(int.from_bytes(data, 'big'), 8 * len(data)) if data else self

    def bytes(self):
        pad = (8 - self.n % 8) % 8
        v = self.val << pad
        return v.to_bytes((self.n + pad) // 8, 'big')


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('>HH', 0, 0) + payload


def exp_pdu_table(table, value, payload):
    def tlv(tag, val):
        pad = (4 - len(val) % 4) % 4 if tag in (12, 14) else 0
        return struct.pack('>HH', tag, len(val) + pad) + val + b'\0' * pad
    return tlv(14, table.encode()) + tlv(32, struct.pack('>I', value)) + \
        struct.pack('>HH', 0, 0) + payload


# ---------------------------------------------------------------- IEs
def plmn(b, mcc=(0, 0, 1), mnc=(0, 1)):
    b.put(1 if mcc else 0, 1)               # mcc present
    for d in (mcc or ()):
        b.rng(d, 0, 9)
    b.rng(len(mnc), 2, 3)
    for d in mnc:
        b.rng(d, 0, 9)


def cell_group_config(n=2):
    """CellGroupConfig with RLC bearers for SRB1 and DRB1."""
    b = B()
    b.put(0, 1)                             # extension bit
    b.bits('1000000')                       # rlc-BearerToAddModList only
    b.rng(0, 0, 3)                          # cellGroupId
    b.put(n - 1, 5)                         # SIZE(1..32)
    for lcid, is_drb, ident in ((1, False, 1), (4, True, 1))[:n]:
        b.put(0, 1)                         # RLC-BearerConfig ext
        b.bits('1000')                      # servedRadioBearer only
        b.rng(lcid, 1, 32)
        b.ch(1 if is_drb else 0, 2)
        b.rng(ident, 1, 32 if is_drb else 3)
    return b.bytes()


def radio_bearer_config(drb=True):
    b = B()
    b.put(0, 1)                             # extension
    b.bits('10100' if drb else '10000')     # srb-ToAddModList [, drb-ToAddModList]
    b.put(0, 1)                             # srb list SIZE(1..2): 1 item
    b.put(0, 1)                             # SRB-ToAddMod ext
    b.bits('000')                           # no optionals
    b.rng(1, 1, 3)                          # srb-Identity
    if drb:
        b.put(0, 5)                         # DRB list SIZE(1..29): 1 item
        b.put(0, 1)                         # DRB-ToAddMod ext
        b.bits('1000')                      # cnAssociation only
        b.ch(0, 2)                          # eps-BearerIdentity
        b.rng(5, 0, 15)
        b.rng(1, 1, 32)                     # drb-Identity
    return b


def nas_identity_request():
    # 5GMM Identity request, identity type SUCI
    return bytes.fromhex('7e005b01')


def nas_registration_complete():
    return bytes.fromhex('7e0043')


# ----------------------------------------------------------- messages
def mib(sfn='101010'):
    b = B()
    b.ch(0, 2)                              # mib
    b.bits(sfn)
    b.enum(1, 2).rng(3, 0, 15).enum(1, 2)
    b.rng(5, 0, 15).rng(7, 0, 15)           # pdcch-ConfigSIB1
    b.enum(1, 2).enum(0, 2).bits('0')
    return b.bytes()


def sib1_ies(b):
    # cellSelectionInfo, ims-EmergencySupport, ue-TimersAndConstants
    b.bits('10001010000')
    b.bits('1000').rng(-60, -70, -22).rng(3, 1, 8)   # cellSelectionInfo
    b.put(0, 1).bits('0')                   # cellAccessRelatedInfo ext, no optionals
    b.put(0, 3)                             # plmn-IdentityInfoList: 1 item (SIZE 1..12 -> 4 bits)
    b.put(0, 1)                             # (4th bit)
    b.put(0, 1).bits('11')                  # PLMN-IdentityInfo ext, TAC and RANAC
    b.put(1, 4)                             # plmn-IdentityList: 2 items
    plmn(b)
    plmn(b, None, (0, 2, 1))
    b.put(0x000001, 24).put(7, 8).put(0x123456789, 36).enum(1, 2)
    b.put(0, 1)                             # ue-TimersAndConstants ext
    for v in (4, 3, 2, 3, 1, 2, 5):
        b.put(v, 3)


def bcch_dl_sch_sib1():
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(1, 2)                              # systemInformationBlockType1
    sib1_ies(b)
    return b.bytes()


def sib_choice(b, idx):                     # sib2..sib9 (idx 0..7)
    b.put(0, 1).put(idx, 3)


def system_information(sibs):
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(0, 2)                              # systemInformation
    b.ch(0, 2)                              # criticalExtensions: systemInformation
    b.bits('00')                            # late, nonCrit
    b.put(len(sibs) - 1, 5)
    for s in sibs:
        s(b)
    return b.bytes()


def sib6(b):
    sib_choice(b, 4)
    b.put(0, 1).bits('0')
    b.bits('0001000100110010').bits('1100000000000001')
    b.put(0x0580, 16)                       # warningType


def sib7(b, seg, last, data, dcs=None, msgid='0001000100110011'):
    sib_choice(b, 5)
    b.put(0, 1).bits('1' if dcs is not None else '0').bits('0')
    b.bits(msgid).bits('1100000000000010')
    b.enum(1 if last else 0, 2).rng(seg, 0, 63).octets(data)
    if dcs is not None:
        b.put(dcs, 8)


def sib8(b, seg, last, data, dcs=None):
    sib_choice(b, 6)
    b.put(0, 1).bits('1' if dcs is not None else '0').bits('00')
    b.bits('0001000100110100').bits('1100000000000011')
    b.enum(1 if last else 0, 2).rng(seg, 0, 63).octets(data)
    if dcs is not None:
        b.put(dcs, 8)


def sib9(b):
    sib_choice(b, 7)
    b.put(0, 1).bits('10')                  # ext, timeInfo
    b.bits('111')                           # dst, leap, localOffset
    b.put(123456789, 39)
    b.bits('01')
    b.rng(18, -127, 128).rng(-8, -63, 64)


def cbs_pages(n):
    out = bytes([n])
    for i in range(n):
        txt = (b'Test warning %d' % i)
        out += txt + b'\x00' * (82 - len(txt)) + bytes([len(txt)])
    return out


def paging():
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(0, 2)                              # paging
    b.bits('100')                           # pagingRecordList
    b.put(2, 5)                             # 3 records
    b.put(0, 1).bits('0').ch(0, 2, True)
    b.raw(bytes.fromhex('c0123456789a'))
    b.put(0, 1).bits('1').ch(0, 2, True)    # accessType non3GPP (no bits)
    b.raw(bytes.fromhex('c0123456789b'))
    b.put(0, 1).bits('0').ch(1, 2, True)    # fullI-RNTI
    b.put(0xa5a5a5a5a5, 40)
    return b.bytes()


def rrc_setup_request():
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(0, 4)                              # rrcSetupRequest
    b.ch(1, 2)                              # randomValue
    b.put(0x1234567890 & ((1 << 39) - 1), 39)
    b.enum(4, 16)                           # mo-Data
    b.bits('0')
    return b.bytes()


def rrc_setup_request_stmsi():
    b = B()
    b.ch(0, 2)
    b.ch(0, 4)
    b.ch(0, 2)                              # ng-5G-S-TMSI-Part1
    b.put(0x0abcdef012 & ((1 << 39) - 1), 39)
    b.enum(2, 16)                           # mt-Access
    b.bits('0')
    return b.bytes()


def rrc_setup():
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(1, 4)                              # rrcSetup
    b.rng(1, 0, 3)                          # transaction id
    b.ch(0, 2)                              # criticalExtensions: rrcSetup
    b.bits('00')                            # late, nonCrit
    rb = radio_bearer_config()
    b.put(rb.val, rb.n)
    b.octets(cell_group_config())
    return b.bytes()


def rrc_reject(wait=True):
    b = B()
    b.ch(0, 2)                              # c1
    b.ch(0, 4)                              # rrcReject
    b.ch(0, 2)                              # criticalExtensions: rrcReject
    b.bits('100' if wait else '000')        # waitTime, late, nonCrit
    if wait:
        b.rng(5, 1, 16)
    return b.bytes()


def dl_dcch(idx, body=None, ncrit=False):
    b = B()
    b.ch(0, 2)                              # c1
    b.put(idx, 4)
    return b


def ul_dcch(idx):
    b = B()
    b.ch(0, 2)
    b.put(idx, 4)
    return b


def put_b(b, other):
    b.put(other.val, other.n)


def reconf_body(b, inner_scg=None, depth=0, scg_field='nr', nas_list=True):
    """RRCReconfiguration (message body, no DL-DCCH wrapper)."""
    b.rng(2, 0, 3)                          # rrc-TransactionIdentifier
    b.ch(0, 2)                              # rrcReconfiguration
    # radioBearerConfig, secondaryCellGroup, measConfig, late, nonCrit
    if inner_scg is None:
        b.bits('11001')
        rb = radio_bearer_config()
        put_b(b, rb)
        b.octets(cell_group_config(1))
        # v1530: masterCellGroup, fullConfig, nasList, masterKeyUpdate,
        # dedSib1, dedSI, otherConfig, nonCrit
        b.bits('11110000')
        b.octets(cell_group_config(2))
        b.put(0, 5)                         # SIZE(1..29): 1 NAS message
        b.octets(nas_identity_request())
        b.bits('0').rng(3, 0, 7)            # masterKeyUpdate: keySetChange, NH count
        b.put(0, 1).bits('1')               # ext, nas-Container present
        b.octets(bytes.fromhex('00'))       # nas-Container (S1-mode to N1-mode)
        return
    b.bits('00001')
    b.bits('00000001')                      # v1530: nonCriticalExtension
    b.bits('01')                            # v1540: nonCriticalExtension
    b.bits('1000')                          # v1560: mrdc-SecondaryCellGroupConfig
    b.put(1, 1).put(0, 1).put(0 if scg_field == 'nr' else 1, 1)
    b.octets(inner_scg)


def rrc_reconf_plain():
    b = dl_dcch(0)
    reconf_body(b)
    return b.bytes()


def reconf_pdu(depth, scg_field='nr'):
    inner = None
    for _ in range(depth):
        bb = B()
        reconf_body(bb, inner)
        inner = bb.bytes()
    return inner


def rrc_reconf_nested(depth):
    msg = None
    for _ in range(depth):
        bb = B()
        reconf_body(bb, msg) if msg is not None else (
            bb.rng(0, 0, 3), bb.ch(0, 2), bb.put(0, 5))
        msg = bb.bytes()
    b = dl_dcch(0)
    b2 = B()
    b2.rng(0, 0, 3)
    b2.ch(0, 2)
    b2.bits('00001').bits('00000001').bits('01').bits('1000')
    b2.put(1, 1).put(0, 1).put(0, 1)
    b2.octets(msg)
    put_b(b, b2)
    return b.bytes()


def dl_info_transfer(nasmsg):
    b = dl_dcch(5)
    b.rng(1, 0, 3).ch(0, 2).bits('100').octets(nasmsg)
    return b.bytes()


def rrc_release():
    b = dl_dcch(2)
    b.rng(0, 0, 3).ch(0, 2)
    b.bits('000100')                        # deprioritisationReq
    b.enum(1, 2).enum(2, 4)
    return b.bytes()


def security_mode_command():
    b = dl_dcch(4)
    b.rng(0, 0, 3).ch(0, 2)
    b.bits('00')                            # late, nonCrit
    b.put(0, 1)                             # SecurityConfigSMC ext
    b.put(0, 1).bits('1')                   # SecurityAlgorithmConfig ext, integrity
    b.put(0, 1).enum(2, 8).put(0, 1).enum(2, 8)   # extensible enums
    return b.bytes()


def ue_capability_enquiry():
    b = dl_dcch(6)
    b.rng(3, 0, 3).ch(0, 2)
    b.bits('00')                            # late, ext
    b.put(2, 3)                             # 3 requests
    for rat, flt in ((0, True), (1, True), (2, False)):
        b.put(0, 1).bits('1' if flt else '0')
        b.put(0, 1).put(rat, 2)             # RAT-Type (extensible)
        if flt:
            f = B()
            f.put(0, 1).bits('1')           # UE-CapabilityRequestFilterNR ext, mrdc
            f.bits('101')
            b.octets(f.bytes())
    return b.bytes()


def mobility_from_nr(rat):
    b = dl_dcch(8)
    b.rng(1, 0, 3).ch(0, 2)
    b.bits('100')    # nas-SecurityParam, late, nonCrit
    b.put(0, 1).put(rat, 2)                 # targetRAT-Type (extensible, 4 values)
    b.octets(bytes.fromhex('0123456789'))   # targetRAT-MessageContainer
    b.octets(bytes.fromhex('0000'))         # nas-SecurityParamFromNR
    return b.bytes()


def dl_info_transfer_mrdc(inner_dl):
    b = dl_dcch(11)
    b.ch(0, 4)                              # c1: dlInformationTransferMRDC
    b.rng(0, 0, 3).ch(0, 2)                 # (transaction id only for DL: see below)
    return b


def logged_meas_cfg(abstime):
    b = dl_dcch(12)
    b.put(0, 1)                             # criticalExtensions
    b.put(0, 7)                             # IEs: no optionals
    b.put(0, 1).put(0, 1)
    b.put(0, 4).put(1, 4)
    b.put(0x123456, 24).put(0xabcd, 16).put(0x01, 8)
    b.put(abstime, 48)
    b.put(0, 3).put(0, 1).put(0, 1).put(0, 1).put(0, 8)
    return b.bytes() + b'\0' * 4


def ul_simple(idx, nasmsg=None):
    b = ul_dcch(idx)
    return b


def rrc_reconf_complete(extra=False):
    b = ul_dcch(1)
    b.rng(2, 0, 3).ch(0, 2).bits('00')
    return b.bytes()


def rrc_setup_complete():
    b = ul_dcch(2)
    b.rng(1, 0, 3).ch(0, 2)
    b.bits('000100')                        # ng-5G-S-TMSI-Value
    b.rng(1, 1, 12)
    b.octets(nas_registration_complete())
    b.ch(0, 2)
    b.raw(bytes.fromhex('c0123456789a'))
    return b.bytes()


def security_mode_complete():
    b = ul_dcch(5)
    b.rng(0, 0, 3).ch(0, 2).bits('00')
    return b.bytes()


def security_mode_failure():
    b = ul_dcch(6)
    b.rng(0, 0, 3).ch(0, 2).bits('00')
    return b.bytes()


def ul_info_transfer(nasmsg):
    b = ul_dcch(7)
    b.ch(0, 2).bits('100').octets(nasmsg)
    return b.bytes()


def measurement_report():
    b = ul_dcch(0)
    b.ch(0, 2).bits('00')                   # crit ext, late, nonCrit
    b.put(0, 1).bits('1')                   # MeasResults ext, neighCells present
    b.rng(5, 1, 64)
    b.put(0, 5)                             # 1 serving MO
    b.put(0, 1).bits('0').rng(0, 0, 31)     # ServMO ext, no best neigh, servCellId
    nr(b, 101)
    b.put(0, 1)                             # measResultNeighCells: ext bit, measResultListNR
    b.put(4, 3)                             # 5 cells
    nr(b, 102)
    nr(b, 103, ssb=False)
    nr(b, 104, v=(0, 0, 0))
    nr(b, 105, v=(127, 127, 127))
    nr(b, 106, v=(126, 126, 126))
    return b.bytes()


def nr(b, pci, ssb=True, v=(70, 30, 60)):
    b.put(0, 1).bits('1')                   # MeasResultNR ext, physCellId
    b.rng(pci, 0, 1007)
    b.bits('0')                             # rsIndexResults absent
    b.bits('10' if ssb else '01')           # cellResults
    b.bits('111').put(v[0], 7).put(v[1], 7).put(v[2], 7)



def ul_ccch(idx):
    b = B()
    b.ch(0, 2)
    b.put(idx, 2)
    return b


def reestablishment_request(cause=1):
    b = ul_ccch(2)
    b.put(0x4601, 16).rng(77, 0, 1007).put(0xbeef, 16).enum(cause, 4).bits('0')
    return b.bytes()


def resume_request():
    b = ul_ccch(1)
    b.put(0xabcdef, 24).put(0x1234, 16).enum(8, 16).bits('0')   # rna-Update
    return b.bytes()


def system_info_request():
    b = ul_ccch(3)
    b.ch(0, 2).put(0x80000001, 32).put(0, 12)
    return b.bytes()


def ul_info_transfer_mrdc(inner):
    b = ul_dcch(13)
    b.ch(0, 2).ch(0, 4).bits('1000').octets(inner)
    return b.bytes()


def dl_info_transfer_mrdc(inner):
    b = dl_dcch(11)
    b.ch(0, 2).ch(0, 4).bits('1000').octets(inner)
    return b.bytes()


def rach_iab():
    """XnAP BoundaryNodeCellsList carrying rACH-Config-Common-IAB (release)."""
    b = B()
    b.put(0, 16)
    b.put(0, 1).put(0, 1).put(0, 1)
    b.bits('0001000000')
    b.put(0, 1).put(0, 1)
    b.put(0, (8 - b.n % 8) % 8)
    b.raw(b'\x00\xf1\x10').put(0x123456789, 36)
    b.put(0, (8 - b.n % 8) % 8)
    b.put(1, 8).raw(b'\x00')
    return b.bytes()


def pcap(path, frames, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main(out):
    ok = []
    mal = []
    def add(lst, name, payload):
        lst.append(exp_pdu(name, payload))
    add(ok, 'nr-rrc.bcch.bch', mib())
    add(ok, 'nr-rrc.bcch.dl.sch', bcch_dl_sch_sib1())
    add(ok, 'nr-rrc.bcch.dl.sch', system_information([sib6, sib9]))
    seg = cbs_pages(2)
    add(ok, 'nr-rrc.bcch.dl.sch', system_information([lambda b: sib7(b, 0, False, seg[:50], 0x44)]))
    add(ok, 'nr-rrc.bcch.dl.sch', system_information([lambda b: sib7(b, 1, True, seg[50:])]))
    add(ok, 'nr-rrc.bcch.dl.sch', system_information([lambda b: sib8(b, 0, False, seg[:60], 0x44)]))
    add(ok, 'nr-rrc.bcch.dl.sch', system_information([lambda b: sib8(b, 1, True, seg[60:])]))
    add(ok, 'nr-rrc.pcch', paging())
    add(ok, 'nr-rrc.ul.ccch', rrc_setup_request())
    add(ok, 'nr-rrc.ul.ccch', rrc_setup_request_stmsi())
    add(ok, 'nr-rrc.dl.ccch', rrc_reject())
    add(ok, 'nr-rrc.dl.ccch', rrc_reject(False))
    add(ok, 'nr-rrc.dl.ccch', rrc_setup())
    add(ok, 'nr-rrc.ul.dcch', rrc_setup_complete())
    add(ok, 'nr-rrc.dl.dcch', security_mode_command())
    add(ok, 'nr-rrc.ul.dcch', security_mode_complete())
    add(ok, 'nr-rrc.ul.dcch', security_mode_failure())
    add(ok, 'nr-rrc.dl.dcch', ue_capability_enquiry())
    add(ok, 'nr-rrc.dl.dcch', dl_info_transfer(nas_identity_request()))
    add(ok, 'nr-rrc.ul.dcch', ul_info_transfer(nas_registration_complete()))
    add(ok, 'nr-rrc.dl.dcch', rrc_reconf_plain())
    add(ok, 'nr-rrc.ul.dcch', rrc_reconf_complete())
    add(ok, 'nr-rrc.dl.dcch', rrc_release())
    add(ok, 'nr-rrc.ul.dcch', measurement_report())
    add(ok, 'nr-rrc.dl.dcch', mobility_from_nr(0))
    add(mal, 'nr-rrc.dl.dcch', mobility_from_nr(1))
    add(ok, 'nr-rrc.dl.dcch', logged_meas_cfg(0xF00000000000))
    add(ok, 'nr-rrc.dl.dcch', logged_meas_cfg(0x260101120000))
    add(ok, 'nr-rrc.rrc_reconf', reconf_pdu(3))
    add(ok, 'nr-rrc.ul.ccch', reestablishment_request(0))
    add(ok, 'nr-rrc.ul.ccch', reestablishment_request(1))
    add(ok, 'nr-rrc.ul.ccch', resume_request())
    add(ok, 'nr-rrc.ul.ccch', system_info_request())
    add(ok, 'nr-rrc.ul.dcch', ul_info_transfer_mrdc(ul_info_transfer(nas_registration_complete())))
    add(ok, 'nr-rrc.dl.dcch', dl_info_transfer_mrdc(dl_info_transfer(nas_identity_request())))
    ok.append(exp_pdu_table('xnap.ies', 315, rach_iab()))
    # the fixed recursion bug: nesting beyond 8 levels stops with a warning
    add(ok, 'nr-rrc.rrc_reconf', reconf_pdu(12))
    # malformed capture: nesting limits and the target-RAT container
    add(mal, 'nr-rrc.rrc_reconf', reconf_pdu(300))
    inner = ul_info_transfer(nas_registration_complete())
    for _ in range(10):
        inner = ul_info_transfer_mrdc(inner)
    add(mal, 'nr-rrc.ul.dcch', inner)
    pcap(out + '/nr-rrc-coverage.pcap', ok)
    pcap(out + '/nr-rrc-coverage-malformed.pcap', mal)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
