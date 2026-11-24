#!/usr/bin/env python3
# Generates test/captures/rsl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RSL (GSM A-bis Radio Signalling Link, 3GPP TS 48.058)
# captures. RSL messages travel in ip.access (IPA) frames over TCP 3006,
# which Wireshark dissects by default. Usage: mkrsl.py <outdir>
import struct
import sys
import os

# ---------------------------------------------------------------- transport
class Conn:
    def __init__(self, cport, sport=3006, cip=(192, 0, 2, 11), sip=(192, 0, 2, 1)):
        self.cport, self.sport = cport, sport
        self.cip, self.sip = bytes(cip), bytes(sip)
        self.cseq, self.sseq = 1000, 5000
        self.frames = []
        self.id = 1

    def _pkt(self, src, dst, sp, dp, seq, ack, flags, data):
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), self.id, 0x4000, 64, 6, 0, src, dst)
        self.id += 1
        s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        ip = ip[:10] + struct.pack(">H", (~s) & 0xffff) + ip[12:]
        if src == self.cip:
            eth = bytes.fromhex("020000000001020000000002") + b"\x08\x00"
        else:
            eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
        return eth + ip + tcp

    def syn(self):
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, 0, 0x02, b""))
        self.cseq += 1
        self.frames.append(self._pkt(self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq, 0x12, b""))
        self.sseq += 1
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq, 0x10, b""))

    def c(self, data):
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq, 0x18, data))
        self.cseq += len(data)

    def s(self, data):
        self.frames.append(self._pkt(self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq, 0x18, data))
        self.sseq += len(data)

def udp_frame(sip, dip, sp, dp, data, ident=1):
    udp = struct.pack(">HHHH", sp, dp, 8 + len(data), 0) + data
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0x4000, 64, 17, 0, bytes(sip), bytes(dip))
    s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack(">H", (~s) & 0xffff) + ip[12:]
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + udp

def write(fname, frames):
    with open(fname, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, d in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(d), len(d)))
            f.write(d)

def ipa(payload, stream=0x00):
    return struct.pack(">HB", len(payload), stream) + payload

# --------------------------------------------------------------------- IEs
def tv(i, *b):
    return bytes([i]) + bytes(b)

def tlv(i, data):
    return bytes([i, len(data)]) + bytes(data)

def tl16v(i, data):
    return bytes([i]) + struct.pack(">H", len(data)) + bytes(data)

def ch_no(v=0x0a):        return tv(1, v)
def link_id(v=0x00):      return tv(2, v)
def act_type(v=0x00):     return tv(3, v)
def bs_power(v=0x23):     return tv(4, v)
def ch_id(ma=b""):
    return tlv(5, bytes([0x64, 0x08, 0x00, 0x01, 0x72, len(ma)]) + ma)
def ch_mode(sod=1, rate=0x08, coding=0x01, dtx=0x03):
    return tlv(6, bytes([dtx, sod, rate, coding]))
def enc_inf(alg=2, key=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
    return tlv(7, bytes([alg]) + key)
def frame_no(v=(0x41, 0x23)): return tv(8, *v)
def ho_ref(v=0x5a):       return tv(9, v)
def l1_inf(a=0x2a, b=0x03): return tv(10, a, b)
def l3_inf(data):         return tl16v(11, data)
def ms_id(data):          return tlv(12, data)
def ms_pow(v=0x07):       return tv(13, v)
def paging_grp(v=0x05):   return tv(14, v)
def paging_load(v=0x0123): return tv(15, v >> 8, v & 0xff)
def phy_ctx(data):        return tlv(16, data)
def access_delay(v=0x03): return tv(17, v)
def rach_load(data):      return tlv(18, data)
def req_ref(ra=0xe5, t=(0x1b, 0x37)): return tv(19, ra, *t)
def rel_mode(v=0x00):     return tv(20, v)
def resource_inf(data):   return tlv(21, data)
def rlm_cause(data):      return tlv(22, data)
def starting_time(v=(0x1b, 0x37)): return tv(23, *v)
def timing_adv(v=0x04):   return tv(24, v)
def uplink_meas(data=bytes([0x9d, 0x30, 0x2a, 0x00])): return tlv(25, data)
def cause(data=b"\x01"):  return tlv(26, data)
def meas_res_no(v=0x11):  return tv(27, v)
def message_id(v=0x1b):   return tv(28, v)
def sys_info_type(v=0x01): return tv(30, v)
def ms_pow_params(data=b"\x01\x02\x03"): return tlv(31, data)
def bs_pow_params(data=b"\x04\x05"): return tlv(32, data)
def full_imm_ass(data):   return tlv(35, data)
def smscb_inf(data):      return tlv(36, data)
def ms_timing_off(v=0x40): return tv(37, v)
def err_msg(data):        return tlv(38, data)
def full_bcch(data):      return tlv(39, data)
def ch_needed(v=0x02):    return tv(40, v)
def cb_cmd_type(v=0x05):  return tv(41, v)
def smscb_mess(data):     return tlv(42, data)
def cbch_load(v=0x83):    return tv(43, v)
def sacch_inf(msgs):
    body = bytes([len(msgs)])
    for t, d in msgs:
        body += bytes([t, len(d)]) + d
    return tlv(44, body)
def smscb_ch_ind(v=0x01): return tv(46, v)
def grp_call_ref(data=bytes([0x00, 0x00, 0x11, 0x22, 0x31])): return tlv(47, data)
def ch_desc(data=bytes([0x10, 0x20, 0x30])): return tlv(48, data)
def nch_drx(v=0x0c):      return tv(49, v)
def cmd_ind(data=b"\x00"): return tlv(50, data)
def emlpp_prio(v=0x03):   return tv(51, v)
def uic(v=0x2b):          return tv(52, v)
def main_ch_ref(v=0x03):  return tv(53, v)
def multirate_conf(data=bytes([0x20, 0x0b, 0x8a, 0x3d])): return tlv(54, data)
def multirate_cntrl(v=0x1d): return tv(55, v)
def sup_codec(data=bytes([0x00, 0x01, 0x03, 0x04, 0x09, 0x0c])): return tlv(56, data)
def codec_conf(data=bytes([0x03, 0x04, 0x05])): return tlv(57, data)
def rtd(v=0x41):          return tv(58, v)
def tfo_status(v=0x01):   return tv(59, v)
def llp_apdu(data=bytes([0x01, 0x02, 0x03])): return tlv(60, data)
def tfo_transp(data=bytes([0x05, 0x06, 0x07])): return tlv(61, data)

# Osmocom
def osmo_rep_acch(v=0xf5):  return tlv(0x60, bytes([v]))
def osmo_tseq(s=1, v=3):    return tlv(0x61, bytes([s, v]))
def osmo_top_acch(v=0xb5):  return tlv(0x62, bytes([v]))
def osmo_osmux(v=0x07):     return tlv(0x63, bytes([v]))

# ip.access
def ipa_remote_ip(a=(192, 0, 2, 77)): return bytes([0xf0]) + bytes(a)
def ipa_remote_port(p=16000):  return bytes([0xf1]) + struct.pack(">H", p)
def ipa_local_ip(a=(192, 0, 2, 11)): return bytes([0xf5]) + bytes(a)
def ipa_local_port(p=16384):   return bytes([0xf3]) + struct.pack(">H", p)
def ipa_speech_mode(v=0x02):   return bytes([0xf4, v])
def ipa_payload(v=0x62):       return bytes([0xf2, v])
def ipa_payload2(v=0x62):      return bytes([0xfc, v])
def ipa_csd(v=0x19):           return bytes([0xf9, v])
def ipa_conn_id(v=0x1234):     return bytes([0xf8]) + struct.pack(">H", v)
def ipa_conn_stat():
    return tlv(0xf6, struct.pack(">7I", 100, 16000, 99, 15900, 1, 20, 5))

def msg(disc, mtype, *ies, t=0):
    return bytes([(disc << 1) | t, mtype]) + b"".join(ies)

RLL, DCM, CCM, TRXM, LOC, IPAD = 0x01, 0x04, 0x06, 0x08, 0x10, 0x3f

# Layer 3 payloads
L3_LUREJ = bytes([0x05, 0x04, 0x11])                 # MM Location Updating Reject
L3_CCSETUP = bytes([0x03, 0x45, 0x04, 0x01, 0xa0])   # CC Setup (short)
L3_CIPH = bytes([0x06, 0x35, 0x01])            # RR Ciphering Mode Command
L3_MEAS = bytes([0x06, 0x15, 0x00, 0x21, 0x33, 0x44, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10])  # RR Measurement Report
L3_ENH = bytes([0x10, 0x06, 0x36]) + bytes(18)
IMM_ASS = bytes([0x2d, 0x06, 0x3f, 0x00, 0x08, 0x00, 0x01, 0xe5, 0x1b, 0x37, 0x04, 0x00]) + bytes([0x2b] * 11)
SI3 = bytes([0x55, 0x06, 0x1b]) + bytes(range(1, 19))
PAGING1 = bytes([0x15, 0x06, 0x21, 0x00, 0x08, 0x39, 0x54, 0x16, 0x32, 0x54, 0x76, 0x98, 0x10, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b])
CBCH_BLOCK = bytes([0x20, 0x11, 0x22, 0x33] + [0x41] * 19)
CBS_PAGE = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + bytes([0x41] * 82)
SACCH_SI5 = bytes([0x49, 0x06, 0x1d]) + bytes([0x00] * 16)

IMSI = bytes([0x39, 0x54, 0x16, 0x32, 0x54, 0x76, 0x98, 0x10])
TMSI = bytes([0xf4, 0xde, 0xad, 0xbe, 0xef])
IMEI = bytes([0x3a, 0x54, 0x16, 0x32, 0x54, 0x76, 0x98, 0x10])

def build_messages():
    """The main capture: list of (stream, message bytes)."""
    M = []
    a = lambda s, m: M.append((s, m))
    # --- Radio link layer management (SAPI/link identifiers) -------------
    for lid in (0x00, 0x03, 0x43, 0x20, 0x4b, 0x13):
        a(0, msg(RLL, 0x01, ch_no(0x0a), link_id(lid), l3_inf(L3_LUREJ)))   # DATA REQ
    a(0, msg(RLL, 0x02, ch_no(0x0a), link_id(0x00), l3_inf(L3_CCSETUP)))    # DATA IND
    a(0, msg(RLL, 0x03, ch_no(0x0a), link_id(0x00), rlm_cause(b"\x01")))    # ERROR IND
    a(0, msg(RLL, 0x03, ch_no(0x0a), link_id(0x00), rlm_cause(b"\x82")))
    a(0, msg(RLL, 0x03, ch_no(0x0a), link_id(0x00), rlm_cause(b"")))
    a(0, msg(RLL, 0x04, ch_no(0x0a), link_id(0x03)))                        # EST REQ
    a(0, msg(RLL, 0x05, ch_no(0x0a), link_id(0x03)))                        # EST CONF
    a(0, msg(RLL, 0x06, ch_no(0x0a), link_id(0x00), l3_inf(L3_LUREJ)))      # EST IND
    a(0, msg(RLL, 0x06, ch_no(0x0a), link_id(0x00)))
    a(0, msg(RLL, 0x07, ch_no(0x0a), link_id(0x00), rel_mode(0x00)))        # REL REQ
    a(0, msg(RLL, 0x07, ch_no(0x0a), link_id(0x00), rel_mode(0x01)))
    a(0, msg(RLL, 0x08, ch_no(0x0a), link_id(0x00)))                        # REL CONF
    a(0, msg(RLL, 0x09, ch_no(0x0a), link_id(0x00)))                        # REL IND
    a(0, msg(RLL, 0x0a, ch_no(0x0a), link_id(0x03), l3_inf(L3_LUREJ)))      # UNIT DATA REQ
    a(0, msg(RLL, 0x0a, ch_no(0x0a), link_id(0x03)))
    a(0, msg(RLL, 0x0b, ch_no(0x0a), link_id(0x03), l3_inf(L3_LUREJ)))      # UNIT DATA IND
    # --- Common channel management ---------------------------------------
    a(0, msg(CCM, 0x11, ch_no(0x80), sys_info_type(0x1c), full_bcch(SI3), starting_time()))  # BCCH INFO
    a(0, msg(CCM, 0x11, ch_no(0x80), sys_info_type(0x01)))
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(struct.pack(">HHH", 1000, 200, 150)), paging_load()))  # CCCH LOAD
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(struct.pack(">HHH", 1000, 200, 150) + b"\x01\x02")))
    a(0, msg(CCM, 0x12, ch_no(0x90), paging_load(7)))
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(0xe5), access_delay(2)))        # CHAN RQD
    for ra in (0x00, 0x80, 0xa0, 0xc0, 0xe0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x70, 0x60, 0x68, 0x6c, 0x7f):
        a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(ra), access_delay(2)))
    ext_ra = bytes([0x42, 0x02, 0xaa, 0xbb]); ab = bytes([0x43, 0x02, 0x33, 0x04]); lvl = bytes([0x45, 0x01, 0x21])
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), phy_ctx(ext_ra + ab + lvl)))
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), phy_ctx(ab + lvl)))
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), phy_ctx(lvl)))
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), phy_ctx(bytes([0x77, 0x01, 0x02]))))
    a(0, msg(CCM, 0x14, ch_no(0x90), full_imm_ass(IMM_ASS)))                 # DELETE IND
    a(0, msg(CCM, 0x15, ch_no(0x90), paging_grp(), ms_id(IMSI), ch_needed(), emlpp_prio()))   # PAGING CMD
    a(0, msg(CCM, 0x15, ch_no(0x90), paging_grp(), ms_id(TMSI)))
    a(0, msg(CCM, 0x16, ch_no(0x90), full_imm_ass(IMM_ASS)))                 # IMM ASS CMD
    a(0, msg(CCM, 0x17, ch_no(0x91), smscb_inf(CBCH_BLOCK), smscb_ch_ind()))  # SMS BC REQ
    a(0, msg(CCM, 0x17, ch_no(0x91), smscb_inf(CBCH_BLOCK)))
    a(0, msg(CCM, 0x1d, ch_no(0x91), cb_cmd_type(0x05), smscb_mess(CBS_PAGE), smscb_ch_ind()))  # SMS BC CMD
    a(0, msg(CCM, 0x1d, ch_no(0x91), cb_cmd_type(0x40), smscb_mess(CBS_PAGE)))
    a(0, msg(CCM, 0x1e, ch_no(0x91), cbch_load(0x83), smscb_ch_ind()))       # CBCH LOAD IND
    a(0, msg(CCM, 0x1e, ch_no(0x91), cbch_load(0x03)))
    a(0, msg(CCM, 0x1f, ch_no(0x91), cmd_ind(b"\x00"), grp_call_ref(), ch_desc(), nch_drx()))  # NOTIFICATION CMD
    for ci in (b"\x01", b"\x20", b"\x45", b"\x7f"):
        a(0, msg(CCM, 0x1f, ch_no(0x91), cmd_ind(ci)))
    a(0, msg(CCM, 0x1f, ch_no(0x91), cmd_ind(b"\x80\x05")))
    # --- TRX management --------------------------------------------------
    a(0, msg(TRXM, 0x19, resource_inf(bytes([0x08, 0x20, 0x09, 0x40, 0x0a, 0x60]))))  # RF RES IND
    a(0, msg(TRXM, 0x19, resource_inf(bytes([0x08, 0x20, 0x09]))))
    a(0, msg(TRXM, 0x19, resource_inf(b"")))
    a(0, msg(TRXM, 0x1a, sys_info_type(0x48), l3_inf(SACCH_SI5), starting_time()))   # SACCH FILLING
    a(0, msg(TRXM, 0x1a, sys_info_type(0x01), l3_inf(IMM_ASS[:23])))
    a(0, msg(TRXM, 0x1a, sys_info_type(0x01)))
    a(0, msg(TRXM, 0x1b, cause(b"\x01")))                                    # OVERLOAD
    a(0, msg(TRXM, 0x1c, cause(b"\x03\x07"), message_id(0x21), ch_no(0x0a), link_id(0x00),
             err_msg(msg(RLL, 0x04, ch_no(0x0a), link_id(0x03)))))           # ERROR REPORT
    a(0, msg(TRXM, 0x1c, cause(b"\x83\x00"), message_id(), ch_no(0x0a), link_id(0x00)))
    a(0, msg(TRXM, 0x1c, cause(b"\x01")))
    # --- Dedicated channel management --------------------------------------
    full_act = [ch_no(0x0a), act_type(0x00), ch_mode(), ch_id(), enc_inf(), ho_ref(), bs_power(),
                ms_pow(), timing_adv(), bs_pow_params(), ms_pow_params(),
                phy_ctx(lvl), sacch_inf([(0x05, SACCH_SI5), (0x06, SACCH_SI5)]), uic(), main_ch_ref(),
                multirate_conf(), multirate_cntrl(), sup_codec(), tfo_transp()]
    a(0, msg(DCM, 0x21, *full_act))
    for at in (0x01, 0x02, 0x05, 0x07, 0x04, 0x03, 0x0c, 0x80):
        a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(at), ch_mode(2, 0x08, 0x18)))
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00)))
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(2, 0x09, 0x58)))     # data, non-transparent
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(3, 0x01, 0x00)))      # signalling
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(7, 0x01, 0x00)))      # bad indicator
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(), ch_id(bytes([0x01, 0x02, 0x03]))))
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(), enc_inf(1, b"")))
    a(0, msg(DCM, 0x22, ch_no(0x0a), frame_no()))                            # ACT ACK
    a(0, msg(DCM, 0x23, ch_no(0x0a), cause(b"\x01")))                        # ACT NACK
    a(0, msg(DCM, 0x24, ch_no(0x0a), cause(b"\x42")))                        # CONN FAIL
    a(0, msg(DCM, 0x25, ch_no(0x0a)))                                        # DEACT SACCH
    a(0, msg(DCM, 0x26, ch_no(0x0a), enc_inf(), link_id(0x00), l3_inf(L3_CIPH)))   # ENCR CMD
    a(0, msg(DCM, 0x27, ch_no(0x0a), access_delay()))                        # HANDO DET
    a(0, msg(DCM, 0x27, ch_no(0x0a)))
    a(0, msg(DCM, 0x28, ch_no(0x0a), meas_res_no(), uplink_meas(), bs_power(), l1_inf(),
             l3_inf(L3_MEAS), ms_timing_off()))                              # MEAS RES
    a(0, msg(DCM, 0x28, ch_no(0x0a), meas_res_no(), uplink_meas(), bs_power(), l1_inf(),
             l3_inf(L3_ENH), ms_timing_off()))
    a(0, msg(DCM, 0x28, ch_no(0x0a), meas_res_no(), uplink_meas(), bs_power()))
    a(0, msg(DCM, 0x29, ch_no(0x0a), ch_mode(), enc_inf(), main_ch_ref(), multirate_conf(),
             multirate_cntrl(), sup_codec(), tfo_transp()))                  # MODE MODIFY REQ
    a(0, msg(DCM, 0x29, ch_no(0x0a), ch_mode()))
    a(0, msg(DCM, 0x2a, ch_no(0x0a)))                                        # MODE MODIFY ACK
    a(0, msg(DCM, 0x2b, ch_no(0x0a), cause(b"\x01")))                        # MODE MODIFY NACK
    a(0, msg(DCM, 0x2c, ch_no(0x0a)))                                        # PHY CTX REQ
    a(0, msg(DCM, 0x2d, ch_no(0x0a), bs_power(), ms_pow(), timing_adv(), phy_ctx(lvl)))   # PHY CTX CONF
    a(0, msg(DCM, 0x2d, ch_no(0x0a), bs_power(), ms_pow(), timing_adv()))
    a(0, msg(DCM, 0x2e, ch_no(0x0a)))                                        # RF CHAN REL
    a(0, msg(DCM, 0x2f, ch_no(0x0a), ms_pow(), ms_pow_params()))             # MS POWER CONTROL
    a(0, msg(DCM, 0x2f, ch_no(0x0a), ms_pow()))
    a(0, msg(DCM, 0x30, ch_no(0x0a), bs_power(), bs_pow_params()))           # BS POWER CONTROL
    a(0, msg(DCM, 0x30, ch_no(0x0a), bs_power()))
    a(0, msg(DCM, 0x31, ch_no(0x0a)))                                        # PREPROC CONFIG
    a(0, msg(DCM, 0x32, ch_no(0x0a)))                                        # PREPROC MEAS RES
    a(0, msg(DCM, 0x33, ch_no(0x0a)))                                        # RF CHAN REL ACK
    a(0, msg(DCM, 0x34, ch_no(0x0a), sys_info_type(0x48), l3_inf(SACCH_SI5), starting_time()))  # SACCH INFO MODIFY
    a(0, msg(DCM, 0x34, ch_no(0x0a), sys_info_type(0x01), l3_inf(IMM_ASS[:23])))
    a(0, msg(DCM, 0x34, ch_no(0x0a), sys_info_type(0x48)))
    a(0, msg(DCM, 0x35, ch_no(0x0a), ch_no(0x0b)))                           # TALKER DET
    a(0, msg(DCM, 0x35, ch_no(0x0a)))
    a(0, msg(DCM, 0x36, ch_no(0x0a), ch_no(0x0b)))                           # LISTENER DET
    a(0, msg(DCM, 0x36, ch_no(0x0a)))
    a(0, msg(DCM, 0x37, ch_no(0x0a), codec_conf(), sup_codec(), tfo_transp()))   # REMOTE CODEC CONF REP
    a(0, msg(DCM, 0x37, ch_no(0x0a), codec_conf()))
    a(0, msg(DCM, 0x38, ch_no(0x0a), rtd(0x41)))                             # RTD REP
    a(0, msg(DCM, 0x39, ch_no(0x0a), multirate_cntrl(), codec_conf(), tfo_transp()))   # PRE HANDO NOTIF
    a(0, msg(DCM, 0x39, ch_no(0x0a), multirate_cntrl(), codec_conf()))
    a(0, msg(DCM, 0x3a, ch_no(0x0a), multirate_conf()))                      # MR CODEC MOD REQ
    a(0, msg(DCM, 0x3a, ch_no(0x0a)))
    a(0, msg(DCM, 0x3b, ch_no(0x0a), multirate_conf()))                      # MR CODEC MOD ACK
    a(0, msg(DCM, 0x3b, ch_no(0x0a)))
    a(0, msg(DCM, 0x3c, ch_no(0x0a), cause(b"\x01")))                        # MR CODEC MOD NACK
    a(0, msg(DCM, 0x3d, ch_no(0x0a), multirate_conf()))                      # MR CODEC MOD PER
    a(0, msg(DCM, 0x3e, ch_no(0x0a), tfo_status(0x01)))                      # TFO REP
    a(0, msg(DCM, 0x3f, ch_no(0x0a), multirate_cntrl(), sup_codec(), tfo_transp()))   # TFO MOD REQ
    a(0, msg(DCM, 0x3f, ch_no(0x0a), multirate_cntrl()))
    # --- Location services -------------------------------------------------
    a(0, msg(LOC, 0x41, llp_apdu()))                                         # LOCATION INFO
    # --- Encapsulated paging (Huawei): CS and PS packages ------------------
    a(0, msg(CCM, 0x18, bytes([0x02]),
             bytes([0x10]) + tlv(12, IMSI) + bytes([0x05, 0x00]),
             bytes([0x21]) + tlv(12, TMSI) + bytes([0x80, 0x01, 0x02, 0x03, 0x04])))
    a(0, msg(CCM, 0x18, bytes([0x01]), bytes([0x10]) + tlv(12, TMSI) + bytes([0x07, 0x00])))
    # --- Osmocom ETWS command (decoded only with the Osmocom preference) ----
    a(0, msg(CCM, 0x7f, ch_no(0x91), tlv(0x2a, bytes(range(10)))))
    # --- reproducers of "RSL: Fix IE lengths and returned offsets" -------
    pload = paging_load(0x1234)
    cnt = struct.pack(">HHH", 1, 2, 3)
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(cnt), pload))                 # RACH load, 6 octets, paging load follows
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(cnt + b"\xaa"), pload))       # 7 octets (supplementary information)
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(cnt[:2]), pload))             # 2 octets: shorter than the counters
    a(0, msg(TRXM, 0x19, tv(21, 1) + bytes(range(1, 41))))                   # resource information, odd length
    a(0, msg(TRXM, 0x19, resource_inf(bytes([0x11, 0x22]))))
    ipa_crcx_ack = msg(IPAD, 0x71, ipa_conn_id(1), ipa_local_ip((192, 0, 2, 10)), ipa_local_port(5000),
                       ipa_speech_mode(2), ipa_payload2(0x62))
    a(0, msg(TRXM, 0x1c, cause(b"\x00"), err_msg(ipa_crcx_ack)))            # embedded ip.access message
    inner = msg(TRXM, 0x1c, cause(b"\x00"))
    a(0, msg(TRXM, 0x1c, cause(b"\x00"), tlv(38, inner), bytes([28, 0x55])))  # IE length honoured
    nested = msg(RLL, 0x04, ch_no(0x0a), link_id(0x03))
    for _ in range(30):                                                      # nested erroneous messages
        nested = msg(TRXM, 0x1c, cause(b"\x00"), tlv(38, nested))
    a(0, nested)
    a(0, msg(CCM, 0x13, ch_no(0x88), tv(19, 0xe5, 0x1b, 0x37), access_delay(),
             phy_ctx(bytes([0x11, 0x05])), tlv(16, bytes([0x77, 0x01, 0x02])), tv(15, 0, 3)))   # phy ctx, unknown inner type
    # --- unknown IE where optional IEs may follow: every optional IE is tried
    #     and skipped ---------------------------------------------------------
    J = bytes([0xee, 0x00, 0x00, 0x00, 0x00])
    a(0, msg(RLL, 0x06, ch_no(0x0a), link_id(0x00), J))
    a(0, msg(RLL, 0x0a, ch_no(0x0a), link_id(0x03), J))
    a(0, msg(CCM, 0x11, ch_no(0x80), sys_info_type(0x01), J))
    a(0, msg(CCM, 0x12, ch_no(0x90), J))
    a(0, msg(CCM, 0x12, ch_no(0x90), rach_load(cnt), J))
    a(0, msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), J))
    a(0, msg(CCM, 0x15, ch_no(0x90), paging_grp(), ms_id(IMSI), J))
    a(0, msg(CCM, 0x17, ch_no(0x91), smscb_inf(CBCH_BLOCK), J))
    a(0, msg(CCM, 0x1d, ch_no(0x91), cb_cmd_type(0x05), smscb_mess(CBS_PAGE), J))
    a(0, msg(CCM, 0x1e, ch_no(0x91), cbch_load(0x83), J))
    a(0, msg(CCM, 0x1f, ch_no(0x91), cmd_ind(b"\x00"), J))
    a(0, msg(TRXM, 0x1a, sys_info_type(0x01), J))
    a(0, msg(TRXM, 0x1c, cause(b"\x01"), J))
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(0x00), ch_mode(), J))
    a(0, msg(DCM, 0x27, ch_no(0x0a), J))
    a(0, msg(DCM, 0x28, ch_no(0x0a), meas_res_no(), uplink_meas(), bs_power(), J))
    a(0, msg(DCM, 0x29, ch_no(0x0a), ch_mode(), J))
    a(0, msg(DCM, 0x2d, ch_no(0x0a), bs_power(), ms_pow(), timing_adv(), J))
    a(0, msg(DCM, 0x2f, ch_no(0x0a), J))
    a(0, msg(DCM, 0x30, ch_no(0x0a), bs_power(), J))
    a(0, msg(DCM, 0x34, ch_no(0x0a), sys_info_type(0x01), J))
    a(0, msg(DCM, 0x35, ch_no(0x0a), J))
    a(0, msg(DCM, 0x37, ch_no(0x0a), codec_conf(), J))
    a(0, msg(DCM, 0x39, ch_no(0x0a), multirate_cntrl(), codec_conf(), J))
    a(0, msg(DCM, 0x3a, ch_no(0x0a), J))
    a(0, msg(DCM, 0x3f, ch_no(0x0a), multirate_cntrl(), J))
    # --- unknown message type ---------------------------------------------
    a(0, msg(DCM, 0x7e, ch_no(0x0a)))
    # --- Osmocom IEs in channel activation / mode modify / handover detect --
    a(0, msg(DCM, 0x21, ch_no(0x0a), act_type(), ch_mode(), osmo_rep_acch(), osmo_top_acch(), osmo_tseq()))
    a(0, msg(DCM, 0x29, ch_no(0x0a), ch_mode(), osmo_rep_acch(), osmo_top_acch(), osmo_tseq()))
    a(0, msg(DCM, 0x27, ch_no(0x0a), access_delay(), osmo_tseq(2, 5)))
    return M

def build_ipaccess():
    """ip.access messages (message discriminator 0x3f) and the ip.access
    types sent with the standard discriminators."""
    M = []
    a = lambda s, m: M.append((s, m))
    a(0, msg(IPAD, 0x70, ch_no(0x0a), ipa_speech_mode(0x02), ipa_payload2(0x62)))            # CRCX
    a(0, msg(IPAD, 0x70, ch_no(0x0a), ipa_remote_ip(), ipa_remote_port(), ipa_speech_mode(0x82),
             ipa_payload(), ipa_csd(0x19), ipa_conn_id()))
    a(0, msg(IPAD, 0x71, ch_no(0x0a), ipa_conn_id(), ipa_local_port(16384), ipa_local_ip(),
             ipa_speech_mode(0x02), ipa_payload2(0x62)))                                    # CRCX ACK (AMR)
    a(0, msg(IPAD, 0x71, ch_no(0x0b), ipa_conn_id(0x77), ipa_local_port(16386), ipa_local_ip(),
             ipa_speech_mode(0x00), ipa_payload(0x03)))                                     # CRCX ACK (FR)
    a(0, msg(IPAD, 0x71, ch_no(0x0b), ipa_conn_id(0x78), ipa_local_port(16388), ipa_local_ip(), ipa_payload(0x62)))
    a(0, msg(IPAD, 0x72, ch_no(0x0a), cause(b"\x01")))                                       # CRCX NACK
    a(0, msg(IPAD, 0x73, ch_no(0x0a), ipa_conn_id(), ipa_remote_ip(), ipa_remote_port(),
             ipa_speech_mode(0x01), ipa_payload2(0x62)))                                    # MDCX
    a(0, msg(IPAD, 0x74, ch_no(0x0a), ipa_conn_id(), ipa_local_port(16384), ipa_local_ip(), ipa_payload2()))   # MDCX ACK
    a(0, msg(IPAD, 0x75, ch_no(0x0a), cause(b"\x01")))                                       # MDCX NACK
    a(0, msg(IPAD, 0x76, ch_no(0x0a), ipa_conn_id(), ipa_conn_stat(), cause(b"\x01")))       # DLCX IND
    a(0, msg(IPAD, 0x77, ch_no(0x0a), ipa_conn_id()))                                        # DLCX
    a(0, msg(IPAD, 0x78, ch_no(0x0a), ipa_conn_id(), ipa_conn_stat()))                       # DLCX ACK
    a(0, msg(IPAD, 0x79, ch_no(0x0a), cause(b"\x01")))                                       # DLCX NACK
    a(0, msg(IPAD, 0x70, frame_no(), ms_pow(), bs_power(), ms_pow_params(), bs_pow_params()))  # other known IEs
    a(0, msg(IPAD, 0x70, ch_no(0x0a), l3_inf(L3_LUREJ), ipa_conn_id()))                        # 16 bit length IE
    a(0, msg(IPAD, 0x70, bytes([0xe0, 0x01, 0x02])))                                         # unknown IE ends parsing
    a(0, msg(IPAD, 0x71, ch_no(0x0a), ipa_conn_id(), ipa_local_port(16390), ipa_local_ip(), osmo_osmux(0x09)))   # Osmux CID
    a(0, msg(IPAD, 0x70, ch_no(0x0a), osmo_tseq(1, 2)))
    for t in (0x60, 0x61, 0x62, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d):
        a(0, msg(DCM, t, ch_no(0x0a), ipa_conn_id()))                                       # ip.access types, normal disc
    return M

def tcp_stream(conn, msgs, per_seg=1, to_bsc=True):
    """Send the IPA framed messages, per_seg of them per TCP segment."""
    i = 0
    while i < len(msgs):
        chunk = msgs[i:i + per_seg]
        i += per_seg
        data = b"".join(ipa(m, s) for s, m in chunk)
        if to_bsc:
            conn.c(data)
        else:
            conn.s(data)

def main(out):
    frames = []
    # BTS (client) -> BSC (server) and back; the direction is not used by RSL
    msgs = build_messages()
    c = Conn(40100)
    c.syn()
    half = len(msgs) // 2
    tcp_stream(c, msgs[:half], 1, True)
    tcp_stream(c, msgs[half:], 1, False)
    # several IPA frames in one TCP segment
    tcp_stream(c, [(0, msg(RLL, 0x08, ch_no(0x0a), link_id(0x00))),
                   (1, msg(RLL, 0x09, ch_no(0x0b), link_id(0x00))),
                   (2, msg(DCM, 0x25, ch_no(0x0c)))], 3, True)
    frames += c.frames

    c2 = Conn(40101, cip=(192, 0, 2, 12))
    c2.syn()
    ip_msgs = build_ipaccess()
    tcp_stream(c2, ip_msgs, 1, True)
    frames += c2.frames

    # RTP/RTCP towards the ip.access media endpoint (dynamic payload 0x62 = AMR)
    rtp = lambda seq: struct.pack(">BBHII", 0x80, 0x62, seq, 160 * seq, 0x1234) + b"\x73\xc0" + bytes(range(30))
    frames.append(udp_frame((192, 0, 2, 77), (192, 0, 2, 11), 16000, 16384, rtp(1), 90))
    frames.append(udp_frame((192, 0, 2, 77), (192, 0, 2, 11), 16000, 16384, rtp(2), 91))

    write(os.path.join(out, "rsl-coverage.pcap"), frames)

    # malformed capture
    mal = []
    c = Conn(40110); c.syn()
    bad = [
        msg(TRXM, 0x1c, cause(b"\x00"), tlv(38, b"")),                     # empty erroneous message (after the fix)
        msg(DCM, 0x21, ch_no(0x0a), act_type(), ch_mode(), tlv(7, b"")),   # encryption information of length 0
        msg(RLL, 0x01, ch_no(0x0a)),                                       # truncated: link id missing
        msg(DCM, 0x21, ch_no(0x0a), bytes([0x03])),                        # truncated act type
        msg(DCM, 0x21, ch_no(0x0a), act_type(), bytes([0x06, 0x20, 0x01])),  # channel mode IE too long
        msg(CCM, 0x12, ch_no(0x90), bytes([18, 0xff])),                    # RACH load longer than the packet
        msg(TRXM, 0x19, bytes([21, 0x40, 0x08])),                          # resource info longer than the packet
        msg(CCM, 0x13, ch_no(0x88), req_ref(), access_delay(), phy_ctx(bytes([0x42, 0x40]))),   # phy ctx claims more
        msg(TRXM, 0x1c, cause(b"\x01"), bytes([38, 0x40]) + msg(RLL, 0x04, ch_no(0x0a))),    # erroneous message cut
        msg(CCM, 0x18, bytes([0x0f])),                                     # nine paging packages, none present
        msg(CCM, 0x18, bytes([0x02]) + bytes([0x10, 0x0c, 0x20, 0x39])),   # package cut short
        msg(RLL, 0x01, ch_no(0x0a), link_id(0), bytes([11, 0x00, 0x40]) + b"\x01"),  # L3 longer than the packet
        msg(TRXM, 0x1a, sys_info_type(0x01), bytes([11, 0x20, 0x00])),
        msg(DCM, 0x21, ch_no(0x0a), act_type(), ch_mode(), bytes([44, 0x10, 0x03, 0x05, 0x40])),   # SACCH info cut
        msg(CCM, 0x1f, ch_no(0x91), cmd_ind(b"\x80")),                     # extended command, one octet
        msg(RLL, 0x01),                                                    # message type only
        bytes([0x02]),                                                     # one octet (type missing)
        msg(DCM, 0x21, ch_no(0x0a), act_type(), ch_mode(), ch_id()[:5]),   # channel id short
    ]
    tcp_stream(c, [(0, m) for m in bad], 1, True)
    mal += c.frames
    # ip.access: IE lengths running past the packet, with the nanoBTS preference
    c = Conn(40111); c.syn()
    bad = [
        msg(IPAD, 0x76, ch_no(0x0a), bytes([0xf6, 0x1c]) + b"\x00" * 10),   # conn stat truncated
        msg(IPAD, 0x71, ch_no(0x0a), bytes([0xf5, 192, 0])),                # local IP truncated
        msg(IPAD, 0x70, bytes([0xf9])),                                     # TV without value
    ]
    tcp_stream(c, [(0, m) for m in bad], 1, True)
    mal += c.frames
    # erroneous message nested with lengths that run past the packet
    def nest(n):
        inner = msg(RLL, 0x04, ch_no(0x0a), link_id(0x03))
        for _ in range(n):
            inner = msg(TRXM, 0x1c, cause(b"\x01"), bytes([38, 0xff]) + inner)
        return inner
    c = Conn(40112); c.syn()
    tcp_stream(c, [(0, nest(40))], 1, True)
    mal += c.frames
    write(os.path.join(out, "rsl-coverage-malformed.pcap"), mal)

if __name__ == "__main__":
    os.makedirs(sys.argv[1], exist_ok=True)
    main(sys.argv[1])
