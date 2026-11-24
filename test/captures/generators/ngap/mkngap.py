#!/usr/bin/env python3
# Generates test/captures/ngap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the NGAP coverage captures: mkngap.py <outdir>
import struct
import os
import sys
from perlib import W

out = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---- transport -----------------------------------------------------------
ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
ETH_R = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
GNB = '192.0.2.1'
AMF = '192.0.2.2'
GPORT = 40000
ASSOC = {'gnb': GNB, 'port': GPORT}

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xffffffff

tsn = {}
def sctp(payload, up, ppid=60, sport=None, dport=None, vtag=None):
    if sport is None: sport, dport = (ASSOC['port'], 38412) if up else (38412, ASSOC['port'])
    if vtag is None: vtag = 0x01020304 if up else 0x05060708
    k = (up, ASSOC['gnb'])
    tsn[k] = tsn.get(k, 0) + 1
    pad = (-len(payload)) % 4
    chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn[k], 0, 0, ppid) + payload + b'\0' * pad
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + chunk)
    hdr = struct.pack('>HHI', sport, dport, vtag) + struct.pack('<I', c)
    return hdr + chunk

def ipv4(payload, up, proto=132):
    gnb = ASSOC['gnb']
    s, d = (gnb, AMF) if up else (AMF, gnb)
    s = bytes(map(int, s.split('.'))); d = bytes(map(int, d.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

frames = []
ifaces = []     # interface of each frame: 0 = Ethernet, 1 = exported PDU
def frame(ngap, up=True, **kw):
    frames.append((ETH if up else ETH_R) + ipv4(sctp(ngap, up, **kw), up)); ifaces.append(0)
def tlv(t, v): return struct.pack('>HH', t, len(v)) + v
def epdu(table, val, payload):
    frames.append(tlv(14, table.encode()) + tlv(32, struct.pack('>I', val)) + tlv(0, b'') + payload); ifaces.append(1)

# ---- NGAP PDU ------------------------------------------------------------
def ie(i, crit, val):
    return W().cint(i, 0, 65535).cint(crit, 0, 2).length(len(val)).raw(val).data()

def msg(ies):
    w = W().bit(0).cint(len(ies), 0, 65535)
    for x in ies: w.raw(x)
    return w.data()

def pdu(kind, proc, val, crit=1):
    w = W().bit(0).cint(kind, 0, 2).cint(proc, 0, 255).cint(crit, 0, 2).length(len(val)).raw(val)
    return w.data()

IMSG, SOUT, UOUT = 0, 1, 2
def send(kind, proc, ies=(), up=True, **kw):
    frame(pdu(kind, proc, msg(list(ies))), up, **kw)


# ---- IE ids (NGAP-Constants.asn) ------------------------------------------
I = dict(AMFName=1, AMF_UE=10, AssistanceData=11, Cause=15, CritDiag=19, DCS=20,
  FiveGSTMSI=26, GlobalRANNodeID=27, HandoverType=29, MessageIdentifier=35, NASC=37,
  NASPDU=38, NGAPMessage=42, NRPPaPDU=46, PagingDRX=50, PagingOrigin=51, PagingPriority=52,
  NASSecPar=39, NumBroadcasts=47, HandoverList=59, ListHORqd=61,
  NotifyList=66, ListHOReq=73, ListSUReq=74, ToReleaseListRelCmd=79, PLMNSupportList=80,
  RANNodeName=82, RAN_UE=85, RelCap=86, RepPeriod=87, ResetType=88, RRCEstCause=90,
  SecurityContext=93, SerialNumber=95, ServedGUAMIList=96, S2T=101, SupportedTAList=102,
  TAIListForPaging=103, TargetID=105, T2S=106, TraceActivation=108, UEAMBR=110,
  UEContextRequest=112, UEPagingIdentity=115, UERadioCapability=117, UERadioCapForPaging=118,
  UESecCap=119, ULI=121, WarningAreaList=122, WarningMessageContents=123, WarningSecInfo=124,
  WarningType=125, AllowedNSSAI=0, AMFSetID=3, ConcurrentWarning=17, DirectFwd=22,
  MaskedIMEISV=34, UL_NGU_UP_TNL=139, PDUSessionType=134, QosFlowSetupRequestList=136,
  PDUSessionAggMBR=130, CurrentQoSParaSetIndex=221, RAT_Information=179,
  UERadioCapEUTRA=265, QosFlowAdditionalInfoList=397, PagingCause=342,
  PDUSessionResourceReleasedListNot=67, RelListRelRes=70, ListSURes=75, RoutingID=89, NRPPa=46, SecondaryRATUsage=142)
REJ, IGN, NOT = 0, 1, 2

# ---- PER value encoders (streaming helpers end in _) -------------------
PLMN = bytes([0x00, 0xf1, 0x10])          # MCC 001 MNC 01
def plmn_(w, p=PLMN): return w.ostr(p, 3, 3)
def tac_(w, t): return w.ostr(t.to_bytes(3, 'big'), 3, 3)
def ext_container(items):
    w = W().cint(len(items), 1, 65535)
    for i, c, v in items:
        w.cint(i, 0, 65535).cint(c, 0, 2).length(len(v)).raw(v)
    return w.data()
def tai_(w, tac=1, plmn=PLMN):
    w.seq(0, [0]); plmn_(w, plmn); tac_(w, tac); return w
def nrcgi_(w, cell=0x123456780, plmn=PLMN):
    w.seq(0, [0]); plmn_(w, plmn); w.bstr(cell, 36, 36, 36); return w
def ecgi_(w, cell=0x1234567, plmn=PLMN):
    w.seq(0, [0]); plmn_(w, plmn); w.bstr(cell, 28, 28, 28); return w
def gnbid_(w, plmn=PLMN, gnb=1):
    w.choice(0, 4); w.seq(0, [0]); plmn_(w, plmn); w.choice(0, 2); w.bstr(gnb, 32, 22, 32); return w
def ngenbid_(w, plmn=PLMN):
    w.choice(1, 4); w.seq(0, [0]); plmn_(w, plmn); w.choice(0, 4); w.bstr(0x12345, 20, 20, 20); return w
def n3iwf_(w, plmn=PLMN):
    w.choice(2, 4); w.seq(0, [0]); plmn_(w, plmn); w.choice(0, 2); w.bstr(0x1234, 16, 16, 16); return w
def printable_(w, s):
    w.bit(0); w.cint(len(s), 1, 150); w.octets(s.encode()); return w
def bitrate_(w, v):
    w.bit(0); return w.cint(v, 0, 4000000000000)
def amf_ue(v): return W().cint(v, 0, 2**40 - 1).data()
def ran_ue(v): return W().cint(v, 0, 2**32 - 1).data()
def nas_pdu(b): return W().ostr(b).data()
def enum(i, n, ext=True): return W().enum(i, n, ext).data()
NROOT = {0: 45, 1: 2, 2: 4, 3: 7, 4: 6}
def cause_(w, kind, idx):
    w.choice(kind, 6); return w.enum(idx, NROOT[kind])
def cause(kind, idx, ext=None):
    w = W().choice(kind, 6)
    return w.enum(idx, NROOT[kind], True, ext).data()
def uli_nr(tac=2, ts=None):
    w = W().choice(1, 4); w.seq(0, [1 if ts else 0, 0]); nrcgi_(w); tai_(w, tac)
    if ts: w.ostr(ts, 4, 4)
    return w.data()
def uli_eutra():
    w = W().choice(0, 4); w.seq(0, [0, 0]); ecgi_(w); tai_(w, 5); return w.data()
def s_nssai_(w, sst=1, sd=None):
    w.seq(0, [1 if sd is not None else 0, 0]); w.ostr(bytes([sst]), 1, 1)
    if sd is not None: w.ostr(sd, 3, 3)
    return w
def supported_ta(items):
    w = W().cint(len(items), 1, 256)
    for tac, rat in items:
        w.seq(0, [1 if rat is not None else 0])
        tac_(w, tac)
        w.cint(1, 1, 12)
        w.seq(0, [0]); plmn_(w)
        w.cint(1, 1, 1024)
        w.seq(0, [0]); s_nssai_(w, 1, b'\x00\x00\x01')
        if rat is not None:
            w.align(); w.raw(ext_container([(I['RAT_Information'], REJ, rat)]))
    return w.data()
def guami_(w):
    w.seq(0, [0]); plmn_(w); w.bstr(1, 8, 8, 8); w.bstr(2, 10, 10, 10); w.bstr(3, 6, 6, 6); return w
def served_guami():
    w = W().cint(1, 1, 256); w.seq(0, [1, 0]); guami_(w); printable_(w, 'backup'); return w.data()
def plmn_support():
    w = W().cint(1, 1, 12); w.seq(0, [0]); plmn_(w); w.cint(1, 1, 1024); w.seq(0, [0]); s_nssai_(w, 1, None); return w.data()
def five_g_s_tmsi_(w, tmsi=0xdeadbeef):
    w.seq(0, [0]); w.bstr(0x155, 10, 10, 10); w.bstr(5, 6, 6, 6); w.ostr(tmsi.to_bytes(4, 'big'), 4, 4); return w
def allowed_nssai():
    w = W().cint(1, 1, 8); w.seq(0, [0]); s_nssai_(w, 1, b'\x00\x00\x02'); return w.data()
def sec16_(w): return w.bstr(0xe000, 16, 16, 16, ext=True)
def uesecap():
    w = W().seq(0, [0]); sec16_(w); sec16_(w); sec16_(w); sec16_(w); return w.data()
def tai_list_paging(tacs):
    w = W().cint(len(tacs), 1, 16)
    for t in tacs: w.seq(0, [0]); tai_(w, t)
    return w.data()
def tla_(w, nbits, value): return w.bstr(value, nbits, 1, 160, ext=True)
def trace_activation(nbits=32):
    w = W().seq(0, [0]); w.ostr(bytes([0x00, 0xf1, 0x10, 0, 0, 1, 0, 2]), 8, 8)
    w.bstr(0xf8, 8, 8, 8); w.enum(2, 6)
    tla_(w, nbits, int.from_bytes(bytes(range(1, 1 + nbits // 8)), 'big')); return w.data()
def uemambr():
    w = W().seq(0, [0]); bitrate_(w, 1000000000); bitrate_(w, 2000000000); return w.data()
def u8(w, v): return w.cint(v, 0, 255)

# ---- HTTP (N2 information over the SBI, 3GPP TS 29.502/29.518) -------------
import json as _json
TCPSTATE = {}
def tcp_frame(payload, up, sport=50000, dport=80, flags=0x18):
    k = (sport, dport)
    st = TCPSTATE.setdefault(k, [1000, 5000])
    s_, d_ = ('192.0.2.10', '192.0.2.11') if up else ('192.0.2.11', '192.0.2.10')
    seq, ack = (st[0], st[1]) if up else (st[1], st[0])
    sp, dp = (sport, dport) if up else (dport, sport)
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = bytes(map(int, s_.split('.'))) + bytes(map(int, d_.split('.'))) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    if up: st[0] += len(payload)
    else: st[1] += len(payload)
    seg = h + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 1, 0, 64, 6, 0, bytes(map(int, s_.split('.'))), bytes(map(int, d_.split('.'))))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    frames.append((ETH if up else ETH_R) + ip + seg); ifaces.append(0)

def http_post(js, parts, path='/nsmf-pdusession/v1/sm-contexts/1/modify'):
    """parts: list of (content-id, binary)"""
    b = b'BOUNDARY'
    body = b'--' + b + b'\r\nContent-Type: application/json\r\n\r\n' + _json.dumps(js).encode()
    for cid, data in parts:
        body += b'\r\n--' + b + b'\r\nContent-Type: application/vnd.3gpp.ngap\r\nContent-Id: ' + cid.encode() + b'\r\n\r\n' + data
    body += b'\r\n--' + b + b'--\r\n'
    hdr = ('POST %s HTTP/1.1\r\nHost: smf.example.com\r\nContent-Type: multipart/related; boundary=BOUNDARY; type="application/json"\r\nContent-Length: %d\r\n\r\n' % (path, len(body))).encode()
    tcp_frame(hdr + body, True)
    tcp_frame(b'HTTP/1.1 204 No Content\r\n\r\n', False)

def n2content(cid, typ=None, msgtype=None):
    d = {'ngapData': {'contentId': cid}}
    if typ: d['ngapIeType'] = typ
    if msgtype is not None: d['ngapMessageType'] = msgtype
    return d

# N2 SM information types and a minimal octet string that each of them decodes
N2GOOD = {
    'PDU_RES_SETUP_REQ': bytes.fromhex('000000'),
    'PDU_RES_SETUP_RSP': bytes.fromhex('000000000000000000000000'),
    'PDU_RES_SETUP_FAIL': bytes.fromhex('0000'),
    'PDU_RES_REL_CMD': bytes.fromhex('0000'),
    'PDU_RES_REL_RSP': bytes.fromhex('00'),
    'PDU_RES_MOD_REQ': bytes.fromhex('000000'),
    'PDU_RES_MOD_RSP': bytes.fromhex('00'),
    'PDU_RES_MOD_FAIL': bytes.fromhex('0000'),
    'PDU_RES_NTY': bytes.fromhex('00'),
    'PDU_RES_NTY_REL': bytes.fromhex('0000'),
    'PDU_RES_MOD_IND': bytes.fromhex('000000000000000000000000'),
    'PDU_RES_MOD_CFM': bytes.fromhex('000000000000000000000000'),
    'PATH_SWITCH_REQ': bytes.fromhex('000000000000000000000000'),
    'PATH_SWITCH_SETUP_FAIL': bytes.fromhex('0000'),
    'PATH_SWITCH_REQ_ACK': bytes.fromhex('00'),
    'PATH_SWITCH_REQ_FAIL': bytes.fromhex('0000'),
    'HANDOVER_REQUIRED': bytes.fromhex('00'),
    'HANDOVER_CMD': bytes.fromhex('00'),
    'HANDOVER_PREP_FAIL': bytes.fromhex('0000'),
    'HANDOVER_REQ_ACK': bytes.fromhex('000000000000000000000000'),
    'HANDOVER_RES_ALLOC_FAIL': bytes.fromhex('0000'),
    'SECONDARY_RAT_USAGE': bytes.fromhex('00'),
    'PDU_RES_MOD_IND_FAIL': bytes.fromhex('0000'),
    'UE_CONTEXT_RESUME_REQ': bytes.fromhex('00'),
    'UE_CONTEXT_RESUME_RSP': bytes.fromhex('00'),
    'UE_CONTEXT_SUSPEND_REQ': bytes.fromhex('00'),
    'SRC_TO_TAR_CONTAINER': bytes.fromhex('00'),
    'TAR_TO_SRC_CONTAINER': bytes.fromhex('00'),
    'TAR_TO_SRC_FAIL_CONTAINER': bytes.fromhex('00'),
    'RAN_STATUS_TRANS_CONTAINER': bytes.fromhex('000000000000000000000000'),
    'NRPPA_PDU': bytes.fromhex('00'),
    'PC5_QOS_PARA': bytes.fromhex('000000000000'),
    'EARLY_STATUS_TRANS_CONTAINER': bytes.fromhex('0000000000000000'),
    'UE_RADIO_CAPABILITY_FOR_PAGING': bytes.fromhex('00'),
    'MBS_SES_REQ': bytes.fromhex('000000'),
    'MBS_SES_RSP': bytes.fromhex('00'),
    'MBS_SES_FAIL': bytes.fromhex('0000'),
    'MBS_SES_REL_RSP': bytes.fromhex('00'),
    'BC_TRA_REQ': bytes.fromhex('00000000000000000000000000000000'),
    'BC_TRA_RSP': bytes.fromhex('0000000000000000'),
    'BC_TRA_FAIL': bytes.fromhex('000000000000000000000000'),
    'MBS_SES_ACT_REQ': bytes.fromhex('0000000000000000'),
    'MBS_SES_DEACT_REQ': bytes.fromhex('0000000000000000'),
    'MBS_SES_UPD_REQ': bytes.fromhex('000000'),
}

PROC = {
 'imsg': [0,64,1,66,67,75,68,80,2,65,3,69,70,4,5,6,63,7,8,9,10,11,12,13,61,14,15,18,16,17,78,71,72,73,74,19,20,21,81,22,23,24,25,26,27,30,28,29,31,32,33,34,35,57,79,36,55,37,52,76,77,38,39,40,41,42,58,59,56,43,60,44,45,46,47,48,62,49,50,51,53,54,82,83,84,85,86],
 'sout': [0,66,67,68,80,69,70,10,12,13,14,78,71,72,73,20,21,81,25,26,27,28,29,32,35,76,40,41,58,59,43,60,51,82,84,85],
 'uout': [0,66,68,80,69,12,13,14,78,71,73,21,81,25,35,76,40,58,59,82,84],
}


def write_pcapng(name, frs, ifs):
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    o = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    o += blk(1, struct.pack('<HHI', 1, 0, 262144))
    o += blk(1, struct.pack('<HHI', 252, 0, 262144))
    for i, (fr, itf) in enumerate(zip(frs, ifs)):
        ts = (1700000000 + i) * 1000000
        o += blk(6, struct.pack('<IIIII', itf, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(os.path.join(out, name), 'wb').write(o)

def write_pcap(name, frs):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

NAS_REG = bytes.fromhex('7e00440b')                              # 5GMM registration reject
NAS_CFG = bytes.fromhex('7e0054')                              # 5GMM configuration update command

def frames_main():
    # --- association setup: NGSetup (also learns that the sender is a gNB)
    g = W().raw(b'')
    gw = gnbid_(W())
    send(IMSG, 21, [
        ie(I['GlobalRANNodeID'], REJ, gw.data()),
        ie(I['RANNodeName'], IGN, printable_(W(), 'gnb-one').data()),
        ie(I['SupportedTAList'], REJ, supported_ta([(1, None), (2, enum(1, 2)), (3, enum(0, 2))])),
        ie(21, IGN, enum(2, 4)),
    ])
    send(SOUT, 21, [
        ie(I['AMFName'], REJ, printable_(W(), 'amf-one').data()),
        ie(I['ServedGUAMIList'], REJ, served_guami()),
        ie(I['RelCap'], IGN, W().cint(255, 0, 255).data()),
        ie(I['PLMNSupportList'], REJ, plmn_support()),
    ], up=False)
    # --- initial UE message on the NB-IoT tracking area (TAC 2): the UE is remembered as NB-IoT
    send(IMSG, 15, [
        ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['NASPDU'], REJ, nas_pdu(NAS_REG)),
        ie(I['ULI'], REJ, uli_nr(2, b'\xe9\x00\x00\x00')),
        ie(I['RRCEstCause'], IGN, enum(3, 10)),
        ie(I['FiveGSTMSI'], REJ, five_g_s_tmsi_(W()).data()),
        ie(I['AMFSetID'], IGN, W().bstr(0x155, 10, 10, 10).data()),
        ie(I['UEContextRequest'], IGN, enum(0, 1)),
        ie(I['AllowedNSSAI'], REJ, allowed_nssai()),
    ])
    send(IMSG, 44, [
        ie(I['AMF_UE'], REJ, amf_ue(100)),
        ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['UERadioCapability'], IGN, W().ostr(b'\x00\x00').data()),
    ])
    send(IMSG, 4, [
        ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['NASPDU'], REJ, nas_pdu(NAS_CFG)),
    ], up=False)
    send(IMSG, 46, [
        ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['NASPDU'], REJ, nas_pdu(NAS_CFG)), ie(I['ULI'], IGN, uli_eutra()),
    ])
    for kind, idx, ex in [(0, 15, None), (0, 0, 0), (1, 0, None), (2, 2, None), (3, 6, None), (4, 4, None)]:
        send(IMSG, 9, [ie(I['Cause'], IGN, cause(kind, idx, ex)), ie(I['AMF_UE'], IGN, amf_ue(1))], up=False)

    # --- handover preparation (RRC container decoded as the sender is a gNB)
    global TID, S2T, t2s_b
    tid = W().choice(0, 3); tid.seq(0, [0]); gnbid_(tid, gnb=2); tai_(tid, 9)
    s2t = W().seq(0, [0, 0, 0, 0]); s2t.ostr(bytes(4)); s2t.choice(0, 3); nrcgi_(s2t)
    s2t.cint(1, 1, 16); s2t.seq(0, [0]); s2t.choice(0, 5); s2t.seq(0, [0, 0, 0]); s2t.choice(0, 3); nrcgi_(s2t)
    s2t.seq(0, [0]); s2t.enum(1, 4); s2t.cint(30, 0, 4095)
    TID, S2T = tid, s2t
    lst = W().cint(1, 1, 256).seq(0, [0]).cint(5, 0, 255); lst.length(1); lst.raw(b'\x00')
    send(IMSG, 12, [
        ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['HandoverType'], REJ, enum(0, 3)),
        ie(I['Cause'], IGN, cause(0, 16)),
        ie(I['TargetID'], REJ, tid.data()),
        ie(I['ListHORqd'], REJ, lst.data()),
        ie(I['S2T'], REJ, W().ostr(s2t.data()).data()),
    ])
    t2s = W().seq(0, [0]); t2s.ostr(b'\x00\x00')
    t2s_b = t2s.data()
    send(SOUT, 12, [
        ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['HandoverType'], REJ, enum(0, 3)),
        ie(I['NASSecPar'], REJ, W().ostr(bytes(4)).data()),
        ie(I['T2S'], REJ, W().ostr(t2s.data()).data()),
    ], up=False)
    send(IMSG, 24, [
        ie(I['UEPagingIdentity'], IGN, five_g_s_tmsi_(W().choice(0, 2)).data()),
        ie(I['PagingDRX'], IGN, enum(1, 4)),
        ie(I['TAIListForPaging'], IGN, tai_list_paging([1, 2])),
        ie(I['PagingPriority'], IGN, enum(2, 8)),
        ie(I['PagingOrigin'], IGN, enum(0, 1)),
    ], up=False)
    send(IMSG, 20, [ie(I['Cause'], IGN, cause(4, 1)), ie(I['ResetType'], REJ, W().choice(0, 3).enum(0, 1).data())])
    for nb in (32, 128, 160):
        send(IMSG, 39, [
            ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
            ie(I['TraceActivation'], IGN, trace_activation(nb))], up=False)

    # --- PDU session resource setup / release / notify with N2 SM transfers
    def qos_item(w, qfi, fiveqi):
        w.seq(0, [0, 0]); w.bit(0); w.cint(qfi, 0, 63)
        w.seq(0, [0, 0, 0, 0]); w.choice(0, 3)
        w.seq(0, [0, 0, 0, 0]); w.bit(0); w.cint(fiveqi, 0, 255)
        w.seq(0, [0]); w.cint(8, 1, 15); w.enum(1, 2); w.enum(1, 2)
        return w
    def setup_transfer(nbits):
        qi = W().cint(1, 1, 64); qos_item(qi, 1, 9)
        gtp = W().choice(0, 2); gtp.seq(0, [0]); tla_(gtp, nbits, int.from_bytes(bytes(range(10, 10 + nbits // 8)), 'big')); gtp.ostr(b'\x00\x00\x10\x01', 4, 4)
        agg = W().seq(0, [0]); bitrate_(agg, 5000000); bitrate_(agg, 6000000)
        return msg([ie(I['PDUSessionAggMBR'], REJ, agg.data()),
                    ie(I['UL_NGU_UP_TNL'], REJ, gtp.data()),
                    ie(I['PDUSessionType'], REJ, enum(0, 5)),
                    ie(I['QosFlowSetupRequestList'], REJ, qi.data())])
    for nb in (32, 128, 160):
        item = W().cint(1, 1, 256); item.seq(0, [1, 0]); item.cint(1, 0, 255); item.ostr(NAS_CFG)
        s_nssai_(item, 1, None); item.ostr(setup_transfer(nb))
        send(IMSG, 29, [
            ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
            ie(I['ListSUReq'], REJ, item.data()), ie(I['UEAMBR'], IGN, uemambr())], up=False)
    rel = W().seq(0, [1]); cause_(rel, 4, 5)
    li = W().cint(1, 1, 64).seq(0, [1, 0]).bit(0).cint(2, 0, 63).ostr(b'\x01\x02')
    rel.align(); rel.raw(ext_container([(I['QosFlowAdditionalInfoList'], IGN, li.data())]))
    item = W().cint(1, 1, 256).seq(0, [0]).cint(1, 0, 255).ostr(rel.data())
    send(IMSG, 28, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['ToReleaseListRelCmd'], REJ, item.data())], up=False)
    rr = W().seq(0, [1]); rr.align(); rr.raw(ext_container([(I['QosFlowAdditionalInfoList'], IGN, li.data())]))
    item = W().cint(1, 1, 256).seq(0, [0]).cint(1, 0, 255).ostr(rr.data())
    send(SOUT, 28, [ie(I['AMF_UE'], IGN, amf_ue(100)), ie(I['RAN_UE'], IGN, ran_ue(7)),
        ie(I['RelListRelRes'], IGN, item.data()), ie(I['ULI'], IGN, uli_nr(1))])
    # notify transfer: QoS flow notify item with the current QoS parameter set index (AlternativeQoSParaSetNotifyIndex)
    nt = W().seq(0, [1, 0, 0]); nt.cint(1, 1, 64)
    nt.seq(0, [1]); nt.bit(0); nt.cint(3, 0, 63); nt.enum(1, 2)
    nt.align(); nt.raw(ext_container([(I['CurrentQoSParaSetIndex'], IGN, W().bit(0).cint(2, 0, 8).data())]))
    item = W().cint(1, 1, 256).seq(0, [0]).cint(1, 0, 255).ostr(nt.data())
    send(IMSG, 30, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['NotifyList'], REJ, item.data()), ie(I['ULI'], IGN, uli_nr(1))])
    # --- warning messages (cell broadcast data coding scheme and pages)
    page = bytes([0x41 | 0x00] * 20) + bytes(62) + bytes([20])
    wmc = bytes([2]) + page + page
    wai = W().choice(3, 5).cint(1, 1, 65535).ostr(b'\x00\x00\x01', 3, 3)
    send(IMSG, 51, [
        ie(I['MessageIdentifier'], REJ, W().bstr(0x1112, 16, 16, 16).data()),
        ie(I['SerialNumber'], REJ, W().bstr(0x3456, 16, 16, 16).data()),
        ie(I['WarningAreaList'], IGN, wai.data()),
        ie(I['RepPeriod'], REJ, W().cint(30, 0, 131071).data()),
        ie(I['NumBroadcasts'], REJ, W().cint(5, 0, 65535).data()),
        ie(I['WarningType'], IGN, W().ostr(b'\x00\x80', 2, 2).data()),
        ie(I['DCS'], IGN, W().bstr(0x0f, 8, 8, 8).data()),
        ie(I['WarningMessageContents'], IGN, W().cint(len(wmc), 1, 9600).octets(wmc).data()),
    ], up=False)

    # --- handover request towards a gNB: NAS container, security, setup list
    tr = setup_transfer(32)
    def ho_req(ho_type, nasc, s2t_bytes):
        it = W().cint(1, 1, 256); it.seq(0, [0]); it.cint(1, 0, 255); s_nssai_(it, 1, None); it.ostr(tr)
        sc = W().seq(0, [0]); sc.cint(3, 0, 7); sc.bstr(0, 256, 256, 256)
        return [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['HandoverType'], REJ, enum(ho_type, 3)),
            ie(I['Cause'], IGN, cause(0, 16)), ie(I['UEAMBR'], REJ, uemambr()),
            ie(I['UESecCap'], REJ, uesecap()), ie(I['SecurityContext'], REJ, sc.data()),
            ie(I['NASC'], REJ, nas_pdu(nasc)), ie(I['ListHOReq'], REJ, it.data()),
            ie(I['AllowedNSSAI'], REJ, allowed_nssai()),
            ie(I['TraceActivation'], IGN, trace_activation(32)),
            ie(I['MaskedIMEISV'], IGN, W().bstr(0x1122334455667788, 64, 64, 64).data()),
            ie(I['S2T'], REJ, W().ostr(s2t_bytes).data())]
    send(IMSG, 13, ho_req(0, bytes(8), s2t.data()), up=False)
    send(IMSG, 13, ho_req(2, bytes(7), s2t.data()), up=False)
    # --- UE radio capability for paging, NRPPa transport, nested NGAP message, private message
    urcp = W().seq(0, [1, 1, 0]); urcp.ostr(b'\x00\x00'); urcp.ostr(b'\x00\x00')
    send(IMSG, 44, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(8)),
        ie(I['UERadioCapForPaging'], IGN, urcp.data()),
        ie(I['UERadioCapEUTRA'], IGN, W().ostr(b'\x00\x00').data())])
    send(IMSG, 50, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(8)),
        ie(I['RoutingID'], REJ, W().ostr(b'\x01').data()),
        ie(I['NRPPa'], REJ, W().ostr(b'\x00\x00\x40\x03\x00\x00\x00').data())])
    inner = pdu(IMSG, 36, msg([ie(I['RAN_UE'], REJ, ran_ue(9))]))
    mid = pdu(IMSG, 36, msg([ie(I['NGAPMessage'], REJ, W().ostr(inner).data())]))
    send(IMSG, 36, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['NGAPMessage'], REJ, W().ostr(mid).data())], up=False)
    # --- location report / rrc state with a time stamped NR location
    send(IMSG, 37, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(92, IGN, enum(0, 2)), ie(I['ULI'], IGN, uli_nr(4, b'\xe9\x00\x00\x00'))])

    # --- paging with assistance data, CE-capable UE data and NB-IoT paging capabilities
    adr = W().seq(0, [1, 0, 0]); adr.seq(0, [0]); adr.seq(0, [0]); adr.cint(1, 1, 16); adr.seq(0, [1, 0]); adr.choice(0, 3)
    nrcgi_(adr); adr.cint(77, 0, 4095)
    ce = W().seq(0, [0]); ecgi_(ce); ce.ostr(b'\x00\x00')
    nbio = W().seq(0, [0, 0, 1]); nbio.align(); nbio.raw(ext_container([(214, IGN, W().ostr(b'\x00\x00').data())]))
    send(IMSG, 24, [
        ie(I['UEPagingIdentity'], IGN, five_g_s_tmsi_(W().choice(0, 2)).data()),
        ie(I['TAIListForPaging'], IGN, tai_list_paging([1])),
        ie(I['UERadioCapForPaging'], IGN, nbio.data()),
        ie(I['AssistanceData'], IGN, adr.data()),
        ie(207, IGN, ce.data())], up=False)
    # --- unknown protocol extension in a TAI, radio capability of a non NB-IoT UE
    ux = W().choice(1, 4); ux.seq(0, [0, 0]); nrcgi_(ux)
    ux.seq(0, [1]); plmn_(ux); tac_(ux, 6); ux.align(); ux.raw(ext_container([(9999, IGN, b'\x01\x02')]))
    send(IMSG, 46, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(99)), ie(I['ULI'], IGN, ux.data())])
    send(IMSG, 44, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(99)),
        ie(I['UERadioCapability'], IGN, W().ostr(b'\x00\x00').data())])
    # --- handover command towards a 5GS to UTRAN handover (RRC container decoded by the RRC dissector)
    send(SOUT, 12, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['RAN_UE'], REJ, ran_ue(7)),
        ie(I['HandoverType'], REJ, W().enum(0, 3, True, 0).data()), ie(I['T2S'], REJ, W().ostr(bytes(8)).data())], up=False)
    # --- exported PDUs: message and IE dissectors reached without dissect_ngap()
    epdu('ngap.proc.imsg', 0, b'\x00\x00\x00')
    epdu('ngap.ies', 26, five_g_s_tmsi_(W()).data())
    # --- second gNB: a handover required before its NG setup, then the NG setup
    ASSOC['gnb'] = '192.0.2.3'; ASSOC['port'] = 40001
    send(IMSG, 12, [
        ie(I['AMF_UE'], REJ, amf_ue(200)), ie(I['RAN_UE'], REJ, ran_ue(17)),
        ie(I['HandoverType'], REJ, enum(0, 3)), ie(I['Cause'], IGN, cause(0, 16)),
        ie(I['TargetID'], REJ, tid.data()), ie(I['ListHORqd'], REJ, lst.data()),
        ie(I['S2T'], REJ, W().ostr(s2t.data()).data())])
    send(IMSG, 21, [
        ie(I['GlobalRANNodeID'], REJ, ngenbid_(W()).data()),
        ie(I['SupportedTAList'], REJ, supported_ta([(1, None)])),
        ie(21, IGN, enum(0, 4))])
    send(IMSG, 12, [
        ie(I['AMF_UE'], REJ, amf_ue(200)), ie(I['RAN_UE'], REJ, ran_ue(17)),
        ie(I['HandoverType'], REJ, enum(0, 3)), ie(I['Cause'], IGN, cause(0, 16)),
        ie(I['TargetID'], REJ, tid.data()), ie(I['ListHORqd'], REJ, lst.data()),
        ie(I['S2T'], REJ, W().ostr(s2t.data()).data())])
    ASSOC['gnb'] = GNB; ASSOC['port'] = GPORT

    # --- N2 information carried over HTTP: every JSON container the dissector knows
    global TCPSTATE
    z = bytes(8)
    def setup_rsp():
        w = W().seq(0, [0, 0, 0, 0]); w.seq(0, [0]); w.choice(0, 2); w.seq(0, [0]); tla_(w, 32, 0x0a0b0c0d); w.ostr(b'\x00\x00\x20\x01', 4, 4)
        w.cint(1, 1, 64); w.seq(0, [0, 0]); w.bit(0); w.cint(1, 0, 63)
        return w.data()
    def sm(cid, typ, blob, key='smInfo', cls='SM', top='n2InfoContainer', content='n2InfoContent'):
        js = {top: {'n2InformationClass': cls, key: {'n2InfoContent': n2content(cid, typ)}}}
        if cls == 'NRPPa': js[top] = {'n2InformationClass': cls, 'nrppaInfo': {'nrppaPdu': n2content(cid, typ)}}
        http_post(js, [(cid, blob)])
    for typ, blob in N2GOOD.items():
        http_post({'n2SmInfo': {'contentId': 'x1'}, 'n2SmInfoType': typ}, [('x1', blob)])
    sm('n1', 'PDU_RES_SETUP_REQ', setup_transfer(128))
    sm('n2', 'PDU_RES_REL_CMD', rel.data())
    sm('n3', 'PDU_RES_NTY', nt.data())
    sm('r1', 'SRC_TO_TAR_CONTAINER', s2t.data(), key='ranInfo', cls='RAN')
    sm('r2', 'TAR_TO_SRC_CONTAINER', t2s.data(), key='ranInfo', cls='RAN')
    sm('p1', 'NRPPA_PDU', b'\x00\x00\x40\x03\x00\x00\x00', cls='NRPPa')
    http_post({'n2InfoContainer': {'n2InformationClass': 'PWS', 'pwsInfo': {'pwsContainer': n2content('w1', msgtype=51)}}},
              [('w1', pdu(IMSG, 51, msg([ie(I['DCS'], IGN, W().bstr(0x0f, 8, 8, 8).data())])))])
    http_post({'n2SmInfo': {'contentId': 'm1'}, 'n2SmInfoType': 'PDU_RES_SETUP_RSP'}, [('m1', setup_rsp())])
    http_post({'n2SmInfo': {'contentId': 'm2'}}, [('m2', z)])
    http_post({'n2MbsSmInfo': n2content('b1', 'MBS_SES_REQ')}, [('b1', z)])
    http_post({'pduSessionList': [{'n2InfoContent': n2content('l0', 'PDU_RES_REL_RSP')}, {'n2InfoContent': n2content('l1', 'PDU_RES_MOD_REQ')}]},
              [('l1', z)])
    http_post({'sourceToTargetData': n2content('s1', 'SRC_TO_TAR_CONTAINER'), 'targetToSourceData': n2content('t1', 'TAR_TO_SRC_CONTAINER')}, [('s1', s2t.data())])
    http_post({'targetToSourceFailureData': n2content('f1', 'TAR_TO_SRC_FAIL_CONTAINER')}, [('f1', z)])
    http_post({'ueRadioCapability': n2content('c1', 'UE_RADIO_CAPABILITY')}, [('c1', W().ostr(b'\x00\x00').data())])
    http_post({'ueNbiotRadioCapability': n2content('c2', 'UE_RADIO_CAPABILITY')}, [('c2', W().ostr(b'\x00\x00').data())])
    http_post({'ueRadioCapabilityForPaging': n2content('c3', 'UE_RADIO_CAPABILITY_FOR_PAGING')}, [('c3', urcp.data())])
    http_post({'n2InfoContainer': {'n2InformationClass': 'RAN', 'ranInfo': {'n2InfoContent': n2content('e1')}}}, [('e1', z)])
    http_post({'n2InfoContainer': {'n2InformationClass': 'RAN', 'ranInfo': {'n2InfoContent': n2content('e2', msgtype=21)}}}, [('e2', pdu(IMSG, 21, msg([])))])

def frames_malformed():
    global frames, ifaces
    # PrivateMessage with a private IE nobody knows ("Unknown Open Type")
    pm = W().bit(0).cint(1, 1, 65535).bit(0).cint(5, 0, 65535).cint(1, 0, 2).length(2).raw(b'\xab\xcd')
    frame(pdu(IMSG, 31, pm.data()))
    # reproducer: RerouteNASRequest whose NGAP-Message holds another one, 300 levels deep
    m = pdu(IMSG, 36, msg([]))
    for _ in range(300):
        m = pdu(IMSG, 36, msg([ie(I['NGAPMessage'], REJ, W().ostr(m).data())]))
    frame(m)
    # more than 15 warning pages
    page = bytes([0x41] * 20) + bytes(62) + bytes([20])
    wmc = bytes([16]) + page * 16
    send(IMSG, 51, [ie(I['DCS'], IGN, W().bstr(0x0f, 8, 8, 8).data()),
        ie(I['WarningMessageContents'], IGN, W().cint(len(wmc), 1, 9600).octets(wmc).data())], up=False)
    # NAS transparent container too short, truncated NAS PDU, bad RRC container
    send(IMSG, 13, [ie(I['NASC'], REJ, nas_pdu(bytes(5)))], up=False)
    send(IMSG, 4, [ie(I['NASPDU'], REJ, nas_pdu(bytes.fromhex('7e0041')))], up=False)
    send(IMSG, 44, [ie(I['UERadioCapability'], IGN, W().ostr(b'\xff').data())])
    # truncated messages: every prefix of a handover required with containers
    good = pdu(IMSG, 12, msg([ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['HandoverType'], REJ, enum(0, 3)),
        ie(I['TargetID'], REJ, TID.data()), ie(I['S2T'], REJ, W().ostr(S2T.data()).data())]))
    for cut in (len(good) - 1, len(good) - 9, len(good) - 30, 12, 9, 6, 3):
        frame(good[:cut])
    # PDU with an unknown choice (extension) and an empty PDU
    frame(b'\x70')
    frame(b'\x00')
    # message type that has no dissector (unknown procedure code)
    frame(pdu(IMSG, 200, msg([])))
    # a nested NGAP message at the limit, with a time stamp in the NR location
    send(IMSG, 15, [ie(I['RAN_UE'], REJ, ran_ue(1)), ie(I['ULI'], REJ, uli_nr(2, b'\xff\xff\xff\xff'))])
    # NG setup response with a truncated GUAMI list
    send(SOUT, 21, [ie(I['ServedGUAMIList'], REJ, served_guami()[:6])], up=False)

    # source/target containers of the other handover types (the contents do not decode)
    for ht in (W().enum(1, 3).data(), W().enum(0, 3, True, 0).data()):
        send(IMSG, 12, [ie(I['HandoverType'], REJ, ht), ie(I['S2T'], REJ, W().ostr(bytes(8)).data())])
        send(SOUT, 12, [ie(I['HandoverType'], REJ, ht), ie(I['T2S'], REJ, W().ostr(bytes(8)).data())], up=False)
    send(UOUT, 12, [ie(I['HandoverType'], REJ, enum(0, 3)), ie(I['Cause'], IGN, cause(1, 1))], up=False)
    # a target to source container in a procedure other than the handover preparation
    send(IMSG, 13, [ie(I['T2S'], REJ, W().ostr(t2s_b).data())], up=False)
    # ng-eNB node: handover command with LTE RRC container
    ASSOC['gnb'] = '192.0.2.4'; ASSOC['port'] = 40002
    send(IMSG, 21, [ie(I['GlobalRANNodeID'], REJ, ngenbid_(W()).data())])
    send(SOUT, 12, [ie(I['AMF_UE'], REJ, amf_ue(100)), ie(I['HandoverType'], REJ, enum(0, 3)), ie(I['T2S'], REJ, W().ostr(t2s_b).data())], up=False)
    ASSOC['gnb'] = GNB; ASSOC['port'] = GPORT
    # a RAN status container whose contents do not decode, over HTTP
    http_post({'n2InfoContainer': {'n2InformationClass': 'RAN', 'ranInfo': {'n2InfoContent': n2content('r3', 'RAN_STATUS_TRANS_CONTAINER')}}}, [('r3', bytes(8))])
    http_post({'n2SmInfo': {'contentId': 'm1'}, 'n2SmInfoType': 'PDU_RES_SETUP_RSP'}, [('m1', bytes(8))])
    # exported PDU for a message with no stats tap, with a bad payload
    epdu('ngap.ies', 26, b'\x00')

if __name__ == '__main__':
    frames_main()
    for k, procs_ in PROC.items():
        kind = {'imsg': IMSG, 'sout': SOUT, 'uout': UOUT}[k]
        for p in procs_:
            if k == 'imsg' and p == 31:
                continue
            send(kind, p, up=(p % 2 == 0))
    write_pcapng('ngap-coverage.pcapng', frames, ifaces)
    n_main = len(frames)
    frames, ifaces = [], []
    frames_malformed()
    write_pcapng('ngap-coverage-malformed.pcapng', frames, ifaces)
    print(n_main, 'main frames,', len(frames), 'malformed frames')
    sys.exit(0)
    print(len(frames), 'frames')
