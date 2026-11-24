#!/usr/bin/env python3
# Generates test/captures/docsis_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DOCSIS dissectors
packet-docsis.c (DOCSIS MAC frames), packet-docsis-tlv.c (configuration
file / registration TLVs) and packet-docsis-vendor.c (Vendor Specific
Information Field, VSIF).

The DOCSIS MAC frames use LINKTYPE_DOCSIS (143) with a computed HCS (and
fragment CRC-32). The TLV dissector is reached in two ways a real
capture reaches it: inside REG-REQ / REG-RSP MAC management messages,
and as whole DOCSIS configuration files carried in Exported PDU frames
(LINKTYPE_WIRESHARK_UPPER_PDU, 252) for the "docsis_tlv" dissector
(there is no wiretap reader for DOCSIS configuration files). A few VSIF
blobs go straight to "docsis_vsif" the same way.

TLVSPEC lists, for each TLV walking function of packet-docsis-tlv.c, the
sub-TLV types with the value length the code accepts (or the function
that takes the value). It was produced from the dissector source with
extract_tlvspec.py and then edited by hand; this script does not read
the Wireshark sources. Every packet is built from scratch with struct;
nothing comes from a real network.

Usage: mkdocsis.py <output directory>

Writes:
  docsis-coverage.pcapng            the main capture (no malformed
                                    packets, no error expert infos)
  docsis-coverage-malformed.pcapng  bad HCS / CRC, wrong lengths,
                                    every TLV with a wrong length, the
                                    original reproducers that only
                                    decode with errors
"""

import os
import struct
import sys
import zlib

LT_DOCSIS = 143
LT_UPPER_PDU = 252

CM = bytes.fromhex('020000000002')
CMTS = bytes.fromhex('020000000001')
BCAST = b'\xff' * 6


# --------------------------------------------------------------------------
# Generic helpers

def crc16_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def tlv(t, v):
    assert len(v) <= 255, (t, len(v))
    return bytes([t, len(v)]) + v


def num(n, v=1):
    """n octets, big endian value v."""
    return v.to_bytes(n, 'big')


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_eth(dst, src, payload, sport=4000, dport=5000):
    """Ethernet II / IPv4 / UDP, no FCS."""
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('>H', ip_csum(ip)) + ip[12:]
    return dst + src + b'\x08\x00' + ip + u


# --------------------------------------------------------------------------
# DOCSIS MAC frames (packet-docsis.c)

def mac_hdr(fc, parm, length, ehdr=b''):
    """FC, MAC_PARM (EHDR_LEN when EHDR_ON), LEN, EHDR, HCS."""
    h = bytes([fc, parm]) + struct.pack('>H', length) + ehdr
    return h + struct.pack('<H', crc16_x25(h))


def fc(fctype, fcparm, exthdr=0):
    return (fctype << 6) | (fcparm << 1) | exthdr


def pdu(fctype, fcparm, payload, ehdr=b'', parm=None):
    ext = 1 if ehdr else 0
    if parm is None:
        parm = len(ehdr) if ehdr else 0
    return mac_hdr(fc(fctype, fcparm, ext), parm, len(ehdr) + len(payload), ehdr) + payload


def frag(ehdr, payload):
    """Fragmentation MAC frame: LEN covers the EHDR, the fragment and the
    fragment CRC-32 (the dissector reads LEN after the HCS)."""
    ext = 1 if ehdr else 0
    h = bytes([fc(3, 3, ext), len(ehdr)]) + struct.pack('>H', len(payload) + 4) + ehdr
    h += struct.pack('<H', crc16_x25(h))
    body = h + payload
    return body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)


def eh(t, v):
    return bytes([(t << 4) | len(v)]) + v


def bp_up(sid, flags=None, seq=0, keyseq=1, ver=1, bpi=False, toggle=False, slots=0):
    b0 = (keyseq << 4) | ver
    s = sid & 0x3fff
    if bpi:
        s |= 0x8000
    if toggle:
        s |= 0x4000
    v = bytes([b0]) + struct.pack('>H', s) + bytes([slots])
    if flags is not None:
        v += bytes([flags | seq])
    return eh(3, v)


def mgmt(mtype, payload, version=1, dst=CMTS, src=CM, rsvd=0):
    return (dst + src + struct.pack('>H', 6 + len(payload)) +
            bytes([0, 0, 3, version, mtype, rsvd]) + payload)


def macmgmt_frame(mtype, payload, version=1, dst=CMTS, src=CM):
    return pdu(3, 1, mgmt(mtype, payload, version, dst, src))


# --------------------------------------------------------------------------
# TLV specification for packet-docsis-tlv.c
# value: int (fixed length), list of ints (each accepted length), 's'
# (string), 'b' (bytes), '@func' (sub-TLVs of that function, or a helper
# that takes a fixed layout), 'call' (handed to another dissector).

TLVSPEC = {
    'phs_err': [
        (1, 1),  # PHS_ERR_PARAM
        (2, 1),  # PHS_ERR_CODE
        (3, 's'),  # PHS_ERR_MSG
    ],
    'phs': [
        (1, 1),  # PHS_CLSFR_REF
        (2, 2),  # PHS_CLSFR_ID
        (3, 2),  # PHS_SFLOW_REF
        (4, 4),  # PHS_SFLOW_ID
        (5, 1),  # PHS_DSC_ACTION
        (6, '@phs_err'),  # PHS_ERRORS
        (7, 'b'),  # PHS_FIELD
        (8, 1),  # PHS_INDEX
        (9, 'b'),  # PHS_MASK
        (10, 1),  # PHS_SUP_SIZE
        (11, 1),  # PHS_VERIFICATION
        (13, 1),  # PHS_DBC_ACTION
        (43, 'b'),  # PHS_VENDOR_SPEC
    ],
    'sflow_err': [
        (1, 1),  # SFW_ERR_PARAM
        (2, 1),  # SFW_ERR_CODE
        (3, 's'),  # SFW_ERR_MSG
    ],
    'downstream_sflow': [
        (14, 4),  # SFW_MAX_DOWN_LAT
        (17, 1),  # SFW_DOWN_RESEQ
    ],
    'upstream_sflow': [
        (14, 2),  # SFW_MAX_CONCAT_BURST
        (15, 1),  # SFW_SCHEDULING_TYPE
        (16, '@reqxmit_policy'),  # SFW_REQ_XMIT_POL
        (17, 4),  # SFW_NOM_POLL_INT
        (18, 4),  # SFW_POLL_JTTR_TOL
        (19, 2),  # SFW_UG_SIZE
        (20, 4),  # SFW_NOM_GRNT_INTV
        (21, 4),  # SFW_GRNT_JTTR_TOL
        (22, 1),  # SFW_GRNTS_PER_INTV
        (24, 4),  # SFW_UG_TIME_REF
        (25, 1),  # SFW_CONTENTION_REQ_BACKOFF_WINDOW_MULT
        (26, 1),  # SFW_NUM_OF_BYTES_REQUESTED_MULT
    ],
    'sflow': [
        (1, 2),  # SFW_REF
        (2, 4),  # SFW_ID
        (3, 2),  # SFW_SID
        (4, 's'),  # SFW_SERVICE_CLASS_NAME
        (5, '@sflow_err'),  # SFW_ERRORS
        (6, 1),  # SFW_QOS_SET_TYPE
        (7, 1),  # SFW_TRAF_PRI
        (8, 4),  # SFW_MAX_SUSTAINED
        (9, 4),  # SFW_MAX_BURST
        (10, 4),  # SFW_MIN_RSVD_TRAF
        (11, 2),  # SFW_MIN_RSVD_PACKETSIZE
        (12, 2),  # SFW_ACTIVE_QOS_TIMEOUT
        (13, 2),  # SFW_ADMITT_QOS_TIMEOUT
        (23, 2),  # SFW_IP_TOS_OVERWRITE
        (27, 4),  # SFW_PEAK_TRAFFIC_RATE
        (31, 4),  # SFW_REQUIRED_ATTRIBUTE_MASK
        (32, 4),  # SFW_FORBIDDEN_ATTRIBUTE_MASK
        (33, 4),  # SFW_ATTRIBUTE_AGGREGATION_RULE_MASK
        (43, 'b'),  # SFW_VENDOR_SPEC
    ],
    'dot1q_clsfr': [
        (1, 2),  # CFR_D1Q_USER_PRI
        (2, 2),  # CFR_D1Q_VLAN_ID
        (43, 'b'),  # CFR_D1Q_VENDOR_SPEC
    ],
    'eth_clsfr': [
        (1, 6),  # CFR_ETH_DST_MAC
        (2, 6),  # CFR_ETH_SRC_MAC
        (3, 3),  # CFR_ETH_DSAP
    ],
    'clsfr_err': [
        (1, [1, 2]),  # CFR_ERR_PARAM
        (2, 1),  # CFR_ERR_CODE
        (3, 's'),  # CFR_ERR_MSG
    ],
    'ip_classifier': [
        (1, 3),  # CFR_IP_TOS_RANGE_MASK
        (2, 2),  # CFR_IP_PROTO
        (3, 4),  # CFR_IP_SOURCE_ADDR
        (4, 4),  # CFR_IP_SOURCE_MASK
        (5, 4),  # CFR_IP_DEST_ADDR
        (6, 4),  # CFR_IP_DEST_MASK
        (7, 2),  # CFR_IP_SRCPORT_START
        (8, 2),  # CFR_IP_SRCPORT_END
        (9, 2),  # CFR_IP_DSTPORT_START
        (10, 2),  # CFR_IP_DSTPORT_END
    ],
    'ip6_classifier': [
        (1, '@ip6_classifier_tc'),  # CFR_IP6_TRAFFIC_CLASS
        (2, 4),  # CFR_IP6_FLOW_LABEL
        (3, 2),  # CFR_IP6_NEXT_HEADER
        (4, 16),  # CFR_IP6_SOURCE_ADDR
        (5, 1),  # CFR_IP6_SOURCE_PREFIX_LENGTH
        (6, 16),  # CFR_IP6_DESTINATION_ADDR
        (7, 1),  # CFR_IP6_DESTINATION_PREFIX_LENGTH
    ],
    'classifiers': [
        (1, 1),  # CFR_REF
        (2, 2),  # CFR_ID
        (3, 2),  # CFR_SFLOW_REF
        (4, 4),  # CFR_SFLOW_ID
        (5, 1),  # CFR_RULE_PRI
        (6, 1),  # CFR_ACT_STATE
        (7, 1),  # CFR_DSA_ACTION
        (8, '@clsfr_err'),  # CFR_ERROR
        (9, '@ip_classifier'),  # CFR_IP_CLASSIFIER
        (12, '@ip6_classifier'),  # CFR_IP6_CLASSIFIER
        (10, '@eth_clsfr'),  # CFR_ETH_CLASSIFIER
        (11, '@dot1q_clsfr'),  # CFR_8021Q_CLASSIFIER
        (43, 'b'),  # CFR_VENDOR_SPEC
    ],
    'doc10cos': [
        (1, 1),  # 1
        (2, 2),  # 2
    ],
    'modemcap': [
        (1, 1),  # CAP_CONCAT
        (2, 1),  # CAP_DOCSIS_VER
        (3, 1),  # CAP_FRAG
        (4, 1),  # CAP_PHS
        (5, 1),  # CAP_IGMP
        (6, 1),  # CAP_PRIVACY
        (7, 1),  # CAP_DOWN_SAID
        (8, 1),  # CAP_UP_SID
        (9, 1),  # CAP_OPT_FILT
        (10, 1),  # CAP_XMIT_EQPERSYM
        (11, 1),  # CAP_NUM_XMIT_EQ_TAPS
        (12, 1),  # CAP_DCC
        (13, 2),  # CAP_IP_FILTERS
        (14, 2),  # CAP_LLC_FILTERS
        (15, 1),  # CAP_EXP_UNICAST_SID
        (16, 4),  # CAP_RNG_HOFF
        (17, 'b'),  # CAP_L2VPN
        (18, 'b'),  # CAP_L2VPN_ESAFE
        (19, 'b'),  # CAP_DUT_FILTERING
        (20, 1),  # CAP_US_FREQ_RNG
        (21, 1),  # CAP_US_SRATE
        (22, 1),  # CAP_SAC
        (23, 1),  # CAP_CODE_HOP_M2
        (24, 1),  # CAP_MTC
        (25, 1),  # CAP_512_MSPS_UTC
        (26, 1),  # CAP_256_MSPS_UTC
        (27, 1),  # CAP_TOTAL_SID_CLUST
        (28, 1),  # CAP_SID_PER_SF
        (29, 1),  # CAP_MRC
        (30, 1),  # CAP_TOTAL_DSID
        (31, 1),  # CAP_RESEQ_DSID
        (32, 1),  # CAP_MC_DSID
        (33, 1),  # CAP_MC_DSID_FWD
        (34, 1),  # CAP_FCTYPE_FWD
        (35, 1),  # CAP_DPV
        (36, 1),  # CAP_UGS
        (37, 1),  # CAP_MAP_UCD
        (38, 2),  # CAP_UDC
        (39, 1),  # CAP_IPV6
        (40, 1),  # CAP_EXT_US_TRNS_PWR
        (44, 4),  # CAP_EM
        (46, 1),  # CAP_CM_STATUS_ACK
        (47, 4),  # CAP_EM_PREF
        (48, 2),  # CAP_EXT_PKT_LEN_SUP_CAP
        (49, 1),  # CAP_OFDM_MULT_RECV_CHAN_SUP
        (50, 1),  # CAP_OFDMA_MULT_TRANS_CHAN_SUP
        (51, 1),  # CAP_DOWN_OFDM_PROF_SUP
        (52, 2),  # CAP_DOWN_OFDM_CHAN_SUBC_QAM_MOD_SUP
        (53, 2),  # CAP_UP_OFDMA_CHAN_SUBC_QAM_MOD_SUP
        (54, 1),  # CAP_DOWN_LOWER_BAND_EDGE_CONF
        (55, 1),  # CAP_DOWN_UPPER_BAND_EDGE_CONF
        (56, 1),  # CAP_DIPL_UP_UPPER_BAND_EDGE_CONF
        (57, 1),  # CAP_DOCSIS_TIME_PROT_MODE
        (58, 1),  # CAP_DOCSIS_TIME_PROT_PERF_SUP
        (59, 2),  # CAP_PMAX
        (60, 1),  # CAP_DIPL_DOWN_LOWER_BAND_EDGE
        (61, 1),  # CAP_DIPL_DOWN_UPPER_BAND_EDGE
        (62, 1),  # CAP_DIPL_UP_UPPER_BAND_EDGE
        (63, 1),  # CAP_ADVANCED_BAND_PLAN
        (74, 1),  # CAP_EXTENDED_SF_SID_CLUSTER_ASSIGN
        (76, 1),  # CAP_LOW_LATENCY_SUP
        (79, 2),  # CAP_ADVANCED_DOWN_LOWER_BAND_EDGE_CONF
        (80, 2),  # CAP_ADVANCED_DOWN_UPPER_BAND_EDGE_CONF
        (81, 2),  # CAP_ADVANCED_UP_UPPER_BAND_EDGE_CONF
        (82, 4),  # CAP_ADVANCED_DOWN_LOWER_BAND_EDGE_OPTIONS_LIST
        (83, 4),  # CAP_ADVANCED_DOWN_UPPER_BAND_EDGE_OPTIONS_LIST
        (84, 4),  # CAP_ADVANCED_UP_UPPER_BAND_EDGE_OPTIONS_LIST
        (85, 1),  # CAP_EXTENDED_POWER_OPTIONS
    ],
    'cos': [
        (1, 1),  # COS_CLASSID
        (2, 4),  # COS_MAX_DOWN
        (3, 4),  # COS_MAX_UP
        (4, 1),  # COS_UP_CH_PRIO
        (5, 4),  # COS_MIN_UP_RATE
        (6, 2),  # COS_MAX_UP_BURST
        (7, 1),  # COS_BP_ENABLE
    ],
    'snmpv3_kickstart': [
        (1, 's'),  # SNMPV3_SEC_NAME
        (2, 'b'),  # SNMPV3_MGR_PUB_NUM
    ],
    'ds_ch_list_single': [
        (1, 2),  # SINGLE_CH_TIMEOUT
        (2, 4),  # SINGLE_CH_FREQ
    ],
    'ds_ch_list_range': [
        (1, 2),  # FREQ_RNG_TIMEOUT
        (2, 4),  # FREQ_RNG_START
        (3, 4),  # FREQ_RNG_END
        (4, 4),  # FREQ_RNG_STEP
    ],
    'dut_filter': [
        (1, 1),  # DUT_CONTROL
        (2, 'b'),  # DUT_CMIM
    ],
    'ds_ch_list': [
        (1, '@ds_ch_list_single'),  # DS_CH_LIST_SINGLE
        (2, '@ds_ch_list_range'),  # DS_CH_LIST_RANGE
        (3, 2),  # DS_CH_LIST_DEFAULT_TIMEOUT
    ],
    'tcc_err': [
        (1, 'b'),  # TCC_ERR_SUBTYPE
        (2, 1),  # TCC_ERR_CODE
        (3, 's'),  # TCC_ERR_MSG
    ],
    'tcc_rng_parms': [
        (1, 1),  # RNG_PARMS_US_CH_ID
        (2, 4),  # RNG_PARMS_TIME_OFF_INT
        (3, 1),  # RNG_PARMS_TIME_OFF_FRAC
        (4, 1),  # RNG_PARMS_POWER_OFF
        (5, 1),  # RNG_PARMS_FREQ_OFF
    ],
    'sid_cl_so_crit': [
        (1, 1),  # SID_CL_SO_MAX_REQ
        (2, 4),  # SID_CL_SO_MAX_OUT_BYTES
        (3, 4),  # SID_CL_SO_MAX_REQ_BYTES
        (4, 2),  # SID_CL_SO_MAX_TIME
    ],
    'sid_cl_enc_map': [
        (1, 1),  # SID_CL_MAP_US_CH_ID
        (2, 2),  # SID_CL_MAP_SID
        (3, 1),  # SID_CL_MAP_ACTION
    ],
    'sid_cl_enc': [
        (1, 1),  # SID_CL_ENC_ID
        (2, '@sid_cl_enc_map'),  # SID_CL_ENC_MAP
    ],
    'sid_cl': [
        (1, 4),  # SID_CL_SF_ID
        (2, '@sid_cl_enc'),  # SID_CL_ENC
        (3, '@sid_cl_so_crit'),  # SID_CL_SO_CRIT
    ],
    'tcc': [
        (1, 1),  # TLV_TCC_REFID
        (2, 1),  # TLV_TCC_US_CH_ACTION
        (3, 1),  # TLV_TCC_US_CH_ID
        (4, 1),  # TLV_TCC_NEW_US_CH_ID
        (5, 'call'),  # TLV_TCC_UCD
        (6, 2),  # TLV_TCC_RNG_SID
        (7, 1),  # TLV_TCC_INIT_TECH
        (8, '@tcc_rng_parms'),  # TLV_TCC_RNG_PARMS
        (9, 1),  # TLV_TCC_DYN_RNG_WIN
        (10, 1),  # TLV_TCC_P1_6HI
        (11, '@tcc_oudp'),  # TLV_TCC_ASSIGN_OFDMA_UP_DATA_PROF
        (14, 1),  # TLV_TCC_EXTENDED_DRW
        (15, 2),  # TLV_TCC_EXTENDED_US_RNG_PWR
        (16, 2),  # TLV_TCC_OUDP_SOUNDING_SID
        (254, '@tcc_err'),  # TLV_TCC_ERR
    ],
    'ch_bl_rng': [
        (1, 4),  # CH_BL_RNG_MIN_CTR_FREQ
        (2, 4),  # CH_BL_RNG_MAX_CTR_FREQ
    ],
    'rcp_rcv_mod': [
        (1, 1),  # RCV_MOD_ENC_IDX
        (2, 1),  # RCV_MOD_ENC_ADJ_CH
        (3, '@ch_bl_rng'),  # RCV_MOD_ENC_CH_BL_RNG
        (4, 4),  # RCV_MOD_ENC_CTR_FREQ_ASGN
        (5, 'b'),  # RCV_MOD_ENC_RSQ_CH_SUBS_CAP
        (6, 'b'),  # RCV_MOD_ENC_CONN
        (7, 'b'),  # RCV_MOD_ENC_PHY_LAYR_PARMS
    ],
    'rcp_rcv_ch': [
        (1, 1),  # RCV_CH_IDX
        (2, 'b'),  # RCV_CH_CONN
        (3, 1),  # RCV_CH_CONN_OFF
        (5, 1),  # RCV_CH_PRIM_DS_CH_IND
    ],
    'rcp': [
        (1, 5),  # TLV_RCP_ID
        (2, 'b'),  # TLV_RCP_NAME
        (3, 1),  # TLV_RCP_FREQ_SPC
        (4, '@rcp_rcv_mod'),  # TLV_RCP_RCV_MOD_ENC
        (5, '@rcp_rcv_ch'),  # TLV_RCP_RCV_CH
        (43, 'call'),  # TLV_RCP_VEN_SPEC
    ],
    'rcc_rcv_mod': [
        (1, 1),  # RCV_MOD_ENC_IDX
        (4, 4),  # RCV_MOD_ENC_CTR_FREQ_ASGN
        (6, 'b'),  # RCV_MOD_ENC_CONN
    ],
    'rcc_rcv_ch': [
        (1, 1),  # RCV_CH_IDX
        (2, 'b'),  # RCV_CH_CONN
        (4, 4),  # RCV_CH_CTR_FREQ_ASGN
        (5, 1),  # RCV_CH_PRIM_DS_CH_IND
    ],
    'rcc_srcc_ds_prof_assign': [
        (1, 1),  # RCC_SRCC_DS_PROF_ASSIGN_DCID
        (2, '@rcc_srcc_ds_prof_assign_prof_list'),  # RCC_SRCC_DS_PROF_ASSIGN_PROF_LIST
    ],
    'rcc_srcc': [
        (1, '@rcc_srcc_prim_ds_ch_assign'),  # RCC_SRCC_PRIM_DS_CHAN_ASSIGN
        (2, '@rcc_srcc_ds_ch_assign'),  # RCC_SRCC_DS_CHAN_ASSIGN
        (3, '@rcc_srcc_ds_prof_assign'),  # RCC_SRCC_DS_PROF_ASSIGN
    ],
    'rcc_err': [
        (1, 1),  # RCC_ERR_MOD_OR_CH
        (2, 1),  # RCC_ERR_IDX
        (3, 1),  # RCC_ERR_PARAM
        (4, 1),  # RCC_ERR_CODE
        (5, 'b'),  # RCC_ERR_MSG
    ],
    'rcc': [
        (1, 5),  # TLV_RCP_ID
        (4, '@rcc_rcv_mod'),  # TLV_RCP_RCV_MOD_ENC
        (5, '@rcc_rcv_ch'),  # TLV_RCP_RCV_CH
        (43, 'call'),  # TLV_RCP_VEN_SPEC
        (6, '@rcc_partial_serv_down_chan'),  # TLV_RCC_PARTIAL_SERV_DOWN_CHAN
        (7, '@rcc_srcc'),  # TLV_RCC_SRCC
        (8, 1),  # TLV_RCC_PRIM_DOWN_CHAN
        (254, '@rcc_err'),  # TLV_RCC_ERR
    ],
    'dsid_ds_reseq': [
        (1, 1),  # DS_RESEQ_DSID
        (2, 'b'),  # DS_RESEQ_CH_LST
        (3, 1),  # DS_RESEQ_WAIT_TIME
        (4, 1),  # DS_RESEQ_WARN_THRESH
        (5, 2),  # DS_RESEQ_HO_TIMER
    ],
    'dsid_mc_addr': [
        (1, 1),  # MC_ADDR_ACTION
        (2, 6),  # MC_ADDR_ADDR
    ],
    'dsid_mc': [
        (1, '@dsid_mc_addr'),  # TLV_DSID_MC_ADDR
        (2, 'b'),  # TLV_DSID_MC_CMIM
        (3, 'b'),  # TLV_DSID_MC_GROUP
        (26, '@phs'),  # TLV_DSID_MC_PHS
    ],
    'dsid': [
        (1, 3),  # TLV_DSID_ID
        (2, 1),  # TLV_DSID_ACTION
        (3, '@dsid_ds_reseq'),  # TLV_DSID_DS_RESEQ
        (4, '@dsid_mc'),  # TLV_DSID_MC
    ],
    'sec_assoc': [
        (1, 1),  # TLV_SEC_ASSOC_ACTION
        (2, 14),  # TLV_SEC_ASSOC_DESC
    ],
    'ch_asgn': [
        (1, 1),  # TLV_CH_ASGN_US_CH_ID
        (2, 4),  # TLV_CH_ASGN_RX_FREQ
    ],
    'cmts_mc_sess_enc': [
        (1, [4, 16]),  # CMTS_MC_SESS_ENC_GRP
        (2, [4, 16]),  # CMTS_MC_SESS_ENC_SRC
        (3, 'b'),  # CMTS_MC_SESS_ENC_CMIM
    ],
    'fdx_tg_assignment': [
        (1, 1),  # TLV_FDX_TG_ASSIGNMENT_TG_ID
        (2, 1),  # TLV_FDX_TG_ASSIGNMENT_RBA_TYPE
        (3, 'call'),  # TLV_FDX_TG_ASSIGNMENT_RBA_MESSAGE
    ],
    'docsis_tlv': [
        (1, '@doc10cos'),  # TLV_DOWN_FREQ
        (2, 1),  # TLV_CHNL_ID
        (3, 1),  # TLV_NET_ACCESS
        (4, '@cos'),  # TLV_COS
        (5, '@modemcap'),  # TLV_MODEM_CAP
        (6, 16),  # TLV_CM_MIC
        (7, 16),  # TLV_CMTS_MIC
        (8, 3),  # TLV_VENDOR_ID
        (9, 's'),  # TLV_SW_UPG_FILE
        (10, 'b'),  # TLV_SNMP_WRITE_CTRL
        (11, 'b'),  # TLV_SNMP_OBJECT
        (12, 4),  # TLV_MODEM_IP
        (13, '@svc_unavail'),  # TLV_SVC_UNAVAIL
        (14, 6),  # TLV_ETHERNET_MAC
        (15, '?'),  # TLV_TEL_SETTINGS
        (17, 'b'),  # TLV_BPI_CONFIG
        (18, 1),  # TLV_MAX_CPES
        (19, 4),  # TLV_TFTP_TIME
        (20, 4),  # TLV_TFTP_MODEM_ADDRESS
        (21, 4),  # TLV_SW_UPG_SRVR
        (22, '@classifiers'),  # TLV_UPSTREAM_CLASSIFIER
        (23, '@classifiers'),  # TLV_DOWN_CLASSIFIER
        (24, '@sflow'),  # TLV_UPSTREAM_SERVICE_FLOW
        (25, '@sflow'),  # TLV_DOWN_SERVICE_FLOW
        (26, '@phs'),  # TLV_PHS
        (27, 20),  # TLV_HMAC_DIGEST
        (28, 2),  # TLV_MAX_CLASSIFIERS
        (29, 1),  # TLV_PRIVACY_ENABLE
        (30, 'b'),  # TLV_AUTH_BLOCK
        (31, 1),  # TLV_KEY_SEQ_NUM
        (32, 'b'),  # TLV_MFGR_CVC
        (33, 'b'),  # TLV_COSIGN_CVC
        (34, '@snmpv3_kickstart'),  # TLV_SNMPV3_KICKSTART
        (35, 'b'),  # TLV_SUBS_MGMT_CTRL
        (36, 8),  # TLV_SUBS_MGMT_CPE
        (37, 'b'),  # TLV_SUBS_MGMT_FLTR
        (38, 'b'),  # TLV_SNMPV3_NTFY_RCVR
        (39, 1),  # TLV_ENABLE_20_MODE
        (40, 1),  # TLV_ENABLE_TEST_MODES
        (41, '@ds_ch_list'),  # TLV_DS_CH_LIST
        (42, 6),  # TLV_MC_MAC_ADDRESS
        (43, '@docsis_extension_field'),  # TLV_DOCSIS_EXTENSION_FIELD
        (44, '@vendor_specific_capabilities'),  # TLV_VENDOR_SPEC
        (45, '@dut_filter'),  # TLV_DUT_FILTER
        (46, '@tcc'),  # TLV_TCC
        (47, '@sid_cl'),  # TLV_SID_CL
        (48, '@rcp'),  # TLV_RCP
        (49, '@rcc'),  # TLV_RCC
        (50, '@dsid'),  # TLV_DSID
        (51, '@sec_assoc'),  # TLV_SEC_ASSOC
        (52, 2),  # TLV_INIT_CH_TIMEOUT
        (56, '@ch_asgn'),  # TLV_CH_ASGN
        (57, 1),  # TLV_CM_INIT_REASON
        (58, 16),  # TLV_SW_UPG_SRVR_IPV6
        (59, 16),  # TLV_TFTP_PROV_CM_IPV6_ADDR
        (60, 'b'),  # TLV_US_DROP_CLFY
        (61, 'b'),  # TLV_SUBS_MGMT_IPV6_LST
        (62, 'b'),  # TLV_US_DROP_CLFY_GROUP_ID
        (63, 2),  # TLV_SUBS_MGMT_CTRL_MAX_CPE_IPV6
        (64, '@cmts_mc_sess_enc'),  # TLV_CMTS_MC_SESS_ENC
        (75, 1),  # TLV_EM_MODE_INDICATOR
        (78, '@em_id_list_for_cm'),  # TLV_EM_ID_LIST_FOR_CM
        (85, '@fdx_tg_assignment'),  # TLV_FDX_TG_ASSIGNMENT
        (86, 1),  # TLV_FDX_RESET
        (255, '?'),  # TLV_END
    ],
}

# Helpers without sub-TLVs: fixed value layouts
HELPERS = {
    'reqxmit_policy': num(4, 0x1ff),
    'ip6_classifier_tc': bytes([0x10, 0x20, 0xfc]),
    'svc_unavail': bytes([3, 1, 2]),
    'tcc_oudp': bytes([5, 6, 13]),
    'em_id_list_for_cm': bytes([0, 1, 0, 2]),
    'rcc_partial_serv_down_chan': bytes([1, 2, 3]),
    'rcc_srcc_prim_ds_ch_assign': bytes([1]),
    'rcc_srcc_ds_ch_assign': bytes([2, 3, 4]),
    'rcc_srcc_ds_prof_assign_prof_list': bytes([0, 1, 2]),
}

STRING = b'docsis'
BYTES = bytes([0x01, 0x02, 0x03, 0x04])
UNKNOWN_TYPE = 200      # not used by any TLV walker


def ucd(chid, tlvs):
    """UCD body: upstream channel id, configuration change count, mini-slot
    size, downstream channel id, then channel TLVs."""
    return bytes([chid, 1, 4, 1]) + tlvs


UCD_SMALL = ucd(1, tlv(1, b'\x08') + tlv(2, num(4, 20000000)))


def rba():
    # TG id, CCC, DCID, control, RBA time, expiration, 2 sub-bands
    return bytes([1, 1, 1, 0xc0]) + num(4, 1000) + num(4, 2000) + bytes([2, 0, 1])


def vsif_cisco():
    # IP Precedence last: after it the dissector skips the length of its
    # last sub-TLV once more
    return (tlv(8, b'\x00\x00\x0c') + tlv(0x0a, b'\x02') +
            tlv(0x80, b'ios.cfg') + tlv(0x05, b'\x00') +
            tlv(0x0b, tlv(1, b'\x05') + tlv(2, b'\x32')))


def vsif_gex():
    v6 = bytes.fromhex('20010db8000000000000000000000000')
    v4 = bytes([192, 0, 2, 0])
    mc4 = bytes([232, 1, 1, 0])
    mc6 = bytes.fromhex('ff3e0000000000000000000000000000')
    out = tlv(8, b'\xff\xff\xff')
    out += tlv(1, num(4, 7)) + tlv(2, num(1, 2)) + tlv(3, num(2, 3)) + tlv(4, num(4, 0x10001))
    out += tlv(5, BYTES)
    out += tlv(6, tlv(1, b'\x02') + tlv(2, b'\xff\x00\x00\x00') + tlv(3, b'\x06') + tlv(9, b'\x00'))
    out += tlv(7, tlv(1, b'savgroup') +
               tlv(2, tlv(1, v4) + tlv(2, b'\x18') + tlv(9, b'\x00')) +
               tlv(2, tlv(1, v6) + tlv(2, b'\x20')) + tlv(9, b'\x00'))
    out += tlv(9, tlv(1, num(4, 1)) + tlv(2, num(4, 2)) + tlv(3, num(4, 4)) +
               tlv(4, num(4, 8)) + tlv(9, b'\x00'))
    out += tlv(10, tlv(1, b'mcprofile') +
               tlv(2, tlv(1, b'\x01') + tlv(2, b'\x01') + tlv(3, v4) + tlv(4, b'\x18') +
                   tlv(5, mc4) + tlv(6, b'\x18') + tlv(9, b'\x00')) +
               tlv(2, tlv(3, v6) + tlv(4, b'\x20') + tlv(5, mc6) + tlv(6, b'\x10')) +
               tlv(3, num(2, 16)) + tlv(9, b'\x00'))
    out += tlv(11, b'svc-type') + tlv(12, b'\x00')
    return out


def vsif_unknown():
    return tlv(8, b'\x00\x10\x95') + tlv(1, b'\x01')


class Gen:
    """Build valid sub-TLVs for every case of a TLV walking function."""

    def __init__(self, spec):
        self.spec = spec

    def values(self, k, ctx):
        if isinstance(k, int):
            return [num(k)]
        if isinstance(k, list):
            return [num(n) for n in k]
        if k == 's':
            return [STRING]
        if k == 'b':
            return [BYTES]
        if k.startswith('@'):
            f = k[1:]
            if f in HELPERS:
                return [HELPERS[f]]
            return None     # sub-TLVs, handled by items()
        raise ValueError(k)

    def items(self, fn, ctx=None):
        """List of encoded sub-TLVs covering every case of fn."""
        out = []
        cases = list(self.spec[fn])
        if fn == 'sflow':
            cases += self.spec['upstream_sflow' if ctx == 24 else 'downstream_sflow']
        for t, k in cases:
            sub = self.special(fn, t, k, ctx)
            if sub is not None:
                out += sub
                continue
            vals = self.values(k, ctx)
            if vals is None:
                out += self.wrap(t, self.items(k[1:], t))
            else:
                out += [tlv(t, v) for v in vals]
        if fn not in NO_UNKNOWN:
            out.append(tlv(UNKNOWN_TYPE, b'\x00\x01'))
        return out

    def special(self, fn, t, k, ctx):
        if k == 'call':
            if fn in ('rcp', 'rcc') and t == 43:
                return [tlv(43, vsif_gex()[:5] + tlv(1, num(4, 9)))]
            if fn == 'fdx_tg_assignment' and t == 3:
                return [tlv(3, rba())]
            if fn == 'tcc' and t == 5:
                return [tlv(5, UCD_SMALL)]
            raise ValueError((fn, t))
        if fn == 'docsis_tlv':
            if t == 1:      # downstream frequency, ranging technique, DOCSIS 1.0 CoS
                return ([tlv(1, num(4, 453000000)), tlv(1, b'\x01')] +
                        self.wrap(1, self.items('doc10cos')))
            if t in (43, 44):
                return [tlv(t, vsif_cisco()), tlv(t, vsif_gex()), tlv(t, vsif_unknown())]
            if t == 15:
                return [tlv(15, b'')]
            if t == 255:
                return []
            if t in (22, 23, 24, 25):
                return self.wrap(t, self.items(k[1:], t))
        if fn == 'sflow' and ctx == 24 and t == 26:
            # multiplier 1 and 16
            return [tlv(26, b'\x01'), tlv(26, b'\x10')]
        if fn == 'tcc' and t == 3:
            return [tlv(3, b'\x01')]
        if fn == 'sid_cl_enc' and t == 2:
            # the map must be exactly 10 octets long
            return [tlv(2, tlv(1, b'\x01') + tlv(2, num(2, 0x22)) + tlv(3, b'\x01')),
                    tlv(2, tlv(1, b'\x02') + tlv(UNKNOWN_TYPE, b'\x00\x01') + tlv(3, b'\x02'))]
        return None

    @staticmethod
    def wrap(t, items):
        """Pack sub-TLVs into as many type t TLVs as needed (255 octets
        each at most)."""
        out, cur = [], b''
        for it in items:
            if len(cur) + len(it) > 255:
                out.append(tlv(t, cur))
                cur = b''
            cur += it
        if cur or not out:
            out.append(tlv(t, cur))
        return out


NO_UNKNOWN = {'upstream_sflow', 'downstream_sflow', 'sid_cl_enc_map'}


def chunk(tlvs, size):
    """Split a list of top-level TLVs into groups of about size octets."""
    out, cur = [], b''
    for t in tlvs:
        if cur and len(cur) + len(t) > size:
            out.append(cur)
            cur = b''
        cur += t
    if cur:
        out.append(cur)
    return out


# --------------------------------------------------------------------------
# Exported PDU and pcapng

def exp_pdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def pcapng_write(fn, pkts, linktypes):
    def block(t, body):
        pad = (-len(body)) % 4
        ln = 12 + len(body) + pad
        return struct.pack('<II', t, ln) + body + b'\0' * pad + struct.pack('<I', ln)
    with open(fn, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in linktypes:
            f.write(block(1, struct.pack('<HHI', lt, 0, 262144)))
        for i, (ifc, data) in enumerate(pkts):
            ts = (1700000000 + i) * 1000000
            f.write(block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                         len(data), len(data)) + data))


class Cap:
    def __init__(self):
        self.pkts = []

    def docsis(self, b):
        self.pkts.append((0, b))

    def tlvfile(self, b, name='docsis_tlv'):
        self.pkts.append((1, exp_pdu(name, b)))

    def write(self, fn):
        pcapng_write(fn, self.pkts, [LT_DOCSIS, LT_UPPER_PDU])


class BadGen(Gen):
    """Every fixed-length case with a wrong length (malformed capture)."""

    def items(self, fn, ctx=None):
        out = []
        cases = list(self.spec[fn])
        if fn == 'sflow':
            cases += self.spec['upstream_sflow' if ctx == 24 else 'downstream_sflow']
        for t, k in cases:
            if fn == 'docsis_tlv' and t in (1, 15, 255, 43, 44):
                continue
            if isinstance(k, int):
                out.append(tlv(t, num(k + 1)))
            elif isinstance(k, list):
                out.append(tlv(t, num(max(k) + 1)))
            elif isinstance(k, str) and k.startswith('@') and k[1:] in self.spec:
                out += self.wrap(t, self.items(k[1:], t))
            elif isinstance(k, str) and k.startswith('@') and k[1:] == 'svc_unavail':
                out.append(tlv(t, b'\x01\x02'))
        return out


# --------------------------------------------------------------------------
# Main capture contents

def docsis_frames(cap):
    """packet-docsis.c: every FC type and parameter, every extended
    header element, encrypted frames, request frames, fragmentation."""
    sid = struct.pack('>H', 0x0123)
    eth = udp_eth(BCAST, CM, b'DOCSIS packet PDU payload')

    # 1 Packet PDU without extended header, Ethernet payload
    cap.docsis(pdu(0, 0, eth))
    # 2 Packet PDU with every extended header element type
    ehdr = (eh(1, b'\x05' + sid) + eh(2, sid) + bp_up(0x0123) +
            eh(4, b'\x11\x00\x10\x00') + eh(5, b'\x01') + eh(5, b'\x01\x22') +
            eh(6, b'\x02\x33') + eh(6, b'\x02') + eh(7, b'\x11\x01\x23') +
            eh(8, b'\x40') + eh(8, b'\x40\x00\x01') + eh(8, b'\x5a\x00\x01\x00\x07') +
            eh(9, b'\x01\x00\x00\x10\x00') + eh(9, b'\x01\x00') + eh(10, b'\xaa\xbb') +
            eh(0, b''))
    cap.docsis(pdu(0, 0, eth, ehdr))
    # 3 Packet PDU with the Extended EH element (type and length octets)
    cap.docsis(pdu(0, 0, eth, b'\xf0' + bytes([7, 3]) + b'\x01\x02\x03'))
    # 4 Packet PDU, downstream privacy with encryption on
    cap.docsis(pdu(0, 0, eth[:12] + b'\x5a' * 40, eh(4, b'\x11\x80\x10\x00')))
    # 5 Special Use PDU carrying a MAC management message (no EHDR)
    cap.docsis(pdu(1, 1, mgmt(1, num(4, 0x12345678), dst=BCAST, src=CMTS)))
    # 6 Special Use PDU, reserved parameter: data
    cap.docsis(pdu(1, 2, b'\x01\x02\x03\x04'))
    # 7 Special Use PDU with an EHDR: data
    cap.docsis(pdu(1, 1, b'\x01\x02\x03\x04', eh(1, b'\x05' + sid)))
    # 8 Isolation PDU, Ethernet payload
    cap.docsis(pdu(2, 0, eth))
    # 9 Isolation PDU, encrypted
    cap.docsis(pdu(2, 0, eth[:12] + b'\x5a' * 40, eh(4, b'\x11\x80\x10\x00')))
    # 10 Timing header (SYNC)
    cap.docsis(pdu(3, 0, mgmt(1, num(4, 0x01020304), dst=BCAST, src=CMTS)))
    # 11 Timing header, encrypted
    cap.docsis(pdu(3, 0, mgmt(1, num(4, 0x01020304), dst=BCAST, src=CMTS),
                   eh(4, b'\x11\x80\x10\x00')))
    # 12 MAC management with a privacy EH, not encrypted (REG-REQ)
    cap.docsis(pdu(3, 1, mgmt(6, sid + tlv(3, b'\x01')), eh(4, b'\x11\x00\x10\x00')))
    # 13 MAC management, encrypted
    cap.docsis(pdu(3, 1, mgmt(6, sid + tlv(3, b'\x01')), eh(4, b'\x11\x80\x10\x00')))
    # 14 Request frame: MAC_PARM = mini-slots, LEN = SID
    cap.docsis(mac_hdr(fc(3, 2), 5, 0x0123))
    # 15 Queue-depth based request: 7 octet header
    h = bytes([fc(3, 4)]) + struct.pack('>HH', 300, 0x0123)
    cap.docsis(h + struct.pack('<H', crc16_x25(h)))
    # 16 Concatenation header
    cap.docsis(mac_hdr(fc(3, 0x1c), 2, 0))
    # 17 Unknown MAC-specific parameter
    cap.docsis(mac_hdr(fc(3, 5), 0, 0))

    # 18-20 Fragmentation: three fragments of one Ethernet frame (SID 0x0123)
    big = udp_eth(BCAST, CM, bytes(range(256))[:120])
    a, b, c = big[:50], big[50:100], big[100:]
    cap.docsis(frag(bp_up(0x0123, 0x20, 0), a))
    cap.docsis(frag(bp_up(0x0123, 0x00, 1), b))
    cap.docsis(frag(bp_up(0x0123, 0x10, 2), c))
    # 21-22 Encrypted fragments (SID 0x0124): reassembled, shown encrypted
    enc = big[:12] + b'\x5a' * 60
    cap.docsis(frag(bp_up(0x0124, 0x20, 0, bpi=True, toggle=True), enc[:36]))
    cap.docsis(frag(bp_up(0x0124, 0x10, 1, bpi=True, toggle=True), enc[36:]))
    # 23 Packet PDU with an extended header of 255 octets (header length
    #    261 does not wrap): the MAC management message starts after it
    ehdr = eh(0, bytes(14)) * 17
    m = mgmt(7, struct.pack('>HB', 0x0261, 0) + tlv(3, b'\x01'))
    cap.docsis(mac_hdr(fc(3, 1, 1), 255, 255 + len(m), ehdr) + m)


def frag_reproducers(cap):
    """docsis_frag_state.py and docsis_frag_sid.py."""
    # docsis_frag_state: frame 2 has no BP_UP element
    cap.docsis(frag(bp_up(0x0100, 0x20, 3), b'\xAA' * 20))
    cap.docsis(frag(b'', b'\xBB' * 20))
    cap.docsis(frag(bp_up(0x0200, 0x20, 7), b'\xCC' * 20))
    # docsis_frag_sid: SIDs 0x0101 and 0x0102 must not be joined
    e = (b'\xff' * 6 + bytes.fromhex('020000000001') + b'\x08\x00' +
         bytes.fromhex('4500002e0001000040110000c0000201c0000202') +
         struct.pack('>HHHH', 1234, 5678, 26, 0) + b'X' * 18)
    half = len(e) // 2
    cap.docsis(frag(bp_up(0x0101, 0x20, 0), e[:half]))
    cap.docsis(frag(bp_up(0x0102, 0x10, 1), e[half:]))


def tlv_reproducers(cap):
    """docsis_tlv_ucd_dup.py and docsis_vsif_lengths.py."""
    u = bytes([5, 1, 4, 1])
    tcc1 = tlv(46, tlv(1, b'\x01') + tlv(3, b'\x05') + tlv(5, u) + tlv(5, u + tlv(1, b'\x00')))
    tcc2 = tlv(46, tlv(1, b'\x02') + tlv(3, b'\x06') + tlv(5, u))
    tcc3 = tlv(46, tlv(5, u))
    body = struct.pack('>HB', 0x1234, 0) + tcc1 + tcc2 + tcc3
    cap.docsis(macmgmt_frame(7, body, dst=CM, src=CMTS))
    cap.docsis(macmgmt_frame(7, body, dst=CM, src=CMTS))
    v6 = bytes.fromhex('20010db8000000000000000000000000')
    cisco = tlv(43, tlv(8, b'\x00\x00\x0c') + tlv(11, tlv(1, b'\x05') + tlv(2, b'\x32')))
    gex = tlv(43, tlv(8, b'\xff\xff\xff') + tlv(7, tlv(2, tlv(1, v6) + tlv(2, b'\x20'))))
    cap.docsis(macmgmt_frame(7, struct.pack('>HB', 0x1234, 0) + cisco + gex, dst=CM, src=CMTS))


def registration(cap, g):
    """REG-REQ and REG-RSP carrying TLVs, with a UCD split over two TCCs."""
    sid = struct.pack('>H', 0x0123)
    req = (tlv(1, num(4, 453000000)) + tlv(2, b'\x01') + tlv(3, b'\x01') +
           b''.join(g.wrap(5, g.items('modemcap'))[:1]) +
           tlv(6, bytes(range(16))) + tlv(7, bytes(range(16, 32))) +
           tlv(18, b'\x04'))
    cap.docsis(macmgmt_frame(6, sid + req))
    # UCD in two pieces: the first TCC is 254 octets long
    preamble = tlv(3, bytes(range(256))[:254 - 3 - 2 - 4 - 2])
    piece1 = ucd(3, preamble)
    tcc1 = tlv(3, b'\x03') + tlv(5, piece1)
    assert len(tcc1) == 254, len(tcc1)
    piece2 = tlv(1, b'\x10') + tlv(2, num(4, 30000000))
    rsp = (tlv(46, tcc1) + tlv(46, tlv(1, b'\x01') + tlv(5, piece2)) +
           tlv(46, tlv(3, b'\x04') + tlv(5, ucd(4, tlv(1, b'\x08')))) +
           tlv(49, tlv(1, num(5, 2)) + tlv(8, b'\x01')))
    cap.docsis(macmgmt_frame(7, sid + b'\x00' + rsp, dst=CM, src=CMTS))


def config_files(cap, g):
    """Whole configuration files for the docsis_tlv dissector."""
    # A small, typical file: network access, max CPEs, service flows,
    # MICs, end marker and padding
    f = (tlv(3, b'\x01') + tlv(18, b'\x04') +
         tlv(24, tlv(1, num(2, 1)) + tlv(6, b'\x07') + tlv(8, num(4, 10000000))) +
         tlv(25, tlv(1, num(2, 2)) + tlv(6, b'\x07') + tlv(8, num(4, 50000000))) +
         tlv(6, bytes(range(16))) + tlv(7, bytes(range(16, 32))) + b'\xff\x00' + b'\x00\x00')
    cap.tlvfile(f)
    # Every TLV, in files of about 1000 octets
    for c in chunk(g.items('docsis_tlv'), 1000):
        cap.tlvfile(c)
    # VSIF encodings on their own
    cap.tlvfile(vsif_cisco(), 'docsis_vsif')
    cap.tlvfile(vsif_gex(), 'docsis_vsif')
    cap.tlvfile(vsif_unknown(), 'docsis_vsif')


# --------------------------------------------------------------------------
# Malformed capture contents

def malformed(cap):
    sid = struct.pack('>H', 0x0123)
    eth = udp_eth(BCAST, CM, b'payload')
    # bad HCS
    f = bytearray(pdu(0, 0, eth))
    f[4] ^= 0xff
    cap.docsis(bytes(f))
    # bad HCS on a fragment
    f = bytearray(frag(bp_up(0x0300, 0x20, 0), b'\x11' * 20))
    f[9] ^= 0xff
    cap.docsis(bytes(f))
    # bad fragment CRC
    f = bytearray(frag(bp_up(0x0301, 0x20, 0), b'\x11' * 20))
    f[-1] ^= 0xff
    cap.docsis(bytes(f))
    # fragment LEN shorter than the fragment CRC
    cap.docsis(mac_hdr(fc(3, 3, 0), 0, 2) + b'\x00\x00')
    # fragment LEN past the end of the frame
    h = bytes([fc(3, 3, 1), 6]) + struct.pack('>H', 200) + bp_up(0x302, 0x20, 0)
    cap.docsis(h + struct.pack('<H', crc16_x25(h)) + b'\x00' * 10)
    # LEN past the end, with and without EHDR
    cap.docsis(mac_hdr(fc(0, 0), 0, 500) + eth)
    cap.docsis(mac_hdr(fc(0, 0, 1), 3, 500, eh(2, sid)) + eth)
    # EH element length errors
    for e in (eh(1, sid), eh(2, b'\x00\x01\x02'), eh(3, b'\x10\x00\x01')):
        cap.docsis(pdu(0, 0, eth, e))
    cap.docsis(frag(bp_up(0x0303, None), b'\x22' * 20))
    # a frame too short for the header
    cap.docsis(b'\x00\x00')
    # docsis_hdrlen_wrap.py: EHDR_LEN 255, HCS valid for the wrapped length
    first3 = bytes([fc(3, 1, 1), 0xFF, 0x01])
    cc = crc16_x25(first3)
    hdr = first3 + bytes([cc & 0xFF, cc >> 8])
    tl = bytes([0x03, 0x01, 0x01])
    m = (CM + CMTS + struct.pack('>H', 6 + 3 + len(tl)) + bytes([0, 0, 3, 1, 7, 0]) +
         struct.pack('>HB', 0x1234, 0) + tl)
    fr = hdr + m
    cap.docsis(fr + b'\x00' * (600 - len(fr)))

    # TLVs with wrong lengths
    bad = BadGen(TLVSPEC)
    for c in chunk(bad.items('docsis_tlv'), 1000):
        cap.tlvfile(c)
    # DOCSIS 1.0 CoS with wrong lengths, a bad request multiplier, an IPv6
    # traffic class of 2 octets, SID-to-channel maps with wrong sub-TLV
    # lengths, an RCP name of 16 octets
    cap.tlvfile(tlv(1, tlv(1, b'\x01\x02') + tlv(2, b'\x00\x01\x02')) +
                tlv(24, tlv(26, b'\x03')) +
                tlv(22, tlv(12, tlv(1, b'\x00\x01'))) +
                tlv(47, tlv(2, tlv(2, tlv(1, b'\x01\x02') + tlv(2, b'\x01') + tlv(3, b'\x01')) +
                               tlv(2, tlv(1, b'\x01') + tlv(2, b'\x01\x02\x03') + tlv(3, b'')))) +
                tlv(48, tlv(2, b'n' * 16)))
    # VSIF errors
    cap.tlvfile(tlv(9, b'\x00\x00') + tlv(1, b'\x00'), 'docsis_vsif')
    cap.tlvfile(tlv(8, b'\x00\x00\x0c\x00'), 'docsis_vsif')
    cap.tlvfile(tlv(8, b'\x00\x00\x0c') + tlv(0x0b, tlv(1, b'\x05\x00') +
                tlv(2, b'\x01\x02\x03\x04') + tlv(3, b'\x00')), 'docsis_vsif')
    cap.tlvfile(tlv(8, b'\xff\xff\xff') +
                tlv(7, tlv(2, tlv(1, b'\x01\x02\x03') + tlv(2, b'\x01\x02'))) +
                tlv(9, tlv(1, b'\x01') + tlv(2, b'\x01') + tlv(3, b'\x01') + tlv(4, b'\x01')) +
                tlv(10, tlv(1, b'') + tlv(1, b'x' * 16) + tlv(3, b'\x01') +
                    tlv(2, tlv(1, b'\x01\x02') + tlv(2, b'\x01\x02') + tlv(3, b'\x01') +
                        tlv(4, b'\x01\x02') + tlv(5, b'\x01') + tlv(6, b'\x01\x02'))),
                'docsis_vsif')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    g = Gen(TLVSPEC)
    cap = Cap()
    docsis_frames(cap)
    frag_reproducers(cap)
    tlv_reproducers(cap)
    registration(cap, g)
    config_files(cap, g)
    cap.write(os.path.join(out, 'docsis-coverage.pcapng'))
    bad = Cap()
    malformed(bad)
    bad.write(os.path.join(out, 'docsis-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
