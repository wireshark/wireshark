#!/usr/bin/env python3
# Generates test/captures/homeplug_av_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the HomePlug AV dissector
(packet-homeplug-av.c, ethertype 0x88E1).

A HomePlug AV frame is the MM version octet, the MM type (16 bit little
endian) and, for AV 1.1 (MMV 1), two fragmentation octets; MM types with
the top bit set carry a three octet OUI that selects the vendor tables
(Qualcomm Atheros 00:B0:52, ST/IoTecha 00:80:E1, VertexCom 00:..:..).
For AV 1.0 (MMV 0) public MMEs the two fragmentation octets follow the
type.  Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkhomeplug_av.py <output directory>

Writes:
  homeplug-av-coverage.pcap            one frame (or more) per MM type of
                                       the general, Qualcomm and ST/IoTecha
                                       tables, with the loops, optional
                                       fields and enumerations they decode
  homeplug-av-coverage-malformed.pcap  cut-short frames
"""
import struct
import sys

ETYPE = 0x88E1
OUI_QCA = bytes.fromhex('00b052')
OUI_ST = bytes.fromhex('0080e1')

GENERAL = [
    ('GENERAL_CC_BACKUP_APPOINT_REQ', 0x0004),
    ('GENERAL_CC_BACKUP_APPOINT_CNF', 0x0005),
    ('GENERAL_CC_LINK_INFO_REQ', 0x0008),
    ('GENERAL_CC_LINK_INFO_CNF', 0x0009),
    ('GENERAL_CC_LINK_INFO_IND', 0x000A),
    ('GENERAL_CC_LINK_INFO_RSP', 0x000B), ('GENERAL_CC_HANDOVER_REQ', 0x000C),
    ('GENERAL_CC_HANDOVER_CNF', 0x000D),
    ('GENERAL_CC_HANDOVER_INFO_IND', 0x0012),
    ('GENERAL_CC_HANDOVER_INFO_RSP', 0x0013),
    ('GENERAL_CC_DISCOVER_LIST_REQ', 0x0014),
    ('GENERAL_CC_DISCOVER_LIST_CNF', 0x0015),
    ('GENERAL_CC_DISCOVER_LIST_IND', 0x0016),
    ('GENERAL_CC_LINK_NEW_REQ', 0x0018), ('GENERAL_CC_LINK_NEW_CNF', 0x0019),
    ('GENERAL_CC_LINK_MOD_REQ', 0x001C), ('GENERAL_CC_LINK_MOD_CNF', 0x001D),
    ('GENERAL_CC_LINK_SQZ_REQ', 0x0020), ('GENERAL_CC_LINK_SQZ_CNF', 0x0021),
    ('GENERAL_CC_LINK_REL_REQ', 0x0024), ('GENERAL_CC_LINK_REL_IND', 0x0026),
    ('GENERAL_CC_DETECTC_REPORT_REQ', 0x0028),
    ('GENERAL_CC_DETECTC_REPORT_CNF', 0x0029),
    ('GENERAL_CC_WHO_RU_REQ', 0x002C), ('GENERAL_CC_WHO_RU_CNF', 0x002D),
    ('GENERAL_CC_ASSOC_REQ', 0x0030), ('GENERAL_CC_ASSOC_CNF', 0x0031),
    ('GENERAL_CC_LEAVE_REQ', 0x0034), ('GENERAL_CC_LEAVE_CNF', 0x0035),
    ('GENERAL_CC_LEAVE_IND', 0x0036), ('GENERAL_CC_LEAVE_RSP', 0x0037),
    ('GENERAL_CC_SET_TEI_MAP_REQ', 0x0038),
    ('GENERAL_CC_SET_TEI_MAP_IND', 0x003A), ('GENERAL_CC_RELAY_REQ', 0x003C),
    ('GENERAL_CC_RELAY_IND', 0x003E),
    ('GENERAL_CC_BEACON_RELIABILITY_REQ', 0x0040),
    ('GENERAL_CC_BEACON_RELIABILITY_CNF', 0x0041),
    ('GENERAL_CC_ALLOC_MOVE_REQ', 0x0044),
    ('GENERAL_CC_ALLOC_MOVE_CNF', 0x0045),
    ('GENERAL_CC_ACCESS_NEW_REQ', 0x0048),
    ('GENERAL_CC_ACCESS_NEW_CNF', 0x0049),
    ('GENERAL_CC_ACCESS_NEW_IND', 0x004A),
    ('GENERAL_CC_ACCESS_NEW_RSP', 0x004B),
    ('GENERAL_CC_ACCESS_REL_REQ', 0x004C),
    ('GENERAL_CC_ACCESS_REL_CNF', 0x004D),
    ('GENERAL_CC_ACCESS_REL_IND', 0x004E),
    ('GENERAL_CC_ACCESS_REL_RSP', 0x004F), ('GENERAL_CC_DCPPC_IND', 0x0052),
    ('GENERAL_CC_DCPPC_RSP', 0x0053), ('GENERAL_CC_HP1_DET_REQ', 0x0054),
    ('GENERAL_CC_HP1_DET_CNF', 0x0055), ('GENERAL_CC_BLE_UPDATE_IND', 0x005A),
    ('GENERAL_CC_BCAST_REPEAT_IND', 0x005E),
    ('GENERAL_CC_BCAST_REPEAT_RSP', 0x005F),
    ('GENERAL_CC_MH_LINK_NEW_REQ', 0x0060),
    ('GENERAL_CC_MH_LINK_NEW_CNF', 0x0061),
    ('GENERAL_CC_ISP_DETECTION_REPORT_IND', 0x0066),
    ('GENERAL_CC_ISP_START_RESYNC_REQ', 0x0068),
    ('GENERAL_CC_ISP_FINISH_RESYNC_REQ', 0x006C),
    ('GENERAL_CC_ISP_DETECTED_RESYNC_IND', 0x0072),
    ('GENERAL_CC_ISP_TRANSMIT_RESYNC_REQ', 0x0074),
    ('GENERAL_CC_POWERSAVE_REQ', 0x0078),
    ('GENERAL_CC_POWERSAVE_CNF', 0x0079),
    ('GENERAL_CC_POWERSAVE_EXIT_REQ', 0x007C),
    ('GENERAL_CC_POWERSAVE_EXIT_CNF', 0x007D),
    ('GENERAL_CC_POWERSAVE_LIST_REQ', 0x0080),
    ('GENERAL_CC_POWERSAVE_LIST_CNF', 0x0081),
    ('GENERAL_CC_POWERSAVE_STOP_REQ', 0x0084),
    ('GENERAL_CC_POWERSAVE_STOP_CNF', 0x0085),
    ('GENERAL_CP_PROXY_APPOINT_REQ', 0x2000),
    ('GENERAL_CP_PROXY_APPOINT_CNF', 0x2001),
    ('GENERAL_PH_PROXY_APPOINT_IND', 0x2006),
    ('GENERAL_CP_PROXY_WAKE_REQ', 0x2008), ('GENERAL_NN_INL_REQ', 0x4000),
    ('GENERAL_NN_INL_CNF', 0x4001), ('GENERAL_NN_NEW_NET_REQ', 0x4004),
    ('GENERAL_NN_NEW_NET_CNF', 0x4005), ('GENERAL_NN_NEW_NET_IND', 0x4006),
    ('GENERAL_NN_ADD_ALLOC_REQ', 0x4008),
    ('GENERAL_NN_ADD_ALLOC_CNF', 0x4009),
    ('GENERAL_NN_ADD_ALLOC_IND', 0x400A),
    ('GENERAL_NN_REL_ALLOC_REQ', 0x400C),
    ('GENERAL_NN_REL_ALLOC_CNF', 0x400D), ('GENERAL_NN_REL_NET_IND', 0x4012),
    ('GENERAL_CM_UNASSOCIATED_STA_IND', 0x6002),
    ('GENERAL_CM_ENCRYPTED_PAYLOAD_IND', 0x6006),
    ('GENERAL_CM_ENCRYPTED_PAYLOAD_RSP', 0x6007),
    ('GENERAL_CM_SET_KEY_REQ', 0x6008), ('GENERAL_CM_SET_KEY_CNF', 0x6009),
    ('GENERAL_CM_GET_KEY_REQ', 0x600C), ('GENERAL_CM_GET_KEY_CNF', 0x600D),
    ('GENERAL_CM_SC_JOIN_REQ', 0x6010), ('GENERAL_CM_SC_JOIN_CNF', 0x6011),
    ('GENERAL_CM_SC_CHAN_EST_IND', 0x6016),
    ('GENERAL_CM_TM_UPDATE_IND', 0x601A), ('GENERAL_CM_AMP_MAP_REQ', 0x601C),
    ('GENERAL_CM_AMP_MAP_CNF', 0x601D), ('GENERAL_CM_BRG_INFO_REQ', 0x6020),
    ('GENERAL_CM_BRG_INFO_CNF', 0x6021), ('GENERAL_CM_CONN_NEW_REQ', 0x6024),
    ('GENERAL_CM_CONN_NEW_CNF', 0x6025), ('GENERAL_CM_CONN_REL_IND', 0x602A),
    ('GENERAL_CM_CONN_REL_RSP', 0x602B), ('GENERAL_CM_CONN_MOD_REQ', 0x602C),
    ('GENERAL_CM_CONN_MOD_CNF', 0x602D), ('GENERAL_CM_CONN_INFO_REQ', 0x6030),
    ('GENERAL_CM_CONN_INFO_CNF', 0x6031), ('GENERAL_CM_STA_CAP_REQ', 0x6034),
    ('GENERAL_CM_STA_CAP_CNF', 0x6035), ('GENERAL_CM_NW_INFO_REQ', 0x6038),
    ('GENERAL_CM_NW_INFO_CNF', 0x6039), ('GENERAL_CM_GET_BEACON_REQ', 0x603C),
    ('GENERAL_CM_GET_BEACON_CNF', 0x603D), ('GENERAL_CM_HFID_REQ', 0x6040),
    ('GENERAL_CM_HFID_CNF', 0x6041), ('GENERAL_CM_MME_ERROR_IND', 0x6046),
    ('GENERAL_CM_NW_STATS_REQ', 0x6048), ('GENERAL_CM_NW_STATS_CNF', 0x6049),
    ('GENERAL_CM_LINK_STATS_REQ', 0x604C),
    ('GENERAL_CM_LINK_STATS_CNF', 0x604D),
    ('GENERAL_CM_ROUTE_INFO_REQ', 0x6050),
    ('GENERAL_CM_ROUTE_INFO_CNF', 0x6051),
    ('GENERAL_CM_ROUTE_INFO_IND', 0x6052),
    ('GENERAL_CM_UNREACHABLE_IND', 0x6056),
    ('GENERAL_CM_MH_CONN_NEW_REQ', 0x6058),
    ('GENERAL_CM_MH_CONN_NEW_CNF', 0x6059),
    ('GENERAL_CM_EXTENDED_TONEMASK_REQ', 0x605C),
    ('GENERAL_CM_EXTENDED_TONEMASK_CNF', 0x605D),
    ('GENERAL_CM_STA_IDENTIFY_REQ', 0x6060),
    ('GENERAL_CM_STA_IDENTIFY_CNF', 0x6061),
    ('GENERAL_CM_STA_IDENTIFY_IND', 0x6062),
    ('GENERAL_CM_STA_IDENTIFY_RSP', 0x6063),
    ('GENERAL_CM_SLAC_PARM_REQ', 0x6064),
    ('GENERAL_CM_SLAC_PARM_CNF', 0x6065),
    ('GENERAL_CM_START_ATTEN_CHAR_IND', 0x606A),
    ('GENERAL_CM_ATTEN_CHAR_IND', 0x606E),
    ('GENERAL_CM_ATTEN_CHAR_RSP', 0x606F),
    ('GENERAL_CM_PKCS_CERT_REQ', 0x6070),
    ('GENERAL_CM_PKCS_CERT_CNF', 0x6071),
    ('GENERAL_CM_PKCS_CERT_IND', 0x6072),
    ('GENERAL_CM_PKCS_CERT_RSP', 0x6073),
    ('GENERAL_CM_MNBC_SOUND_IND', 0x6076),
    ('GENERAL_CM_VALIDATE_REQ', 0x6078), ('GENERAL_CM_VALIDATE_CNF', 0x6079),
    ('GENERAL_CM_SLAC_MATCH_REQ', 0x607C),
    ('GENERAL_CM_SLAC_MATCH_CNF', 0x607D),
    ('GENERAL_CM_SLAC_USER_DATA_REQ', 0x6080),
    ('GENERAL_CM_SLAC_USER_DATA_CNF', 0x6081),
    ('GENERAL_CM_ATTEN_PROFILE_IND', 0x6086),
]
QCA = [
    ('QUALCOMM_GET_SW_REQ', 0xA000), ('QUALCOMM_GET_SW_CNF', 0xA001),
    ('QUALCOMM_WR_MEM_REQ', 0xA004), ('QUALCOMM_WR_MEM_CNF', 0xA005),
    ('QUALCOMM_RD_MEM_REQ', 0xA008), ('QUALCOMM_RD_MEM_CNF', 0xA009),
    ('QUALCOMM_ST_MAC_REQ', 0xA00C), ('QUALCOMM_ST_MAC_CNF', 0xA00D),
    ('QUALCOMM_GET_NVM_REQ', 0xA010), ('QUALCOMM_GET_NVM_CNF', 0xA011),
    ('QUALCOMM_RS_DEV_REQ', 0xA01C), ('QUALCOMM_RS_DEV_CNF', 0xA01D),
    ('QUALCOMM_WR_MOD_REQ', 0xA020), ('QUALCOMM_WR_MOD_CNF', 0xA021),
    ('QUALCOMM_WR_MOD_IND', 0xA022), ('QUALCOMM_RD_MOD_REQ', 0xA024),
    ('QUALCOMM_RD_MOD_CNF', 0xA025), ('QUALCOMM_NVM_MOD_REQ', 0xA028),
    ('QUALCOMM_NVM_MOD_CNF', 0xA029), ('QUALCOMM_WD_RPT_REQ', 0xA02C),
    ('QUALCOMM_WD_RPT_IND', 0xA02E), ('QUALCOMM_LNK_STATS_REQ', 0xA030),
    ('QUALCOMM_LNK_STATS_CNF', 0xA031), ('QUALCOMM_SNIFFER_REQ', 0xA034),
    ('QUALCOMM_SNIFFER_CNF', 0xA035), ('QUALCOMM_SNIFFER_IND', 0xA036),
    ('QUALCOMM_NW_INFO_REQ', 0xA038), ('QUALCOMM_NW_INFO_CNF', 0xA039),
    ('QUALCOMM_CP_RPT_REQ', 0xA040), ('QUALCOMM_CP_RPT_IND', 0xA042),
    ('QUALCOMM_FR_LBK_REQ', 0xA048), ('QUALCOMM_FR_LBK_CNF', 0xA049),
    ('QUALCOMM_LBK_STAT_REQ', 0xA04C), ('QUALCOMM_LBK_STAT_CNF', 0xA04D),
    ('QUALCOMM_SET_KEY_REQ', 0xA050), ('QUALCOMM_SET_KEY_CNF', 0xA051),
    ('QUALCOMM_MFG_STRING_REQ', 0xA054), ('QUALCOMM_MFG_STRING_CNF', 0xA055),
    ('QUALCOMM_RD_CBLOCK_REQ', 0xA058), ('QUALCOMM_RD_CBLOCK_CNF', 0xA059),
    ('QUALCOMM_SET_SDRAM_REQ', 0xA05C), ('QUALCOMM_SET_SDRAM_CNF', 0xA05D),
    ('QUALCOMM_HOST_ACTION_IND', 0xA062),
    ('QUALCOMM_HOST_ACTION_RSP', 0xA063), ('QUALCOMM_OP_ATTR_REQ', 0xA068),
    ('QUALCOMM_OP_ATTR_CNF', 0xA069), ('QUALCOMM_GET_ENET_PHY_REQ', 0xA06C),
    ('QUALCOMM_GET_ENET_PHY_CNF', 0xA06D),
    ('QUALCOMM_TONE_MAP_TX_REQ', 0xA070),
    ('QUALCOMM_TONE_MAP_TX_CNF', 0xA071),
    ('QUALCOMM_TONE_MAP_RX_REQ', 0xA090),
    ('QUALCOMM_TONE_MAP_RX_CNF', 0xA091),
    ('QUALCOMM_LINK_STATUS_REQ', 0xA0B8),
    ('QUALCOMM_LINK_STATUS_CNF', 0xA0B9),
]
ST = [
    ('ST_IOTECHA_STP_AUTH_SET_NMK_REQ', 0x8000),
    ('ST_IOTECHA_STP_AUTH_SET_NMK_CNF', 0x8001),
    ('ST_IOTECHA_STP_LINK_STATUS_REQ', 0x8004),
    ('ST_IOTECHA_STP_LINK_STATUS_CNF', 0x8005),
    ('ST_IOTECHA_STP_LINK_STATUS_IND', 0x8006),
    ('ST_IOTECHA_STP_DISCOVER_LOCAL_REQ', 0x8008),
    ('ST_IOTECHA_STP_DISCOVER_LOCAL_CNF', 0x8009),
    ('ST_IOTECHA_STP_SET_MAXGAIN_REQ', 0x800C),
    ('ST_IOTECHA_STP_SET_MAXGAIN_CNF', 0x800D),
    ('ST_IOTECHA_STP_DISCOVER_REQ', 0xA000),
    ('ST_IOTECHA_STP_DISCOVER_CNF', 0xA001),
    ('ST_IOTECHA_STP_GET_TEI_LIST_REQ', 0xA00C),
    ('ST_IOTECHA_STP_GET_TEI_LIST_CNF', 0xA00D),
    ('ST_IOTECHA_STP_GET_TEI_SNAPSHOT_REQ', 0xA010),
    ('ST_IOTECHA_STP_GET_TEI_SNAPSHOT_CNF', 0xA011),
    ('ST_IOTECHA_STP_GET_BSS_LIST_REQ', 0xA014),
    ('ST_IOTECHA_STP_GET_BSS_LIST_CNF', 0xA015),
    ('ST_IOTECHA_STP_CHANQUAL_REPORT_REQ', 0xA018),
    ('ST_IOTECHA_STP_CHANQUAL_REPORT_CNF', 0xA019),
    ('ST_IOTECHA_STP_CHANQUAL_REPORT_IND', 0xA01A),
    ('ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_REQ', 0xA100),
    ('ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_CNF', 0xA101),
    ('ST_IOTECHA_STP_TEST_CHAN_ATTEN_DATA_IND', 0xA106),
    ('ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_REQ', 0xA108),
    ('ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_CNF', 0xA109),
    ('ST_IOTECHA_STP_TEST_SOUND_QUIET_IND', 0xA10E),
    ('ST_IOTECHA_STP_MFCT_UPDATE_STAGE_REQ', 0xA200),
    ('ST_IOTECHA_STP_MFCT_UPDATE_STAGE_CNF', 0xA201),
    ('ST_IOTECHA_STP_MFCT_UPDATE_FINISH_REQ', 0xA204),
    ('ST_IOTECHA_STP_MFCT_UPDATE_FINISH_CNF', 0xA205),
    ('ST_IOTECHA_STP_MFCT_GET_ITEM_REQ', 0xA208),
    ('ST_IOTECHA_STP_MFCT_GET_ITEM_CNF', 0xA209),
    ('ST_IOTECHA_STP_MFCT_GET_KEYLIST_REQ', 0xA20C),
    ('ST_IOTECHA_STP_MFCT_GET_KEYLIST_CNF', 0xA20D),
    ('ST_IOTECHA_STP_FUP_REQ', 0xA210),
    ('ST_IOTECHA_STP_RESERVED_REQ', 0xA214),
    ('ST_IOTECHA_STP_CPSTATE_IND', 0xA22E),
    ('ST_IOTECHA_STP_USER_MESSAGE_IND', 0xA232),
]


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, pad=True, dst=1, src=2):
    fr = bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('>H', ETYPE) + payload
    if pad and len(fr) < 60:
        fr += bytes(60 - len(fr))
    return fr


def mme(mmv, mmtype, payload, oui=None, fmi=b'\x10\x05'):
    """MMV, MMTYPE, two fragmentation octets (public MMEs, and the
    header of AV 1.1) and for vendor MMEs the OUI."""
    b = bytes([mmv]) + struct.pack('<H', mmtype)
    if oui is None:
        b += fmi
    else:
        if mmv:
            b += fmi
        b += oui
    return b + payload


Z = bytes(300)
OUI_VTX = bytes.fromhex('0013d7')
OUI_OTHER = bytes.fromhex('644d70')       # dSPACE: no table


def P(*spec, n=300):
    """n zero octets with (offset, value) pairs patched in; a value is an
    int (one octet) or bytes."""
    b = bytearray(n)
    for off, val in spec:
        if isinstance(val, int):
            val = bytes([val])
        if off + len(val) > len(b):
            b.extend(bytes(off + len(val) - len(b)))
        b[off:off + len(val)] = val
    return bytes(b)


def MAC(n):
    return bytes([2, 0, 0, 0, 0, n])


def variants():
    """(mmv, mmtype, oui, payload) for the main capture."""
    fr = []
    add = lambda mmv, t, oui, p: fr.append((mmv, t, oui, p))
    # 1. every MM type of the three tables once, zero filled, AV 1.1
    for n, v in GENERAL:
        add(1, v, None, Z)
    for n, v in QCA:
        add(1, v, OUI_QCA, Z)
    for n, v in ST:
        add(1, v, OUI_ST, bytes(1770) if v == 0xA01A else Z)
    # 2. HomePlug AV 1.0 public MMEs: the two fragmentation octets follow the header
    for t in (0x0004, 0x6008, 0x6039, 0x6049, 0x606E, 0x6064):
        add(0, t, None, Z)
    # 3. general MMEs with loops and optional fields
    add(1, 0x0015, None, P((0, 2), (25, 2)))                          # CC_DISCOVER_LIST_CNF: 2 STAs, 2 networks
    add(1, 0x6006, None, P((2, 4)))                                   # CM_ENCRYPTED_PAYLOAD_IND, PID HLE
    add(1, 0x6006, None, P((2, 2), (22, 8), n=40))                    # other PID: UUID, length, payload
    add(1, 0x600C, None, P((0, 1), (1, 4)))                           # CM_GET_KEY_REQ, hash key
    add(1, 0x6021, None, P((0, 1), (2, 2)))                           # CM_BRG_INFO_CNF: bridging, 2 MACs
    add(0, 0x6039, None, P((0, 2)))                                   # CM_NW_INFO_CNF: 2 networks (AV 1.0 layout)
    add(0, 0x6049, None, P((0, 2)))                                   # CM_NW_STATS_CNF: 2 STAs
    add(1, 0x003A, None, P((1, 2)))                                   # CC_SET_TEI_MAP_IND: 2 entries
    add(1, 0x003A, None, P((0, 2), (1, 1), (2, 5), (3, MAC(7)), (9, 1)))
    # 4. GreenPHY / SLAC
    add(1, 0x6064, None, P((1, 1), (10, 3), (11, b'\x01\x00\x02\x00\x03\x00')))   # SLAC_PARM_REQ, public key, 3 ciphers
    add(1, 0x6065, None, P((16, 1), (17 + 8, b'\x01\x00')))                       # SLAC_PARM_CNF, public key
    add(1, 0x6086, None, P((6, 3), (8, b'\x05\x06\x07')))                          # ATTEN_PROFILE_IND: 3 groups
    add(1, 0x606E, None, P((1, 0), (51, 4), (52, bytes([10, 20, 30, 40]))))       # ATTEN_CHAR_IND: 4 groups
    add(1, 0x606E, None, P((1, 1)))                                               # public key signature
    add(1, 0x606F, None, P((1, 1)))                                               # ATTEN_CHAR_RSP
    add(1, 0x606A, None, P((1, 1)))                                               # START_ATTEN_CHAR_IND
    add(1, 0x6076, None, P((1, 1)))                                               # MNBC_SOUND_IND
    add(1, 0x6076, None, P((0, 1)))                                               # other application type
    add(1, 0x6078, None, P((0, 1)))                                               # VALIDATE_REQ, other signal type
    add(1, 0x6079, None, P((0, 1)))                                               # VALIDATE_CNF
    add(1, 0x607C, None, P((1, 1), (2, b'\x20\x00')))                             # SLAC_MATCH_REQ, public key
    add(1, 0x607D, None, P((1, 1), (2, b'\x20\x00')))                             # SLAC_MATCH_CNF
    # CM_SLAC_USER_DATA.REQ with a vendor TLV (fixed TLV header) and other TLVs
    tlv = struct.pack('<H', (0x1F << 9) | 8) + bytes.fromhex('0013d7') + b'\x01' + b'ABCD'
    tlv += struct.pack('<H', (0x01 << 9) | 3) + b'xyz'
    tlv += struct.pack('<H', (0x20 << 9) | 2) + b'ab'
    add(1, 0x6080, None, P((3, tlv), n=40) + b'\0' * 4)
    add(1, 0x6081, None, P((3, tlv), n=40) + b'\0' * 4)
    # 5. Qualcomm
    add(1, 0xA031, OUI_QCA, P((0, 0), (1, 0)))                         # LNK_STATS_CNF: Tx
    add(1, 0xA031, OUI_QCA, P((1, 1), (52, 2)))                        # Rx with two intervals
    add(1, 0xA031, OUI_QCA, P((1, 2), (92, 1)))                        # Tx/Rx, one interval
    add(1, 0xA031, OUI_QCA, P((0, 1)))                                 # failure status: no statistics
    for dt in range(0, 8):                                              # SNIFFER_IND, delimiter types
        add(1, 0xA036, OUI_QCA, P((14, dt)))
    add(1, 0xA039, OUI_QCA, P((5, 1), (6 + 26, 2), n=320))             # NW_INFO_CNF AV 1.1: 1 network, 2 STAs
    add(0, 0xA039, OUI_QCA, P((0, 1), (1 + 17, 2)))                    # AV 1.0
    add(0, 0xA070, OUI_QCA, Z)                                         # TONE_MAP_TX_REQ AV 1.0
    add(0, 0xA090, OUI_QCA, Z)                                         # TONE_MAP_RX_REQ AV 1.0
    carriers = bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0x00, 0xf1, 0x01, 0x80, 0x08])
    add(1, 0xA071, OUI_QCA, P((16, 20), (22, carriers)))               # TONE_MAP_TX_CNF AV 1.1, 20 carriers
    add(0, 0xA071, OUI_QCA, P((3, 9), (5, carriers)))                  # AV 1.0, odd number of carriers
    add(1, 0xA091, OUI_QCA, P((16, 20), (28, carriers)))               # TONE_MAP_RX_CNF AV 1.1
    add(0, 0xA091, OUI_QCA, P((3, 8), (5, carriers[:4]), n=700))       # AV 1.0, fewer than A carriers
    add(0, 0xA091, OUI_QCA, P((3, b'\xb0\x04'), (5, carriers * 2), n=1500))   # more than A carriers
    # 6. ST/IoTecha (five octet header, then the message)
    def tl(t, v):
        return struct.pack('<H', (t << 10) | len(v)) + v
    tlvs = (tl(1, b'name') + tl(2, b'\x01\x02') + tl(3, b'build') + tl(4, b'rsv') + tl(5, b'uid') +
            tl(6, MAC(9)) + tl(7, b'hw') + tl(8, b'1.0') + tl(9, b'5.4') + tl(10, b'usr') + b'\0\0')
    add(1, 0xA001, OUI_ST, P((5, tlvs)))                               # STP_DISCOVER.CNF
    add(1, 0x8009, OUI_ST, P((5, tlvs)))                               # STP_DISCOVER_LOCAL.CNF
    add(1, 0xA00D, OUI_ST, P((5, 3), (6, b'\x01\x02\x03')))           # GET_TEI_LIST.CNF
    add(1, 0xA011, OUI_ST, P((5, 2), (6, 7), (7, MAC(1) + b'\x01\x00' + MAC(2) + b'\x00\x01')))   # GET_TEI_SNAPSHOT.CNF
    bss = (b'\x01\x00\x00' + b'\x02\x03\x00abc' + b'\x03\x00\x00' + b'\xff\x00\x00')
    add(1, 0xA015, OUI_ST, P((5, 1), (6, bss)))                        # GET_BSS_LIST.CNF
    add(1, 0xA015, OUI_ST, P((5, 2), (6, b'\x02\x01\x00x')))           # entries that do not start a BSS
    add(1, 0xA01A, OUI_ST, P((25, 2), (26, b'\x11\x12'), (28, 2), (29, b'\x01\x00\x07\x02\x00\x08'),
                             (39, bytes(range(256)) * 6 + bytes(195)), n=1770))   # CHANQUAL_REPORT.IND
    add(1, 0xA20D, OUI_ST, P((5, b'key1\0second-key\0third\0\0')))    # MFCT_GET_KEYLIST.CNF
    add(1, 0xA208, OUI_ST, P((5, struct.pack('<II', 0, 64) + b'item-name\0')))     # MFCT_GET_ITEM.REQ
    add(1, 0xA209, OUI_ST, P((5, struct.pack('<II', 0, 8) + b'item-name\0' + b'valuevalue'), n=40))
    add(1, 0xA200, OUI_ST, P((5, b'\x12\x34' + struct.pack('<HHH', 16, 0, 4) + b'data'), n=40))   # UPDATE_STAGE.REQ
    add(1, 0xA22E, OUI_ST, P((5, b'\x02\x32' + struct.pack('<HH', 1000, 2200) + b'\x07' +
                            struct.pack('<HHH', 100, 200, 300))))    # CPSTATE.IND, all ADC voltages
    add(1, 0xA22E, OUI_ST, P((5, b'\x01\x64\x00\x00\x00\x00\x01\x34\x12')))   # only ADC 1
    add(1, 0xA22E, OUI_ST, P((5, b'\x03')))                              # no ADC
    # STP_USER_MESSAGE.IND with two strings (fixed: the second string no longer starts with the NUL)
    add(1, 0xA232, OUI_ST, P((13, b'info-text\0details-text\0'), n=40))
    add(1, 0xA232, OUI_ST, P((13, b'only-one\0'), n=24))               # one string
    add(1, 0xA232, OUI_ST, P(n=14))                                      # no strings
    # STP_DISCOVER.CNF with a DEVICE_TYPE TLV (the type was compared unshifted)
    add(1, 0xA001, OUI_ST, P((5, tl(2, b'\x01\x02') + tl(1, b'NAME') + b'\0\0'), n=24))
    # 7. other OUIs: VertexCom (handled by its own dissector) and one without a table
    add(1, 0xA000, OUI_VTX, Z)
    add(0, 0xA000, OUI_VTX, Z)
    add(1, 0xA000, OUI_OTHER, Z)
    add(0, 0xA000, OUI_OTHER, Z)
    return fr


def main(out):
    frames = [eth(mme(f[0], f[1], f[3], oui=f[2])) for f in variants()]
    pcap(out + '/homeplug-av-coverage.pcap', frames)
    m = [eth(bytes([1, 0, 0]), pad=False),                       # shorter than the 3 octet header
         eth(bytes([0, 0x04]), pad=False),
         eth(bytes([1, 0x15, 0x00, 0x10, 0x05, 2, 0]), pad=False),     # CC_DISCOVER_LIST.CNF cut short
         eth(mme(1, 0x6006, b'\x00\x00\x02', None), pad=False),         # encrypted payload cut short
         eth(mme(1, 0xA071, b'\x00' * 16 + b'\x14\x00' + b'\x12', OUI_QCA), pad=False),   # tone map cut short
         eth(mme(1, 0xA031, b'\x00\x01\x00\x00' + b'\x00' * 48 + b'\x05', OUI_QCA), pad=False),
         eth(mme(1, 0xA036, b'\x00' * 14 + b'\x01', OUI_QCA), pad=False),   # sniffer: SoF cut short
         eth(mme(1, 0xA001, b'\x00' * 5 + struct.pack('<H', (2 << 10) | 40) + b'ab', OUI_ST), pad=False),
         eth(mme(1, 0xA015, b'\x00' * 5 + b'\x01\x01\x00\x00\x02\xff\x00', OUI_ST), pad=False),
         eth(mme(1, 0x6080, b'\x00\x00\x00' + struct.pack('<H', (0x1F << 9) | 200) + b'\x00\x13', None), pad=False),
         eth(mme(1, 0xA0B9, b'', OUI_QCA), pad=False),
         eth(mme(1, 0xA22E, b'\x00' * 6, OUI_ST), pad=False),
         eth(mme(0, 0xA000, b'', OUI_VTX), pad=False)]
    pcap(out + '/homeplug-av-coverage-malformed.pcap', m)

if __name__ == '__main__':
    main(sys.argv[1])
