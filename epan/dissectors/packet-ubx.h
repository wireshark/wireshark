/* packet-ubx.h
 * u-blox UBX protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2023 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_UBX_H
#define PACKET_UBX_H


/* Length of the UBX message header
 * (without payload and checksum) */
#define UBX_HEADER_SIZE 6
/* Length of the checksum at the end of a UBX message */
#define UBX_CHKSUM_SIZE 2

/* UBX GNSS Type IDs */
#define GNSS_ID_GPS     0
#define GNSS_ID_SBAS    1
#define GNSS_ID_GALILEO 2
#define GNSS_ID_BEIDOU  3
#define GNSS_ID_IMES    4
#define GNSS_ID_QZSS    5
#define GNSS_ID_GLONASS 6

/* UBX message mnemonics for message class / id */
#define UBX_ACK_ACK 0x0501
#define UBX_ACK_NAK 0x0500
#define UBX_AID_ALM 0x0B30
#define UBX_AID_AOP 0x0B33
#define UBX_AID_EPH 0x0B31
#define UBX_AID_HUI 0x0B02
#define UBX_AID_INI 0x0B01
#define UBX_CFG_ANT 0x0613
#define UBX_CFG_BATCH 0x0693
#define UBX_CFG_CFG 0x0609
#define UBX_CFG_DAT 0x0606
#define UBX_CFG_DGNSS 0x0670
#define UBX_CFG_DOSC 0x0661
#define UBX_CFG_ESFALG 0x0656
#define UBX_CFG_ESFA 0x064C
#define UBX_CFG_ESFG 0x064D
#define UBX_CFG_ESFWT 0x0682
#define UBX_CFG_ESRC 0x0660
#define UBX_CFG_GEOFENCE 0x0669
#define UBX_CFG_GNSS 0x063E
#define UBX_CFG_HNR 0x065C
#define UBX_CFG_INF 0x0602
#define UBX_CFG_ITFM 0x0639
#define UBX_CFG_LOGFILTER 0x0647
#define UBX_CFG_MSG 0x0601
#define UBX_CFG_NAV5 0x0624
#define UBX_CFG_NAVX5 0x0623
#define UBX_CFG_NMEA 0x0617
#define UBX_CFG_ODO 0x061E
#define UBX_CFG_PM2 0x063B
#define UBX_CFG_PMS 0x0686
#define UBX_CFG_PRT 0x0600
#define UBX_CFG_PWR 0x0657
#define UBX_CFG_RATE 0x0608
#define UBX_CFG_RINV 0x0634
#define UBX_CFG_RST 0x0604
#define UBX_CFG_RXM 0x0611
#define UBX_CFG_SBAS 0x0616
#define UBX_CFG_SENIF 0x0688
#define UBX_CFG_SLAS 0x068D
#define UBX_CFG_SMGR 0x0662
#define UBX_CFG_SPT 0x0664
#define UBX_CFG_TMODE2 0x063D
#define UBX_CFG_TMODE3 0x0671
#define UBX_CFG_TP5 0x0631
#define UBX_CFG_TXSLOT 0x0653
#define UBX_CFG_USB 0x061B
#define UBX_ESF_ALG 0x1014
#define UBX_ESF_INS 0x1015
#define UBX_ESF_MEAS 0x1002
#define UBX_ESF_RAW 0x1003
#define UBX_ESF_STATUS 0x1010
#define UBX_HNR_ATT 0x2801
#define UBX_HNR_INS 0x2802
#define UBX_HNR_PVT 0x2800
#define UBX_INF_DEBUG 0x0404
#define UBX_INF_ERROR 0x0400
#define UBX_INF_NOTICE 0x0402
#define UBX_INF_TEST 0x0403
#define UBX_INF_WARNING 0x0401
#define UBX_LOG_BATCH 0x2111
#define UBX_LOG_CREATE 0x2107
#define UBX_LOG_ERASE 0x2103
#define UBX_LOG_FINDTIME 0x210E
#define UBX_LOG_INFO 0x2108
#define UBX_LOG_RETRIEVEBATCH 0x2110
#define UBX_LOG_RETRIEVEPOSEXTRA 0x210f
#define UBX_LOG_RETRIEVEPOS 0x210b
#define UBX_LOG_RETRIEVESTRING 0x210d
#define UBX_LOG_RETRIEVE 0x2109
#define UBX_LOG_STRING 0x2104
#define UBX_MGA_ACK_DATA0 0x1360
#define UBX_MGA_ANO 0x1320
#define UBX_MGA_BDS 0x1303
#define UBX_MGA_DBD 0x1380
#define UBX_MGA_FLASH 0x1321
#define UBX_MGA_GAL 0x1302
#define UBX_MGA_GLO 0x1306
#define UBX_MGA_GPS 0x1300
#define UBX_MGA_INI 0x1340
#define UBX_MGA_QZSS 0x1305
#define UBX_MON_BATCH 0x0A32
#define UBX_MON_GNSS 0x0A28
#define UBX_MON_HW2 0x0A0B
#define UBX_MON_HW 0x0A09
#define UBX_MON_IO 0x0A02
#define UBX_MON_MSGPP 0x0A06
#define UBX_MON_PATCH 0x0A27
#define UBX_MON_RXBUF 0x0A07
#define UBX_MON_RXR 0x0A21
#define UBX_MON_SMGR 0x0A2E
#define UBX_MON_SPT 0x0A2F
#define UBX_MON_TXBUF 0x0A08
#define UBX_MON_VER 0x0A04
#define UBX_NAV_AOPSTATUS 0x0160
#define UBX_NAV_ATT 0x0105
#define UBX_NAV_CLOCK 0x0122
#define UBX_NAV_COV 0x0136
#define UBX_NAV_DGPS 0x0131
#define UBX_NAV_DOP 0x0104
#define UBX_NAV_EELL 0x013d
#define UBX_NAV_EOE 0x0161
#define UBX_NAV_GEOFENCE 0x0139
#define UBX_NAV_HPPOSECEF 0x0113
#define UBX_NAV_HPPOSLLH 0x0114
#define UBX_NAV_NMI 0x0128
#define UBX_NAV_ODO 0x0109
#define UBX_NAV_ORB 0x0134
#define UBX_NAV_POSECEF 0x0101
#define UBX_NAV_POSLLH 0x0102
#define UBX_NAV_PVT 0x0107
#define UBX_NAV_RELPOSNED 0x013C
#define UBX_NAV_RESETODO 0x0110
#define UBX_NAV_SAT 0x0135
#define UBX_NAV_SBAS 0x0132
#define UBX_NAV_SLAS 0x0142
#define UBX_NAV_SOL 0x0106
#define UBX_NAV_STATUS 0x0103
#define UBX_NAV_SVINFO 0x0130
#define UBX_NAV_SVIN 0x013B
#define UBX_NAV_TIMEBDS 0x0124
#define UBX_NAV_TIMEGAL 0x0125
#define UBX_NAV_TIMEGLO 0x0123
#define UBX_NAV_TIMEGPS 0x0120
#define UBX_NAV_TIMELS 0x0126
#define UBX_NAV_TIMEUTC 0x0121
#define UBX_NAV_VELECEF 0x0111
#define UBX_NAV_VELNED 0x0112
#define UBX_RXM_IMES 0x0261
#define UBX_RXM_MEASX 0x0214
#define UBX_RXM_PMREQ 0x0241
#define UBX_RXM_RAWX 0x0215
#define UBX_RXM_RLM 0x0259
#define UBX_RXM_RTCM 0x0232
#define UBX_RXM_SFRBX 0x0213
#define UBX_RXM_SVSI 0x0220
#define UBX_SEC_UNIQID 0x2703
#define UBX_TIM_DOSC 0x0D11
#define UBX_TIM_FCHG 0x0D16
#define UBX_TIM_HOC 0x0D17
#define UBX_TIM_SMEAS 0x0D13
#define UBX_TIM_SVIN 0x0D04
#define UBX_TIM_TM2 0x0D03
#define UBX_TIM_TOS 0x0D12
#define UBX_TIM_TP 0x0D01
#define UBX_TIM_VCOCAL 0x0D15
#define UBX_TIM_VRFY 0x0D06
#define UBX_UPD_SOS 0x0914

#define UBX_REGISTER_DISSECTOR(d,m) dissector_add_uint("ubx.msg_class_id", m, create_dissector_handle(d, proto_ubx));

#endif
