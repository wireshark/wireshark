#!/usr/bin/env python3
# Generates test/captures/gsm_a_gm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GSM A GM (GPRS mobility and session management, 3GPP TS 24.008
# chapters 9.4 and 9.5) coverage captures.  Usage: mkgsm_a_gm.py <outdir>
# The GMM and SM messages are carried in Exported PDU frames (link type 252)
# that name the gsm_a_dtap dissector, with the link direction tag (the PCO
# and other elements depend on uplink / downlink).  Synthetic, no network data.
# MSGS is the message/element table of packet-gsm_a_gm.c (extracted with
# extract_msgs.py); the contents of the elements are made up here.
import os
import random
import struct
import sys

MSGS = {(8, 1): ('Attach Request',
          [('MAND_LV', None, 'GM', 'DE_MS_NET_CAP'),
           ('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_ATTACH_TYPE:DE_CIPH_KEY_SEQ_NUM'),
           ('MAND_V', None, 'GM', 'DE_DRX_PARAM'),
           ('MAND_LV', None, 'COMMON', 'DE_MID'),
           ('MAND_V', None, 'GM', 'DE_RAI'),
           ('MAND_LV', None, 'GM', 'DE_MS_RAD_ACC_CAP'),
           ('OPT_TV', '0x19', 'GM', 'DE_P_TMSI_SIG'),
           ('OPT_TV', '0x17', 'GM', 'DE_GPRS_TIMER'),
           ('OPT_TV_SHORT', '0x90', 'GM', 'DE_TMSI_STAT'),
           ('OPT_TLV', '0x33', 'GM', 'DE_PS_LCS_CAP'),
           ('OPT_TLV', '0x11', 'COMMON', 'DE_MS_CM_2'),
           ('OPT_TLV', '0x20', 'COMMON', 'DE_MS_CM_3'),
           ('OPT_TLV', '0x40', 'DTAP', 'DE_SUP_CODEC_LIST'),
           ('OPT_TLV', '0x58', 'NAS_PDU_TYPE_EMM', 'DE_EMM_UE_NET_CAP'),
           ('OPT_TLV', '0x1A', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x1B', 'GM', 'DE_RAI_2'),
           ('OPT_TLV', '0x5D', 'GM', 'DE_VOICE_DOMAIN_PREF'),
           ('OPT_TV_SHORT', '0xD0', 'GM', 'DE_DEVICE_PROPERTIES'),
           ('OPT_TV_SHORT', '0xE0', 'GM', 'DE_PTMSI_TYPE'),
           ('OPT_TV_SHORT', '0xC0', 'COMMON', 'DE_MS_NET_FEAT_SUP'),
           ('OPT_TLV', '0x14', 'GM', 'DE_LAI_2'),
           ('OPT_TV_SHORT', '0xF0', 'GM', 'DE_ADD_UPD_TYPE'),
           ('OPT_TLV', '0x10', 'GM', 'DE_NET_RES_ID_CONT'),
           ('OPT_TLV', '0x6A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x39', 'GM', 'DE_GPRS_TIMER_3'),
           ('OPT_TLV', '0x6E', 'GM', 'DE_EXT_DRX_PARAMS')]),
 (8, 2): ('Attach Accept',
          [('MAND_VV_SHORT', None, 'GM:GM', 'DE_ATTACH_RES:DE_FORCE_TO_STAND_H'),
           ('MAND_V', None, 'GM', 'DE_GPRS_TIMER'),
           ('MAND_V', None, 'GM', 'DE_RAD_PRIO_2'),
           ('MAND_V', None, 'GM', 'DE_RAD_PRIO'),
           ('MAND_V', None, 'GM', 'DE_RAI'),
           ('OPT_TV', '0x19', 'GM', 'DE_P_TMSI_SIG'),
           ('OPT_TV', '0x17', 'GM', 'DE_GPRS_TIMER'),
           ('OPT_TLV', '0x18', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x23', 'COMMON', 'DE_MID'),
           ('OPT_TV', '0x25', 'GM', 'DE_GMM_CAUSE'),
           ('OPT_TLV', '0x2A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_T', '0x8C', 'GM', 'DE_CELL_NOT'),
           ('OPT_TLV', '0x4A', 'COMMON', 'DE_PLMN_LIST'),
           ('OPT_TV_SHORT', '0xB0', 'GM', 'DE_NET_FEAT_SUP'),
           ('OPT_TLV', '0x34', 'DTAP', 'DE_EMERGENCY_NUM_LIST'),
           ('OPT_TV_SHORT', '0xA0', 'GM', 'DE_REQ_MS_INFO'),
           ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x38', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x39', 'GM', 'DE_GPRS_TIMER_3'),
           ('OPT_TLV', '0x66', 'GM', 'DE_ADD_NET_FEAT_SUP'),
           ('OPT_TLV', '0x6A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x6E', 'GM', 'DE_EXT_DRX_PARAMS'),
           ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_UP_INTEG_IND'),
           ('OPT_TLV', '0x31', 'GM', 'DE_MS_NET_CAP'),
           ('OPT_TLV', '0x33', 'GM', 'DE_MS_RAD_ACC_CAP'),
           ('OPT_TLV', '0x65', 'GM', 'DE_DCN_ID'),
           ('OPT_TLV', '0x63', 'GM', 'DE_PLMN_ID_CN_OPERATOR'),
           ('OPT_TV_SHORT', '0xD0', 'GM', 'DE_NON_3GPP_NW_PROV_POL')]),
 (8, 3): ('Attach Complete', [('OPT_TLV', '0x27', 'GM', 'DE_RAT_INFO_CONTAINER'), ('OPT_TLV', '0x2B', 'GM', 'DE_EUTRAN_IRAT_INFO_CONTAINER')]),
 (8, 4): ('Attach Reject',
          [('MAND_V', None, 'GM', 'DE_GMM_CAUSE'), ('OPT_TLV', '0x2A', 'GM', 'DE_GPRS_TIMER_2'), ('OPT_TLV', '0x3A', 'GM', 'DE_GPRS_TIMER_2')]),
 (8, 5): ('Detach Request', []),
 (8, 6): ('Detach Accept', [('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_FORCE_TO_STAND:DE_SPARE_NIBBLE')]),
 (8, 8): ('Routing Area Update Request',
          [('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_UPD_TYPE:DE_CIPH_KEY_SEQ_NUM'),
           ('MAND_V', None, 'GM', 'DE_RAI'),
           ('MAND_LV', None, 'GM', 'DE_MS_RAD_ACC_CAP'),
           ('OPT_TV', '0x19', 'GM', 'DE_P_TMSI_SIG'),
           ('OPT_TV', '0x17', 'GM', 'DE_GPRS_TIMER'),
           ('OPT_TV', '0x27', 'GM', 'DE_DRX_PARAM'),
           ('OPT_TV_SHORT', '0x90', 'GM', 'DE_TMSI_STAT'),
           ('OPT_TLV', '0x18', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x31', 'GM', 'DE_MS_NET_CAP'),
           ('OPT_TLV', '0x32', 'GM', 'DE_PDP_CONTEXT_STAT'),
           ('OPT_TLV', '0x33', 'GM', 'DE_PS_LCS_CAP'),
           ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_CTX_STATUS'),
           ('OPT_TLV', '0x58', 'NAS_PDU_TYPE_EMM', 'DE_EMM_UE_NET_CAP'),
           ('OPT_TLV', '0x1A', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x1B', 'GM', 'DE_RAI_2'),
           ('OPT_TLV', '0x11', 'COMMON', 'DE_MS_CM_2'),
           ('OPT_TLV', '0x20', 'COMMON', 'DE_MS_CM_3'),
           ('OPT_TLV', '0x40', 'DTAP', 'DE_SUP_CODEC_LIST'),
           ('OPT_TLV', '0x5D', 'GM', 'DE_VOICE_DOMAIN_PREF'),
           ('OPT_TV_SHORT', '0xE0', 'GM', 'DE_PTMSI_TYPE'),
           ('OPT_TV_SHORT', '0xD0', 'GM', 'DE_DEVICE_PROPERTIES'),
           ('OPT_TV_SHORT', '0xC0', 'COMMON', 'DE_MS_NET_FEAT_SUP'),
           ('OPT_TLV', '0x14', 'GM', 'DE_LAI_2'),
           ('OPT_TV_SHORT', '0xF0', 'GM', 'DE_ADD_UPD_TYPE'),
           ('OPT_TLV', '0x10', 'GM', 'DE_NET_RES_ID_CONT'),
           ('OPT_TLV', '0x6A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x39', 'GM', 'DE_GPRS_TIMER_3'),
           ('OPT_TLV', '0x6E', 'GM', 'DE_EXT_DRX_PARAMS')]),
 (8, 9): ('Routing Area Update Accept',
          [('MAND_VV_SHORT', None, 'GM:GM', 'DE_FORCE_TO_STAND:DE_UPD_RES'),
           ('MAND_V', None, 'GM', 'DE_GPRS_TIMER'),
           ('MAND_V', None, 'GM', 'DE_RAI'),
           ('OPT_TV', '0x19', 'GM', 'DE_P_TMSI_SIG'),
           ('OPT_TLV', '0x18', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x23', 'COMMON', 'DE_MID'),
           ('OPT_TLV', '0x26', 'GM', 'DE_REC_N_PDU_NUM_LIST'),
           ('OPT_TV', '0x17', 'GM', 'DE_GPRS_TIMER'),
           ('OPT_TV', '0x25', 'GM', 'DE_GMM_CAUSE'),
           ('OPT_TLV', '0x2A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_T', '0x8C', 'GM', 'DE_CELL_NOT'),
           ('OPT_TLV', '0x4A', 'COMMON', 'DE_PLMN_LIST'),
           ('OPT_TLV', '0x32', 'GM', 'DE_PDP_CONTEXT_STAT'),
           ('OPT_TV_SHORT', '0xB0', 'GM', 'DE_NET_FEAT_SUP'),
           ('OPT_TLV', '0x34', 'DTAP', 'DE_EMERGENCY_NUM_LIST'),
           ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_CTX_STATUS'),
           ('OPT_TV_SHORT', '0xA0', 'GM', 'DE_REQ_MS_INFO'),
           ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x38', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x39', 'GM', 'DE_GPRS_TIMER_3'),
           ('OPT_TLV', '0x66', 'GM', 'DE_ADD_NET_FEAT_SUP'),
           ('OPT_TLV', '0x6A', 'GM', 'DE_GPRS_TIMER_2'),
           ('OPT_TLV', '0x6E', 'GM', 'DE_EXT_DRX_PARAMS'),
           ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_UP_INTEG_IND'),
           ('OPT_TLV', '0x31', 'GM', 'DE_MS_NET_CAP'),
           ('OPT_TLV', '0x33', 'GM', 'DE_MS_RAD_ACC_CAP'),
           ('OPT_TLV', '0x65', 'GM', 'DE_DCN_ID'),
           ('OPT_TLV', '0x63', 'GM', 'DE_PLMN_ID_CN_OPERATOR'),
           ('OPT_TV_SHORT', '0xD0', 'GM', 'DE_NON_3GPP_NW_PROV_POL')]),
 (8, 10): ('Routing Area Update Complete',
           [('OPT_TLV', '0x26', 'GM', 'DE_REC_N_PDU_NUM_LIST'),
            ('OPT_TLV', '0x27', 'GM', 'DE_RAT_INFO_CONTAINER'),
            ('OPT_TLV', '0x2B', 'GM', 'DE_EUTRAN_IRAT_INFO_CONTAINER')]),
 (8, 11): ('Routing Area Update Reject',
           [('MAND_V', None, 'GM', 'DE_GMM_CAUSE'),
            ('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_FORCE_TO_STAND:DE_SPARE_NIBBLE'),
            ('OPT_TLV', '0x2A', 'GM', 'DE_GPRS_TIMER_2'),
            ('OPT_TLV', '0x3A', 'GM', 'DE_GPRS_TIMER_2')]),
 (8, 12): ('Service Request',
           [('MAND_VV_SHORT', None, 'COMMON:GM', 'DE_CIPH_KEY_SEQ_NUM:DE_SRVC_TYPE'),
            ('MAND_LV', None, 'COMMON', 'DE_MID'),
            ('OPT_TLV', '0x32', 'GM', 'DE_PDP_CONTEXT_STAT'),
            ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_CTX_STATUS'),
            ('OPT_TLV', '0x36', 'GM', 'DE_UPLINK_DATA_STATUS'),
            ('OPT_TV_SHORT', '0xD0', 'GM', 'DE_DEVICE_PROPERTIES')]),
 (8, 13): ('Service Accept', [('OPT_TLV', '0x32', 'GM', 'DE_PDP_CONTEXT_STAT'), ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_CTX_STATUS')]),
 (8, 14): ('Service Reject', [('MAND_V', None, 'GM', 'DE_GMM_CAUSE'), ('OPT_TLV', '0x3A', 'GM', 'DE_GPRS_TIMER_2')]),
 (8, 16): ('P-TMSI Reallocation Command',
           [('MAND_LV', None, 'COMMON', 'DE_MID'),
            ('MAND_V', None, 'GM', 'DE_RAI'),
            ('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_FORCE_TO_STAND:DE_SPARE_NIBBLE'),
            ('OPT_TV', '0x19', 'GM', 'DE_P_TMSI_SIG'),
            ('OPT_TLV', '0x65', 'GM', 'DE_DCN_ID')]),
 (8, 17): ('P-TMSI Reallocation Complete', []),
 (8, 18): ('Authentication and Ciphering Req',
           [('MAND_VV_SHORT', None, 'GM:GM', 'DE_CIPH_ALG:DE_IMEISV_REQ'),
            ('MAND_VV_SHORT', None, 'GM:GM', 'DE_FORCE_TO_STAND:DE_AC_REF_NUM_H'),
            ('OPT_TV', '0x21', 'DTAP', 'DE_AUTH_PARAM_RAND'),
            ('OPT_TV_SHORT', '0x80', 'COMMON', 'DE_CIPH_KEY_SEQ_NUM'),
            ('OPT_TLV', '0x28', 'DTAP', 'DE_AUTH_PARAM_AUTN'),
            ('OPT_TLV', '0x31', 'GM', 'DE_MS_NET_CAP'),
            ('OPT_TLV', '0x42', 'GM', 'DE_INTEG_ALG'),
            ('OPT_TLV', '0x43', 'GM', 'DE_MAC'),
            ('OPT_TLV', '0x33', 'GM', 'DE_MS_RAD_ACC_CAP')]),
 (8, 19): ('Authentication and Ciphering Resp',
           [('MAND_VV_SHORT', None, 'GM:COMMON', 'DE_AC_REF_NUM:DE_SPARE_NIBBLE'),
            ('OPT_TV', '0x22', 'DTAP', 'DE_AUTH_RESP_PARAM'),
            ('OPT_TLV', '0x23', 'COMMON', 'DE_MID'),
            ('OPT_TLV', '0x29', 'DTAP', 'DE_AUTH_RESP_PARAM_EXT'),
            ('OPT_TLV', '0x43', 'GM', 'DE_MAC')]),
 (8, 20): ('Authentication and Ciphering Rej', []),
 (8, 21): ('Identity Request', [('MAND_VV_SHORT', None, 'GM:GM', 'DE_ID_TYPE_2:DE_FORCE_TO_STAND_H')]),
 (8, 22): ('Identity Response', [('MAND_LV', None, 'COMMON', 'DE_MID')]),
 (8, 28): ('Authentication and Ciphering Failure', [('MAND_V', None, 'GM', 'DE_GMM_CAUSE'), ('OPT_TLV', '0x30', 'DTAP', 'DE_AUTH_FAIL_PARAM')]),
 (8, 32): ('GMM Status', [('MAND_V', None, 'GM', 'DE_GMM_CAUSE')]),
 (8, 33): ('GMM Information',
           [('OPT_TLV', '0x43', 'DTAP', 'DE_NETWORK_NAME'),
            ('OPT_TLV', '0x45', 'DTAP', 'DE_NETWORK_NAME'),
            ('OPT_TV', '0x46', 'DTAP', 'DE_TIME_ZONE'),
            ('OPT_TV', '0x47', 'DTAP', 'DE_TIME_ZONE_TIME'),
            ('OPT_TLV', '0x48', 'DTAP', 'DE_LSA_ID'),
            ('OPT_TLV', '0x49', 'DTAP', 'DE_DAY_SAVING_TIME')]),
 (10, 65): ('Activate PDP Context Request',
            [('MAND_V', None, 'GM', 'DE_NET_SAPI'),
             ('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_QOS'),
             ('MAND_LV', None, 'GM', 'DE_PD_PRO_ADDR'),
             ('OPT_TLV', '0x28', 'GM', 'DE_ACC_POINT_NAME'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xA0', 'GM', 'DE_REQ_TYPE'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_DEVICE_PROPERTIES'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 66): ('Activate PDP Context Accept',
            [('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_QOS'),
             ('MAND_V', None, 'GM', 'DE_RAD_PRIO'),
             ('OPT_TLV', '0x2B', 'GM', 'DE_PD_PRO_ADDR'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x34', 'GM', 'DE_PACKET_FLOW_ID'),
             ('OPT_TLV', '0x39', 'GM', 'DE_SM_CAUSE_2'),
             ('OPT_TV_SHORT', '0xB0', 'GM', 'DE_SM_CONNECTIVITY_TYPE'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 67): ('Activate PDP Context Reject',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_3'),
             ('OPT_TLV', '0x6B', 'GM', 'DE_RE_ATTEMPT_IND'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 68): ('Request PDP Context Activation',
            [('MAND_LV', None, 'GM', 'DE_PD_PRO_ADDR'),
             ('OPT_TLV', '0x28', 'GM', 'DE_ACC_POINT_NAME'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 69): ('Request PDP Context Activation rej.',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 70): ('Deactivate PDP Context Request',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TV_SHORT', '0x90', 'GM', 'DE_TEAR_DOWN_IND'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT'),
             ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_3'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 71): ('Deactivate PDP Context Accept',
            [('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 72): ('Modify PDP Context Request(Network to MS direction)',
            [('MAND_V', None, 'GM', 'DE_RAD_PRIO'),
             ('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_QOS'),
             ('OPT_TLV', '0x2B', 'GM', 'DE_PD_PRO_ADDR'),
             ('OPT_TLV', '0x34', 'GM', 'DE_PACKET_FLOW_ID'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x36', 'GM', 'DE_TRAFFIC_FLOW_TEMPLATE'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 73): ('Modify PDP Context Accept (MS to network direction)',
            [('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 74): ('Modify PDP Context Request(MS to network direction)',
            [('OPT_TV', '0x32', 'GM', 'DE_LLC_SAPI'),
             ('OPT_TLV', '0x30', 'GM', 'DE_QOS'),
             ('OPT_TLV', '0x31', 'GM', 'DE_TRAFFIC_FLOW_TEMPLATE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_DEVICE_PROPERTIES'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 75): ('Modify PDP Context Accept (Network to MS direction)',
            [('OPT_TLV', '0x30', 'GM', 'DE_QOS'),
             ('OPT_TV', '0x32', 'GM', 'DE_LLC_SAPI'),
             ('OPT_TV_SHORT', '0x80', 'GM', 'DE_RAD_PRIO'),
             ('OPT_TLV', '0x34', 'GM', 'DE_PACKET_FLOW_ID'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 76): ('Modify PDP Context Reject',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_3'),
             ('OPT_TLV', '0x6B', 'GM', 'DE_RE_ATTEMPT_IND'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 77): ('Activate Secondary PDP Context Request',
            [('MAND_V', None, 'GM', 'DE_NET_SAPI'),
             ('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_QOS'),
             ('MAND_LV', None, 'GM', 'DE_LINKED_TI'),
             ('OPT_TLV', '0x36', 'GM', 'DE_TRAFFIC_FLOW_TEMPLATE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_DEVICE_PROPERTIES'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 78): ('Activate Secondary PDP Context Accept',
            [('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_QOS'),
             ('MAND_V', None, 'GM', 'DE_RAD_PRIO'),
             ('OPT_TLV', '0x34', 'GM', 'DE_PACKET_FLOW_ID'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 79): ('Activate Secondary PDP Context Reject',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_3'),
             ('OPT_TLV', '0x6B', 'GM', 'DE_RE_ATTEMPT_IND'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 85): ('SM Status', [('MAND_V', None, 'GM', 'DE_SM_CAUSE')]),
 (10, 86): ('Activate MBMS Context Request',
            [('MAND_V', None, 'GM', 'DE_ENH_NSAPI'),
             ('MAND_V', None, 'GM', 'DE_LLC_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_MBMS_BEARER_CAP'),
             ('MAND_LV', None, 'GM', 'DE_PD_PRO_ADDR'),
             ('MAND_LV', None, 'GM', 'DE_ACC_POINT_NAME'),
             ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_DEVICE_PROPERTIES')]),
 (10, 87): ('Activate MBMS Context Accept',
            [('MAND_LV', None, 'GM', 'DE_TMGI'), ('MAND_V', None, 'GM', 'DE_LLC_SAPI'), ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT')]),
 (10, 88): ('Activate MBMS Context Reject',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT'),
             ('OPT_TLV', '0x37', 'GM', 'DE_GPRS_TIMER_3'),
             ('OPT_TLV', '0x6B', 'GM', 'DE_RE_ATTEMPT_IND')]),
 (10, 89): ('Request MBMS Context Activation',
            [('MAND_V', None, 'GM', 'DE_NET_SAPI'),
             ('MAND_LV', None, 'GM', 'DE_PD_PRO_ADDR'),
             ('MAND_LV', None, 'GM', 'DE_ACC_POINT_NAME'),
             ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT')]),
 (10, 90): ('Request MBMS Context Activation Reject', [('MAND_V', None, 'GM', 'DE_SM_CAUSE'), ('OPT_TLV', '0x35', 'GM', 'DE_MBMS_PROT_CONF_OPT')]),
 (10, 91): ('Request Secondary PDP Context Activation',
            [('MAND_LV', None, 'GM', 'DE_QOS'),
             ('MAND_LV', None, 'GM', 'DE_LINKED_TI'),
             ('OPT_TLV', '0x36', 'GM', 'DE_TRAFFIC_FLOW_TEMPLATE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TV_SHORT', '0xC0', 'GM', 'DE_SM_WLAN_OFFLOAD_ACCEPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT'),
             ('OPT_TLV', '0x5C', 'GM', 'DE_EXT_QOS')]),
 (10, 92): ('Request Secondary PDP Context Activation Reject',
            [('MAND_V', None, 'GM', 'DE_SM_CAUSE'),
             ('OPT_TLV', '0x27', 'GM', 'DE_PRO_CONF_OPT'),
             ('OPT_TLV', '0x33', 'GM', 'DE_NBIFOM_CONT'),
             ('OPT_TLV_E', '0x7B', 'GM', 'DE_EXT_PRO_CONF_OPT')]),
 (10, 93): ('Notification', [('MAND_LV', None, 'GM', 'DE_SM_NOTIF_IND')])}

def exp_pdu(payload, link_dir=None):
    name = b'gsm_a_dtap'
    pad = (4 - len(name) % 4) % 4
    h = struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad
    if link_dir is not None:
        h += struct.pack('>HHi', 39, 4, link_dir)
    return h + struct.pack('>HH', 0, 0) + payload

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

UL, DL = 0, 1
SM_UL = {0x41, 0x45, 0x49, 0x4a, 0x4d, 0x5c}      # the dissector sets the direction itself
SM_UNKNOWN = {0x46, 0x47, 0x4c, 0x55}

# --------------------------------------------------------------- bit writer
class Bits:
    def __init__(self): self.b = []
    def put(self, v, n):
        for i in range(n - 1, -1, -1): self.b.append((v >> i) & 1)
    def bytes(self):
        b = self.b + [0] * (-len(self.b) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))

def ra_cap(seed, ncaps=2, density=0.8):
    """MS Radio Access Capability: random content with the right framing
    (the dissector stops reading fields when the declared length runs out)"""
    r = random.Random(seed)
    w = Bits()
    types = [0, 1, 2, 3, 4, 5, 6, 7, 8, 15]
    for n in range(ncaps):
        if n:
            w.put(1, 1)
        t = r.choice(types[:9] if n == 0 else types)
        L = r.choice([127, 120, 100, 80, 60, 40, 24])
        w.put(t, 4)
        w.put(L, 7)
        for _ in range(L):
            w.put(1 if r.random() < density else 0, 1)
    return w.bytes()

# ------------------------------------------------------------------ elements
def tlv(iei, c): return bytes([iei, len(c)]) + c
def tlve(iei, c): return bytes([iei]) + struct.pack('>H', len(c)) + c

IMSI = bytes([0x09, 0x10, 0x10, 0x21, 0x43, 0x65, 0x87, 0xf9])
TMSI = bytes([0xf4, 0x01, 0x02, 0x03, 0x04])
IMEISV = bytes([0x03, 0x53, 0x94, 0x21, 0x43, 0x65, 0x87, 0x09, 0xf1])
PLMN = bytes([0x00, 0xf1, 0x10])

def pco_container(pid, c, dl):
    two = (dl and pid in (0x23, 0x24, 0x30, 0x31, 0x32, 0x41, 0x51, 0x56)) or (not dl and pid in (0x41, 0x51, 0x56))
    return struct.pack('>H', pid) + (struct.pack('>H', len(c)) if two else bytes([len(c)])) + c

IP4 = bytes([192, 0, 2, 1])
IP6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
DNN = bytes([8]) + b'internet'
SNSSAI = bytes([0x01, 0x01])

def pco_dl():
    c = []
    A = c.append
    A((0xc021, bytes([1, 1, 0, 4])))
    A((0xc023, bytes([2, 1, 0, 5, 0])))
    A((0x8021, bytes([3, 1, 0, 10, 0x81, 6]) + IP4))
    A((0x0001, IP6)); A((0x0003, IP6)); A((0x0007, IP6)); A((0x0002, b'\x00'))
    A((0x0004, b'\x01')); A((0x0005, b'\x01')); A((0x0008, IP6 + b'\x40')); A((0x0009, IP4))
    A((0x000c, IP4)); A((0x000d, IP4)); A((0x000e, bytes([0x21, 0x43, 0x65, 0x87])))
    A((0x0010, b'\x05\xdc')); A((0x0014, b'\x03')); A((0x0015, b'\x00\x01'))
    A((0x0016, bytes([0x01, 0x00, 0x00, 0x01]))); A((0x0025, bytes([0x01, 0x02, 0x03, 0x04, 5])))
    A((0x0019, bytes([1, 2, 3, 4]))); A((0x0026, bytes([1, 2, 3, 4])))
    A((0x001b, SNSSAI + PLMN)); A((0x001c, bytes([1, 0, 6, 0x31, 0x11, 1, 1, 1, 1])))
    A((0x001d, bytes([0x04, 0x03, 0xe8, 0x04, 0x03, 0xe8]))); A((0x001e, b'\x00\x01'))
    A((0x001f, bytes([1, 0x20, 0x41, 1, 1, 9])))
    A((0x0020, b'\x00\x01')); A((0x0021, b'\x00\x01'))
    A((0x0023, bytes([1, 0, 6, 0x31, 0x11, 1, 1, 1, 1]))); A((0x0024, bytes([1, 0x20, 0x41, 1, 1, 9])))
    A((0x0027, b'acs.example.net'))
    for p in (0x28, 0x29, 0x2a, 0x2b):
        A((p, bytes([0x01, 0x00, 0x00, 0, 0xe9, 0x00, 0x00])))
    A((0x0030, b'\x01\x02')); A((0x0035, b'ecsp'))
    for t in (0, 1, 2, 3, 4, 5, 6):
        body = {0: b'\x01', 1: b'\x01\xbb', 2: bytes([4]) + b'dns1', 3: b'\x01\x02', 4: b'\x03\x04', 5: b'\x05\x06', 6: b'\x07\x08'}[t]
        A((0x0031, bytes([t]) + body))
    A((0x0032, bytes([0]) + IP4)); A((0x0032, bytes([0x11]) + IP6 + bytes([2, 0xaa, 0xbb, 0x01, 0x03, 4, 1, 2, 3, 4])))
    A((0x0032, bytes([2, 4]) + b'ecs1')); A((0x0032, bytes([5, 1])))
    A((0x0036, IP4 + bytes([0x03]) + bytes([len(DNN)]) + DNN + bytes([len(SNSSAI)]) + SNSSAI))
    A((0x0037, IP6 + bytes([0x00])))
    A((0x0038, bytes([4]) + b'name' + bytes([0x01]) + bytes([len(DNN)]) + DNN))
    A((0x003b, IP4 + IP4)); A((0x003c, IP6 + IP6)); A((0x003d, bytes([4]) + b'eas1'))
    A((0x0041, bytes([0x01, 0x02, 0x03])))
    A((0x0051, bytes([1, 1, 0, 5, 1])))
    A((0x0056, bytes([0x01, 0x02])))
    A((0xff00, PLMN + b'app')); A((0xff01, PLMN)); A((0xff02, b'\x00\xf1')); A((0xff03, b'\x01'))
    A((0xff04, b'')); A((0x1234, b'\x01\x02')); A((0x1235, b''))
    return [pco_container(p, d, True) for p, d in c]

def pco_generic():
    c = [(0xc021, bytes([1, 1, 0, 4])), (0x8021, bytes([1, 1, 0, 10, 0x81, 6]) + bytes(4)), (0x0002, b'\x00'),
         (0x000a, b''), (0x0011, b'')]
    return [pco_container(p, d, False) for p, d in c]

def pco_ul():
    c = []
    A = c.append
    A((0xc021, bytes([1, 1, 0, 4]))); A((0xc023, bytes([1, 1, 0, 10, 4]) + b'user' + b'\0'))
    A((0x8021, bytes([1, 1, 0, 10, 0x81, 6]) + bytes(4)))
    A((0x0001, b'')); A((0x0002, b'\x00')); A((0x000a, b'')); A((0x000c, b'')); A((0x000d, b'')); A((0x0010, b''))
    A((0x0011, b'')); A((0x0012, b'')); A((0x0013, b'')); A((0x0018, b'')); A((0x0040, b''))
    A((0x0017, b'\x01')); A((0x0017, b'')); A((0x001a, b'')); A((0x0022, b'\x01'))
    A((0x0039, b'\x03')); A((0x003a, b'\x07')); A((0x0052, b'dnn.example'))
    A((0x0058, bytes([2]) + SNSSAI)); A((0x0058, b'\x01'))
    A((0x0041, bytes([0x01, 0x02]))); A((0x0051, bytes([2, 1, 0, 5, 1])))
    A((0x0056, bytes([0x01, 0x02])))
    A((0xff00, PLMN + b'app')); A((0xff01, b'\x01'))
    A((0x1234, b'\x01\x02'))
    A((0x0014, b'')); A((0x001e, b'\x01')); A((0x0020, b''))
    return [pco_container(p, d, False) for p, d in c]

def mbms_pco():
    return b'\x80' + pco_container(0x0011, b'\x01', False)  # not used by the table, plain bytes

def pdp_addr(kind):
    return {'v4': bytes([0x01, 0x21]) + IP4, 'v6': bytes([0x01, 0x57]) + IP6[:16],
            'v46': bytes([0x01, 0x8d]) + IP4 + IP6, 'dyn4': bytes([0x01, 0x21]),
            'dyn6': bytes([0x01, 0x57]), 'dyn46': bytes([0x01, 0x8d]),
            'ppp': bytes([0x00, 0x01]), 'nonip': bytes([0x00, 0x02]), 'ppp_addr': bytes([0x00, 0x01, 1, 2, 3, 4]),
            'empty': bytes([0xf0, 0x00]), 'unk': bytes([0x03, 0x77, 1, 2]), 'v4unk': bytes([0x01, 0x30]) + IP4,
            'etsi_unknown': bytes([0x00, 0x09])}[kind]

QOS = [
    bytes([0x13, 0x73, 0x1f]),                                             # R97 only
    bytes([0x13, 0x73, 0x1f, 0x84]),                                       # +traffic class
    bytes([0x13, 0x73, 0x1f, 0x84, 0x97, 0xfe, 0x74, 0x77, 0x92, 0x89]),    # R99 up to the guaranteed
    bytes([0x13, 0x73, 0x1f, 0x84, 0x97, 0xfe, 0x74, 0x77, 0x92, 0x89, 0xff, 0xff, 0x02, 0x21]),
    bytes([0x13, 0x73, 0x1f, 0x74, 0x98, 0x40, 0x10, 0x10, 0x10, 0x10, 0x8c, 0x8c, 0x93, 0x40, 0x01, 0x01, 0x01]),
    bytes([0x13, 0x73, 0x1f, 0x84, 0x00, 0x99, 0x20, 0x30, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0]),
    bytes([0x13, 0x73, 0x1f, 0x84, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]),
    bytes([0x13, 0x73, 0x1f, 0x44, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00]),
]
EXT_QOS = [
    bytes([0x01, 0x02, 0x03, 0x04]),
    bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]),
    bytes([0xfa, 0xfe, 0x40, 0xfd, 0x40, 0x40, 0x40, 0x40, 0x40, 0xfa, 0xfe]),
    bytes([0x40, 0x40, 0x70, 0x71, 0x72, 0xa0, 0x80, 0x80, 0x01, 0x01, 0x01]),
]

def tft(op, filters=(), params=b'', ebit=None):
    """Traffic flow template: op = operation code, filters = list of
    (id, direction, precedence, components)"""
    n = len(filters)
    first = (op << 5) | ((1 if params else 0) << 4) | n
    body = bytes([first])
    for fid, d, prec, comps in filters:
        body += bytes([(d << 4) | fid, prec, len(comps)]) + comps
    return body + params

COMPS = {
    'v4addr': bytes([0x10]) + IP4 + bytes([255, 255, 255, 0]),
    'v6addr': bytes([0x20]) + IP6 + bytes([0xff] * 16),
    'v6prefix': bytes([0x21]) + IP6 + b'\x40',
    'proto': bytes([0x30, 6]),
    'dport': bytes([0x40, 0x01, 0xbb]),
    'dportr': bytes([0x41, 0x00, 0x50, 0x00, 0x60]),
    'sport': bytes([0x50, 0x1f, 0x90]),
    'sportr': bytes([0x51, 0x1f, 0x90, 0x1f, 0xa0]),
    'spi': bytes([0x60, 1, 2, 3, 4]),
    'tos': bytes([0x70, 0x10, 0xff]),
    'flow': bytes([0x80, 0x01, 0x02, 0x03]),
    'dest_mac': bytes([0x81, 1, 2, 3, 4, 5, 6]),
    'src_mac': bytes([0x82, 1, 2, 3, 4, 5, 6]),
    '8021q_c': bytes([0x83, 0x0f, 0xff]),
    '8021q_s': bytes([0x84, 0x0f, 0xff]),
    '8021q_cp': bytes([0x85, 0x05]),
    '8021q_sp': bytes([0x86, 0x05]),
    'ethertype': bytes([0x87, 0x08, 0x00]),
    'dst_local': bytes([0x88, 0x01]),
    'unknown': bytes([0x99, 0x01]),
}

TP_ALL = bytes([0x01, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x04, 0, 1, 0, 2, 0x03, 0x02, 0x01, 0x05, 0x04, 0x02, 1, 2])

def tft_variants():
    f = lambda *k: b''.join(COMPS[x] for x in k)
    out = [
        tft(1, [(1, 1, 0x10, f('v4addr', 'proto', 'dport', 'sport'))]),
        tft(1, [(1, 1, 0x10, f('v6addr', 'dportr', 'sportr')), (2, 2, 0x20, f('v6prefix', 'spi', 'tos')),
                (3, 3, 0x30, f('flow', 'dest_mac', 'src_mac')), (4, 0, 0x40, f('8021q_c', '8021q_s', '8021q_cp', '8021q_sp', 'ethertype'))]),
        tft(2),
        tft(3, [(5, 1, 1, f('v4addr'))]),
        tft(4, [(6, 1, 1, f('v4addr'))]),
        tft(5, [(1, 0, 0, b'')]),
        tft(6, [(1, 0, 0, b'')]),
        tft(0, [(1, 0, 0, b'')]),
        tft(7),
        tft(1, [(1, 1, 0x10, f('dst_local', 'unknown'))]),
        tft(1, [(1, 1, 0x10, f('v4addr'))], params=TP_ALL),
        tft(2, params=TP_ALL),
        tft(1, [(1, 1, 0x10, f('v4addr'))], params=bytes([0x01, 0x03, 1, 2, 3])),
        tft(3, [(7, 1, 0, f('v4addr', 'proto'))], params=bytes([0x03, 0x01, 0x02])),
    ]
    return out

def ms_net_caps():
    return [bytes([0xe5]), bytes([0xe5, 0xe0]), bytes([0xe5, 0xe0, 0xff]), bytes([0xe5, 0xe0, 0xff, 0xff, 0xff, 0xff])]

def tmgi(v):
    return [bytes([0x00, 0x00, 0x01]), bytes([0x00, 0x00, 0x01, 0x00, 0xf1, 0x10]),
            bytes([0x00, 0x00, 0x01, 0x00, 0xf1, 0x10, 0x01])][v % 3]

# content tables: DE -> list of alternatives (a variant picks alt[v % len])
V_LEN = {'DE_DRX_PARAM': [b'\x0a\x13', b'\x04\x08', b'\x05\x39'], 'DE_ENH_NSAPI': [b'\x05', b'\x0f'],
         'DE_GMM_CAUSE': [b'\x07', b'\x0b', b'\x6f', b'\x11'], 'DE_GPRS_TIMER': [bytes([u << 5 | 3]) for u in (1, 0, 2, 7, 3, 4)],
         'DE_LLC_SAPI': [b'\x03', b'\x0b', b'\x00'], 'DE_NET_SAPI': [b'\x05', b'\x0f', b'\x06'],
         'DE_RAD_PRIO': [b'\x01', b'\x04', b'\x03'], 'DE_RAD_PRIO_2': [b'\x02', b'\x04', b'\x01'],
         'DE_RAI': [PLMN + b'\x00\x01\x02', PLMN + b'\x10\x20\x03', b'\x13\x00\x62\x00\x07\x01'],
         'DE_SM_CAUSE': [b'\x1a', b'\x24', b'\x27', b'\x33', b'\x1d', b'\x68'], 'DE_SPARE': [b'\x00']}
TV_LEN = {'DE_AUTH_RESP_PARAM': [bytes([1, 2, 3, 4])], 'DE_AUTH_PARAM_RAND': [bytes(range(16))],
          'DE_P_TMSI_SIG': [bytes([1, 2, 3])], 'DE_TIME_ZONE': [b'\x29', b'\x21'],
          'DE_TIME_ZONE_TIME': [bytes([0x62, 0x11, 0x50, 0x21, 0x43, 0x65, 0x29]), bytes([0x62, 0x11, 0x50, 0x21, 0x43, 0x65, 0x21])]}
SHORT = {'DE_ADD_UPD_TYPE': [0, 1, 2], 'DE_CIPH_KEY_SEQ_NUM': [1, 7, 0], 'DE_DEVICE_PROPERTIES': [0, 1],
         'DE_MS_NET_FEAT_SUP': [0, 1], 'DE_NET_FEAT_SUP': [0, 1, 0xf, 6], 'DE_NON_3GPP_NW_PROV_POL': [0, 1],
         'DE_PTMSI_TYPE': [0, 1], 'DE_REQ_MS_INFO': [0, 0xc, 4, 8], 'DE_REQ_TYPE': [1, 2, 3, 4, 0],
         'DE_SM_CONNECTIVITY_TYPE': [0, 1, 2], 'DE_SM_WLAN_OFFLOAD_ACCEPT': [0, 1, 2, 3], 'DE_TEAR_DOWN_IND': [0, 1],
         'DE_TMSI_STAT': [0, 1], 'DE_UP_INTEG_IND': [0, 1, 2], 'DE_RAD_PRIO': [1, 4, 3],
         'DE_ATTACH_TYPE': [1, 2, 3, 4, 5], 'DE_ATTACH_RES': [1, 2, 3], 'DE_FORCE_TO_STAND': [0, 1], 'DE_FORCE_TO_STAND_H': [0, 1],
         'DE_SPARE_NIBBLE': [0], 'DE_UPD_TYPE': [0, 1, 2, 3, 4, 5], 'DE_UPD_RES': [0, 1, 4, 5], 'DE_AC_REF_NUM': [0, 5],
         'DE_AC_REF_NUM_H': [0, 5], 'DE_CIPH_ALG': [0, 1, 2], 'DE_IMEISV_REQ': [0, 1], 'DE_ID_TYPE_2': [1, 2, 3, 4, 5],
         'DE_SRVC_TYPE': [0, 1, 2, 3, 4]}
VAR = {
    'DE_ACC_POINT_NAME': [bytes([8]) + b'internet' + bytes([3]) + b'com', bytes([4]) + b'mnc1' + bytes([6]) + b'mcc262', b'\x03abc'],
    'DE_ADD_NET_FEAT_SUP': [b'\x01', b'\x00'], 'DE_AUTH_FAIL_PARAM': [bytes(range(14))],
    'DE_AUTH_PARAM_AUTN': [bytes(range(16))], 'DE_AUTH_RESP_PARAM_EXT': [bytes(range(4)), bytes(range(12))],
    'DE_DAY_SAVING_TIME': [b'\x01', b'\x00'], 'DE_DCN_ID': [b'\x00\x01'],
    'DE_EMERGENCY_NUM_LIST': [bytes([3, 0x01, 0x11, 0xf2, 4, 0x02, 0x19, 0x91, 0xf1])],
    'DE_EMM_UE_NET_CAP': [b'\xf0\xf0', b'\xf0\xf0\xe0\xa0', b'\xf0\xf0\xe0\xa0\xff\xff'],
    'DE_EUTRAN_IRAT_INFO_CONTAINER': [b'\x00\x00'], 'DE_EXT_DRX_PARAMS': [b'\x35', b'\x00', b'\xff'],
    'DE_EXT_QOS': EXT_QOS, 'DE_GPRS_TIMER_2': [bytes([u << 5 | 3]) for u in (1, 0, 2, 7, 3)], 'DE_GPRS_TIMER_3': [bytes([u << 5 | 3]) for u in (1, 0, 2, 3, 4, 5, 6, 7)],
    'DE_INTEG_ALG': [b'\x01', b'\x02'], 'DE_LAI_2': [PLMN + b'\x00\x01'], 'DE_LINKED_TI': [b'\x01', b'\x0f\x03', b'\x80'],
    'DE_LSA_ID': [b'\x01\x02\x03'], 'DE_MAC': [b'\x01\x02\x03\x04'], 'DE_MBMS_BEARER_CAP': [b'\x01', b'\x7f'],
    'DE_MBMS_CTX_STATUS': [b'\xff\xff', b'\x01\x00\x80\x00', b'\xff\xff\xff\xff\xff\xff\xff\xff'],
    'DE_MBMS_PROT_CONF_OPT': [b'\x80', b'\x80\x00\x0c\x00'],
    'DE_MID': [TMSI, IMSI, IMEISV, b'\x08'],
    'DE_MS_CM_2': [b'\x57\x58\xa0', b'\x57\x18\x80'], 'DE_MS_CM_3': [b'\x60\x14\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00', b'\x40\x00\x00\x00\x00\x00\x00\x00'],
    'DE_MS_NET_CAP': ms_net_caps(), 'DE_NBIFOM_CONT': [b'\x01\x01\x01', b'\x01\x01\x01\x02\x01\x01\x03\x01\x00', b'\x03\x01\x02'],
    'DE_NETWORK_NAME': [b'\x80' + b'Test'], 'DE_NET_RES_ID_CONT': [b'\x01\x02', b'\x01\x02\x03'],
    'DE_PACKET_FLOW_ID': [b'\x08', b'\x01', b'\x02', b'\x03', b'\x09'], 'DE_PDP_CONTEXT_STAT': [b'\xff\xff', b'\x20\x00'],
    'DE_PD_PRO_ADDR': [pdp_addr(k) for k in ('v4', 'v6', 'v46', 'dyn4', 'dyn6', 'dyn46', 'ppp', 'nonip', 'ppp_addr', 'empty', 'unk', 'v4unk', 'etsi_unknown')],
    'DE_PLMN_ID_CN_OPERATOR': [PLMN], 'DE_PLMN_LIST': [PLMN + PLMN],
    'DE_PS_LCS_CAP': [b'\x7f', b'\x7f\x03', b'\x7f\x03\x01'], 'DE_QOS': QOS,
    'DE_RAI_2': [PLMN + b'\x00\x01\x02'], 'DE_RAT_INFO_CONTAINER': [b'\x00\x00'],
    'DE_REC_N_PDU_NUM_LIST': [b'\x51\x02\x62\x03', b'\x51\x02'], 'DE_RE_ATTEMPT_IND': [b'\x01', b'\x00'],
    'DE_SM_CAUSE_2': [b'\x1a', b'\x24'], 'DE_SM_NOTIF_IND': [b'\x00', b'\x01'],
    'DE_SUP_CODEC_LIST': [bytes([0x00, 0x02, 0xaf, 0xff, 0x04, 0x02, 0x40, 0x00])],
    'DE_TRAFFIC_FLOW_TEMPLATE': tft_variants(), 'DE_TMGI': [tmgi(0), tmgi(1), tmgi(2)],
    'DE_UPLINK_DATA_STATUS': [b'\xff\xff', b'\x01\x00'], 'DE_VOICE_DOMAIN_PREF': [b'\x03', b'\x0f', b'\x00'],
    'DE_P_TMSI_SIG_2': [b'\x01\x02\x03'], 'DE_EXT_PRO_CONF_OPT': None, 'DE_PRO_CONF_OPT': None,
    'DE_MS_RAD_ACC_CAP': None,
}

FORCE = None
RA_FORCE = None

def pick(lst, v):
    return lst[v % len(lst)]

def element(mac, iei, de, v, dl, ra_seed, pd8=False, unk=False):
    if FORCE and FORCE[0] == de.split(':')[0]:
        v = FORCE[1]
    elif FORCE:
        v = 0
    if mac == 'MAND_VV_SHORT':
        a, b = de.split(':')
        lo = pick(SHORT.get(a, [0]), v)
        hi = pick(SHORT.get(b, [0]), v + 1)
        return bytes([(hi << 4) | lo])
    if mac == 'OPT_TV_SHORT':
        return bytes([int(iei, 16) | pick(SHORT[de], v)])
    if mac == 'OPT_T':
        return bytes([int(iei, 16)])
    if mac == 'MAND_V' and de == 'DE_RAD_PRIO_2':
        return b''      # shares its octet with the next element (Attach Accept)
    if mac == 'MAND_V' and de == 'DE_RAD_PRIO' and pd8:
        return bytes([(pick([2, 4, 1], v) << 4) | pick([1, 4, 3], v)])
    if mac in ('MAND_V', 'OPT_TV'):
        c = pick(V_LEN.get(de) or TV_LEN[de], v)
        return (bytes([int(iei, 16)]) if mac == 'OPT_TV' else b'') + c
    if de == 'DE_MS_RAD_ACC_CAP':
        c = ra_cap(*RA_FORCE) if RA_FORCE else ra_cap(ra_seed, 1 + v % 3)
    elif de in ('DE_EXT_PRO_CONF_OPT', 'DE_PRO_CONF_OPT'):
        cs = pco_generic() if unk else (pco_dl() if dl else pco_ul())
        if mac == 'OPT_TLV_E':
            c = b'\x80' + b''.join(cs)
        else:   # at most 255 octets: chunk number v
            chunks, cur = [], b''
            for x in cs:
                if x[:2] == b'\x00\x56':
                    continue    # the 5GS dissector changes the link direction
                if len(cur) + len(x) > 240:
                    chunks.append(cur); cur = b''
                cur += x
            chunks.append(cur)
            c = b'\x80' + chunks[v % len(chunks)]
    else:
        c = pick(VAR[de], v)
    if mac == 'MAND_LV':
        return bytes([len(c)]) + c
    if mac == 'OPT_TLV':
        return tlv(int(iei, 16), c)
    if mac == 'OPT_TLV_E':
        return tlve(int(iei, 16), c)
    raise Exception(mac)

DIRTY = {'DE_EUTRAN_IRAT_INFO_CONTAINER'}
DETACH = {'MO': [('MAND_VV_SHORT', None, 'GM', 'DE_DETACH_TYPE:DE_SPARE_NIBBLE'), ('OPT_TLV', '0x18', 'COMMON', 'DE_MID'),
                 ('OPT_TLV', '0x19', 'GM', 'DE_P_TMSI_SIG_2')],
          'MT': [('MAND_VV_SHORT', None, 'GM', 'DE_DETACH_TYPE:DE_FORCE_TO_STAND_H'), ('OPT_TV', '0x25', 'GM', 'DE_GMM_CAUSE')]}

def message(pd, code, v, ra_seed=1, drop=(), dirty=False, variant=None):
    name, els = MSGS[(pd, code)]
    if variant:
        els = DETACH[variant]
    if pd == 8:
        dl = code in (2, 4, 6, 9, 11, 13, 14, 16, 18, 20, 21, 33) or variant == 'MT'
        hdr = bytes([0x08, code])
        link = DL if dl else UL
    else:
        dl = code not in SM_UL
        unk = code in SM_UNKNOWN
        hdr = bytes([0x0a | ((v & 7) << 4), code])
        link = DL if dl else UL
    body = b''
    for i, (mac, iei, p, de) in enumerate(els):
        if i in drop or (de in DIRTY and not dirty):
            continue
        body += element(mac, iei, de, v, dl, ra_seed + i, pd == 8, pd == 10 and code in SM_UNKNOWN)
    return exp_pdu(hdr + body, link)

RA_GOOD = [(1, 1), (5, 1), (10, 1), (14, 1), (19, 1), (24, 1), (28, 1), (32, 1), (37, 1), (42, 1), (47, 1), (51, 1), (56, 1), (60, 1), (64, 1), (68, 1), (72, 1), (77, 1), (82, 1), (86, 1), (90, 1), (94, 1), (5, 2), (12, 2), (19, 2), (26, 2), (35, 2), (41, 2), (47, 2), (52, 2), (58, 2), (64, 2), (70, 2), (75, 2), (83, 2), (89, 2), (94, 2), (102, 2), (1, 3), (15, 3), (28, 3), (38, 3), (50, 3), (61, 3), (70, 3), (83, 3), (93, 3), (109, 3), (1, 4), (24, 4), (42, 4), (60, 4), (78, 4), (96, 4)]   # (seed, number of capabilities) that decode without errors

def build(outdir):
    global RA_FORCE
    f = []
    ras = 1
    ran = [0]
    def nra():
        global RA_FORCE
        RA_FORCE = RA_GOOD[ran[0] % len(RA_GOOD)]
        ran[0] += 1
    for (pd, code) in sorted(MSGS):
        if (pd, code) == (8, 5):
            continue
        for v in range(3):
            nra()
            f.append(message(pd, code, v, ras))
            ras += 7
    for variant in ('MO', 'MT'):
        for v in range(3):
            nra()
            f.append(message(8, 5, v, ras, variant=variant))
    # extra variants of the element contents: QoS, TFT, PDP address, MS network
    # capability, PCO in both directions with every shape
    for v in range(3, 14):
        for code in (0x41, 0x42, 0x48, 0x4a, 0x4d, 0x4e, 0x5b):
            nra()
            f.append(message(10, code, v, ras))
            ras += 3
    for v in range(3, 8):
        for code in (1, 8, 2, 9):
            nra()
            f.append(message(8, code, v, ras))
            ras += 5
    # RA capabilities: many random ones in Attach and RAU requests
    for i in range(len(RA_GOOD) * 2):
        nra()
        f.append(message(8, 1 if i % 2 else 8, i, i))
    write_pcap(os.path.join(outdir, 'gsm_a_gm-coverage.pcap'), f)
    # ---- malformed capture
    b = []
    RA_FORCE = None
    # elements that decode with errors: E-UTRAN container, Receive N-PDU list of 1
    # octet (the fix), unvetted RA capabilities
    for v in range(3):
        b.append(message(8, 2, v, 3, dirty=True))
        b.append(message(8, 9, v, 3, dirty=True))
        b.append(message(8, 10, v, 3, dirty=True))
    for s in range(40):
        for code in (1, 8):
            RA_FORCE = (s, 1 + s % 4)
            b.append(message(8, code, s, s))
    RA_FORCE = None
    for code in (9, 10):
        b.append(exp_pdu(bytes([0x08, code, 0x26, 1, 0x05]), UL))
    # PCO with container lengths running over, 2 octet lengths, short containers
    for pid, ln in ((0xff00, 2), (0xff00, 1), (0x0001, 40), (0x0023, 40), (0x0003, 17)):
        for dirn in (UL, DL):
            b.append(exp_pdu(bytes([0x0a | 0x10, 0x42 if dirn == DL else 0x41]) + (b'\x00' if dirn == DL else b'\x00') + b'', dirn))
    for dirn, code in ((DL, 0x42), (UL, 0x41), (DL, 0x47), (UL, 0x45)):
        for bad in (struct.pack('>HB', 0xff00, 2) + b'\x12', struct.pack('>HB', 0x0001, 40) + b'\x00' * 3,
                    struct.pack('>HH', 0x0023, 40) + b'\x00' * 3, struct.pack('>HB', 0xff00, 1) + b'\x12', b'\x00\x0d'):
            body = b'\x80' + bad
            b.append(exp_pdu(bytes([0x0a, code]) + bytes([0x00] * 0) + b'\x7b' + struct.pack('>H', len(body)) + body, dirn))
    # truncated messages: every prefix of a few full messages
    for pd, code in ((8, 1), (8, 2), (8, 9), (10, 65), (10, 66), (10, 72), (10, 77), (8, 18)):
        full = message(pd, code, 0, 5)
        hdr_len = len(full) - len(full.split(b'\0\0\0\0')[-1])
        pdu = full
        for cut in range(8, 40):
            b.append(pdu[:len(pdu) - cut] if cut < len(pdu) - 40 else pdu[:60 - cut])
    # TFT: filters running over the element
    for t in (bytes([0x21, 0x01, 0x10, 0x40, 0x10, 1]), bytes([0x23, 0x01, 0x10, 0x01, 0x10]),
              bytes([0x31, 0x01, 0x10, 0x03, 0x30, 6]), bytes([0x31, 0x01, 0x10, 0x02]), bytes([0x30, 0x01]),
              bytes([0x32, 0x01, 0x10, 0x00, 0x01, 0x10, 0x00]), bytes([0x30, 0x02, 0x05]), bytes([0x30 | 0x10 | 0, 0x05, 0x03]),
              bytes([0x31, 0x01, 0x10, 0x01, 0x30, 0x01, 0x02])):
        b.append(exp_pdu(bytes([0x0a, 0x4d, 0x05, 0x03, 0x0b, 0x03, 0x13, 0x73, 0x1f, 0x01, 0x01, 0x36, len(t)]) + t, UL))
    write_pcap(os.path.join(outdir, 'gsm_a_gm-coverage-malformed.pcap'), b)
    print(len(f), len(b))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
