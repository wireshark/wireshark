/* packet-tlv.h
 * Contains Definitions for Configuration types
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/* Define Top Level TLV Types
 * Please see http://www.cablemodem.com/Specs/SP-RFIv1.1-I08-020301.pdf
 * Appendix C.
 */
#ifndef __PACKET_TLV_H__
#define __PACKET_TLV_H__
#define TLV_DOWN_FREQ 1
#define TLV_CHNL_ID 2
#define TLV_NET_ACCESS 3
#define TLV_COS 4
#define TLV_MODEM_CAP 5
#define TLV_CM_MIC 6
#define TLV_CMTS_MIC 7
#define TLV_VENDOR_ID 8
#define TLV_SW_UPG_FILE 9
#define TLV_SNMP_WRITE_CTRL 10
#define TLV_SNMP_OBJECT 11
#define TLV_MODEM_IP 12
#define TLV_SVC_UNAVAIL 13
#define TLV_ETHERNET_MAC 14
#define TLV_TEL_SETTINGS 15
#define TLV_BPI_CONFIG 17
#define TLV_MAX_CPES 18
#define TLV_TFTP_TIME 19
#define TLV_TFTP_MODEM_ADDRESS 20
#define TLV_SW_UPG_SRVR 21
#define TLV_UPSTREAM_CLASSIFIER 22
#define TLV_DOWN_CLASSIFIER 23
#define TLV_UPSTREAM_SERVICE_FLOW 24
#define TLV_DOWN_SERVICE_FLOW 25
#define TLV_PHS 26
#define TLV_HMAC_DIGEST 27
#define TLV_MAX_CLASSIFIERS 28
#define TLV_PRIVACY_ENABLE 29
#define TLV_AUTH_BLOCK 30
#define TLV_KEY_SEQ_NUM 31
#define TLV_MFGR_CVC 32
#define TLV_COSIGN_CVC 33
#define TLV_SNMPV3_KICKSTART 34
#define TLV_SUBS_MGMT_CTRL 35
#define TLV_SUBS_MGMT_CPE 36
#define TLV_SUBS_MGMT_FLTR 37
#define TLV_VENDOR_SPEC 43
#define TLV_END 255

/* Define DOCSIS 1.0 Class Of Service Configuration Types
 * These are subtypes of TLV_COS (4)
 */
#define COS_CLASSID 1
#define COS_MAX_DOWN 2
#define COS_MAX_UP 3
#define COS_UP_CH_PRIO 4
#define COS_MIN_UP_RATE 5
#define COS_MAX_UP_BURST 6
#define COS_BP_ENABLE 7

/* Define SNMPV3 KickStart subtypes
 * These are subtypes of TLV_SNMPV3_KICKSTART (34)
 */
#define SNMPV3_SEC_NAME 1
#define SNMPV3_MGR_PUB_NUM 2

/* Define Modem Capabilities Subtypes
 * These are subtypes of TLV_MODEM_CAP (5)
 */
#define CAP_CONCAT 1
#define CAP_DOCSIS_VER 2
#define CAP_FRAG 3
#define CAP_PHS 4
#define CAP_IGMP 5
#define CAP_PRIVACY 6
#define CAP_DOWN_SAID 7
#define CAP_UP_SID 8
#define CAP_OPT_FILT 9
#define CAP_XMIT_EQPERSYM 10
#define CAP_NUM_XMIT_EQ_TAPS 11
#define CAP_DCC 12

/* Define Classifier subtypes
 * These are subtypes of either:
 * TLV_UPSTREAM_CLASSIFIER (22)
 * TLV_DOWN_CLASSIFIER (23)
 */
#define CFR_REF 1
#define CFR_ID 2
#define CFR_SFLOW_REF 3
#define CFR_SFLOW_ID 4
#define CFR_RULE_PRI 5
#define CFR_ACT_STATE 6
#define CFR_DSA_ACTION 7
#define CFR_ERROR 8
#define CFR_IP_CLASSIFIER 9
#define CFR_ETH_CLASSIFIER 10
#define CFR_8021Q_CLASSIFIER 11
#define CFR_VENDOR_SPEC 43

/* Define Classifier Error sub-subtypes
 * These are subtypes of CFR_ERROR ([22/23].8)
 */
#define CFR_ERR_PARAM 1
#define CFR_ERR_CODE 2
#define CFR_ERR_MSG 3

/* Define IP Classifier sub-subtypes
 * These are subtypes of CFR_IP_CLASSIFIER ([22/23].9)
 */
#define CFR_IP_TOS_RANGE_MASK 1
#define CFR_IP_PROTO 2
#define CFR_IP_SOURCE_ADDR 3
#define CFR_IP_SOURCE_MASK 4
#define CFR_IP_DEST_ADDR 5
#define CFR_IP_DEST_MASK 6
#define CFR_IP_SRCPORT_START 7
#define CFR_IP_SRCPORT_END 8
#define CFR_IP_DSTPORT_START 9
#define CFR_IP_DSTPORT_END 10

/* Define Ethertype Classifier sub-subtypes
 * These are subtypes of CFR_ETH_CLASSIFIER ([22/23].10)
 */
#define CFR_ETH_DST_MAC 1
#define CFR_ETH_SRC_MAC 2
#define CFR_ETH_DSAP 3

/* Define 802.1P/Q Classifier sub-subtypes
 * These are subtypes of CFR_8021Q_CLASSIFIER ([22/23].11)
 */
#define CFR_D1Q_USER_PRI 1
#define CFR_D1Q_VLAN_ID 2
#define CFR_D1Q_VENDOR_SPEC 43

/* Define Upstream/Downstream Service flow subtypes
 * These are subtypes of:
 * TLV_UPSTREAM_SERVICE_FLOW (24)
 * TLV_DOWN_SERVICE_FLOW (25)
 */
#define SFW_REF 1
#define SFW_ID 2
#define SFW_SID 3
#define SFW_SERVICE_CLASS_NAME 4
#define SFW_ERRORS 5
#define SFW_QOS_SET_TYPE 6
#define SFW_TRAF_PRI 7
#define SFW_MAX_SUSTAINED 8
#define SFW_MAX_BURST 9
#define SFW_MIN_RSVD_TRAF 10
#define SFW_MIN_RSVD_PACKETSIZE 11
#define SFW_ACTIVE_QOS_TIMEOUT 12
#define SFW_ADMITT_QOS_TIMEOUT 13
#define SFW_VENDOR_SPEC 43
/* The following types only apply to
 * TLV_UPSTREAM_SERVICE_FLOW (24)
 */
#define SFW_MAX_CONCAT_BURST 14
#define SFW_SCHEDULING_TYPE 15
#define SFW_REQ_XMIT_POL 16
#define SFW_NOM_POLL_INT 17
#define SFW_POLL_JTTR_TOL 18
#define SFW_UG_SIZE 19
#define SFW_NOM_GRNT_INTV 20
#define SFW_GRNT_JTTR_TOL 21
#define SFW_GRNTS_PER_INTV 22
#define SFW_IP_TOS_OVERWRITE 23
#define SFW_UG_TIME_REF 24

/* The following types only apply to
 * TLV_DOWN_SERVICE_FLOW (25)
 */
#define SFW_MAX_DOWN_LAT 14

/* Define Service Flow Error sub-subtypes
 * These are subtypes of
 * SFW_ERRORS ([24/25].5)
 */
#define SFW_ERR_PARAM 1
#define SFW_ERR_CODE 2
#define SFW_ERR_MSG 3


/* Define Payload Header Supression subtypes
 * These are subtypes of TLV_PHS (26)
 */
#define PHS_CLSFR_REF 1
#define PHS_CLSFR_ID 2
#define PHS_SFLOW_REF 3
#define PHS_SFLOW_ID 4
#define PHS_DSC_ACTION 5
#define PHS_ERRORS 6
#define PHS_FIELD 7
#define PHS_INDEX 8
#define PHS_MASK 9
#define PHS_SUP_SIZE 10
#define PHS_VERIFICATION 11
#define PHS_VENDOR_SPEC 43

/* Define PHS Error sub-subtypes
 * These are subtypes of PHS_ERRORS (26.6)
 */
#define PHS_ERR_PARAM 1
#define PHS_ERR_CODE 2
#define PHS_ERR_MSG 3

#endif
