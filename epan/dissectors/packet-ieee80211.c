/* packet-ieee80211.c
 * Routines for Wireless LAN (IEEE 802.11) dissection
 * Copyright 2000, Axis Communications AB
 * Inquiries/bugreports should be sent to Johan.Jorgensen@axis.com
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 *
 * Credits:
 *
 * The following people helped me by pointing out bugs etc. Thank you!
 *
 * Marco Molteni
 * Lena-Marie Nilsson
 * Magnus Hultman-Persson
 */

/*
 * 09/12/2003 - Added dissection of country information tag
 *
 * Ritchie<at>tipsybottle.com
 *
 * 03/22/2004 - Added dissection of RSN IE
 * Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * 10/24/2005 - Add dissection for 802.11e
 * Zhu Yi <yi.zhu@intel.com>
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <glib.h>
#include <epan/bitswap.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-ieee80211.h"
#include <epan/etypes.h>
#include <epan/oui.h>
#include <epan/crc32.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/crypt/wep-wpadefs.h>

#include <ctype.h>
#include "isprint.h"

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include <airpcap_loader.h>
#else
/* XXX - This is probably a bit much */
#define MAX_ENCRYPTION_KEYS 64
#endif

#ifndef roundup2
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

/* Defragment fragmented 802.11 datagrams */
static gboolean wlan_defragment = TRUE;

/* Check for the presence of the 802.11 FCS */
static gboolean wlan_check_fcs = FALSE;

/* Ignore the WEP bit; assume packet is decrypted */
#define WLAN_IGNORE_WEP_NO     0
#define WLAN_IGNORE_WEP_WO_IV  1
#define WLAN_IGNORE_WEP_W_IV   2
static gint wlan_ignore_wep = WLAN_IGNORE_WEP_NO;

/* Tables for reassembly of fragments. */
static GHashTable *wlan_fragment_table = NULL;
static GHashTable *wlan_reassembled_table = NULL;

/* Stuff for the WEP decoder */

static gint num_wepkeys = 0;
static gboolean enable_decryption = FALSE;
static guint8 **wep_keys = NULL;
static int *wep_keylens = NULL;
static void init_wepkeys(void);
#ifndef	HAVE_AIRPDCAP
static tvbuff_t *try_decrypt_wep(tvbuff_t *tvb, guint32 offset, guint32 len);
static int wep_decrypt(guint8 *buf, guint32 len, int key_override);
#else
/* Davide Schiera (2006-11-26): created function to decrypt WEP and WPA/WPA2	*/
static tvbuff_t *try_decrypt(tvbuff_t *tvb, guint32 offset, guint32 len, guint8 *algorithm, guint32 *sec_header, guint32 *sec_trailer);
#endif
static int weak_iv(guchar *iv);
#define SSWAP(a,b) {guint8 tmp = s[a]; s[a] = s[b]; s[b] = tmp;}

/* #define USE_ENV */
/* When this is set, an unlimited number of WEP keys can be set in the
   environment:

   WIRESHARK_WEPKEYNUM=##
   WIRESHARK_WEPKEY1=aa:bb:cc:dd:...
   WIRESHARK_WEPKEY2=aa:bab:cc:dd:ee:...

   ... you get the idea.

   otherwise you're limited to specifying four keys in the preference system.
 */

#ifndef USE_ENV
static char *wep_keystr[MAX_ENCRYPTION_KEYS];
#endif

/* ************************************************************************* */
/*                          Miscellaneous Constants                          */
/* ************************************************************************* */
#define SHORT_STR 256

/* ************************************************************************* */
/*  Define some very useful macros that are used to analyze frame types etc. */
/* ************************************************************************* */

/*
 * Extract the protocol version from the frame control field
 */
#define FCF_PROT_VERSION(x)  ((x) & 0x3)

/*
 * Extract the frame type from the frame control field.
 */
#define FCF_FRAME_TYPE(x)    (((x) & 0xC) >> 2)

/*
 * Extract the frame subtype from the frame control field.
 */
#define FCF_FRAME_SUBTYPE(x) (((x) & 0xF0) >> 4)

/*
 * Convert the frame type and subtype from the frame control field into
 * one of the MGT_, CTRL_, or DATA_ values.
 */
#define COMPOSE_FRAME_TYPE(x) (((x & 0x0C)<< 2)+FCF_FRAME_SUBTYPE(x))	/* Create key to (sub)type */

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)  ((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x) ((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)    ((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)     ((x) & 0x08)

/*
 * Extract the flags from the frame control field.
 */
#define FCF_FLAGS(x)           (((x) & 0xFF00) >> 8)

/*
 * Bits from the flags field.
 */
#define FLAG_TO_DS		0x01
#define FLAG_FROM_DS		0x02
#define FLAG_MORE_FRAGMENTS	0x04
#define FLAG_RETRY		0x08
#define FLAG_POWER_MGT		0x10
#define FLAG_MORE_DATA		0x20
#define FLAG_PROTECTED		0x40
#define FLAG_ORDER		0x80

/*
 * Test bits in the flags field.
 */
/*
 * XXX - Only HAVE_FRAGMENTS and IS_PROTECTED are in use.  Should the rest
 * be removed?
 */
#define IS_TO_DS(x)            ((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          ((x) & FLAG_FROM_DS)
#define HAVE_FRAGMENTS(x)      ((x) & FLAG_MORE_FRAGMENTS)
#define IS_RETRY(x)            ((x) & FLAG_RETRY)
#define POWER_MGT_STATUS(x)    ((x) & FLAG_POWER_MGT)
#define HAS_MORE_DATA(x)       ((x) & FLAG_MORE_DATA)
#define IS_PROTECTED(x)        ((x) & FLAG_PROTECTED)
#define IS_STRICTLY_ORDERED(x) ((x) & FLAG_ORDER)

/*
 * Extract subfields from the flags field.
 */
#define FLAGS_DS_STATUS(x)          ((x) & (FLAG_FROM_DS|FLAG_TO_DS))

/*
 * Extract an indication of the types of addresses in a data frame from
 * the frame control field.
 */
#define FCF_ADDR_SELECTOR(x) ((x) & ((FLAG_TO_DS|FLAG_FROM_DS) << 8))

#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         (FLAG_FROM_DS << 8)
#define DATA_ADDR_T3         (FLAG_TO_DS << 8)
#define DATA_ADDR_T4         ((FLAG_TO_DS|FLAG_FROM_DS) << 8)

/*
 * Extract the fragment number and sequence number from the sequence
 * control field.
 */
#define SEQCTL_FRAGMENT_NUMBER(x) ((x) & 0x000F)
#define SEQCTL_SEQUENCE_NUMBER(x) (((x) & 0xFFF0) >> 4)

/*
 * Extract subfields from the QoS control field.
 */
#define QOS_TID(x)	      ((x) & 0x000F)
#define QOS_PRIORITY(x)       ((x) & 0x0007)
#define QOS_EOSP(x)	      (((x) & 0x0010) >> 4) /* end of service period */
#define QOS_ACK_POLICY(x)     (((x) & 0x0060) >> 5)
#define QOS_AMSDU_PRESENT(x)     (((x) & 0x0080) >> 6)
#define QOS_FIELD_CONTENT(x)  (((x) & 0xFF00) >> 8)

#define QOS_FLAG_EOSP		0x08

/*
 * Extract subfields from the result of QOS_FIELD_CONTENT().
 */
#define QOS_PS_BUF_STATE(x)	(((x) & 0x02) >> 1)
#define QOS_PS_BUF_AC(x)	(((x) & 0x0C) >> 2)
#define QOS_PS_BUF_LOAD(x)	(((x) & 0xF0) >> 4)

/*
 * Extract subfields from the HT Control field.
 * .11n D-1.10 & D-2.0, 7.1.3.5a, 32 bits.
 */
#define HTC_LAC(htc)		((htc) & 0xFF)
#define HTC_LAC_MAI(htc)	(((htc) >> 2) & 0xF)
#define IS_ASELI(htc)		(HTC_LAC_MAI(htc) == 0x7)
#define HTC_LAC_MAI_MSI(htc)	((HTC_LAC_MAI(htc) >> 1) & 0x3)
#define HTC_LAC_MFSI(htc)	(((htc) >> 4) & 0x7)
#define HTC_LAC_ASEL_CMD(htc)	(((htc) >> 9) & 0x7)
#define HTC_LAC_ASEL_DATA(htc)	(((htc) >> 12) & 0xF)
#define HTC_LAC_MFB(htc)	(((htc) >> 9) & 0x7F)
#define HTC_CAL_POS(htc)	(((htc) >> 16) & 0x3)
#define HTC_CAL_SEQ(htc)	(((htc) >> 18) & 0x3)
#define HTC_CSI_STEERING(htc)	(((htc) >> 22) & 0x3)
#define HTC_NDP_ANN(htc)	(((htc) >> 24) & 0x1)
#define HTC_AC_CONSTRAINT(htc)	(((htc) >> 30) & 0x1)
#define HTC_RDG_MORE_PPDU(htc)	(((htc) >> 31) & 0x1)

/*
 * Extract the association ID from the value in an association ID field.
 */
#define ASSOC_ID(x)             ((x) & 0x3FFF)

/*
 * Extract subfields from the key octet in WEP-encrypted frames.
 */
#define KEY_OCTET_WEP_KEY(x)    (((x) & 0xC0) >> 6)

/*
 * Extract subfields from TS Info field.
 */
#define TSI_TYPE(x)		(((x) & 0x000001) >> 0)
#define TSI_TSID(x)		(((x) & 0x00001E) >> 1)
#define TSI_DIR(x)		(((x) & 0x000060) >> 5)
#define TSI_ACCESS(x)		(((x) & 0x000180) >> 7)
#define TSI_AGG(x)		(((x) & 0x000200) >> 9)
#define TSI_APSD(x)		(((x) & 0x000400) >> 10)
#define TSI_UP(x)		(((x) & 0x003800) >> 11)
#define TSI_ACK(x)		(((x) & 0x00C000) >> 14)
#define TSI_SCHED(x)		(((x) & 0x010000) >> 16)
#define TSI_RESERVED(x)		(((x) & 0xFE0000) >> 17)

#define KEY_EXTIV		0x20
#define EXTIV_LEN		8


/* ************************************************************************* */
/*              Constants used to identify cooked frame types                */
/* ************************************************************************* */
#define MGT_FRAME            0x00	/* Frame type is management */
#define CONTROL_FRAME        0x01	/* Frame type is control */
#define DATA_FRAME           0x02	/* Frame type is Data */

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24	/* Length of Managment frame-headers */

/*
 * COMPOSE_FRAME_TYPE() values for management frames.
 */
#define MGT_ASSOC_REQ        0x00	/* association request        */
#define MGT_ASSOC_RESP       0x01	/* association response       */
#define MGT_REASSOC_REQ      0x02	/* reassociation request      */
#define MGT_REASSOC_RESP     0x03	/* reassociation response     */
#define MGT_PROBE_REQ        0x04	/* Probe request              */
#define MGT_PROBE_RESP       0x05	/* Probe response             */
#define MGT_BEACON           0x08	/* Beacon frame               */
#define MGT_ATIM             0x09	/* ATIM                       */
#define MGT_DISASS           0x0A	/* Disassociation             */
#define MGT_AUTHENTICATION   0x0B	/* Authentication             */
#define MGT_DEAUTHENTICATION 0x0C	/* Deauthentication           */
#define MGT_ACTION           0x0D	/* Action */
#define MGT_ACTION_NO_ACK    0x0E	/* Action No Ack */

/*
 * COMPOSE_FRAME_TYPE() values for control frames.
 */
#define CTRL_CONTROL_WRAPPER 0x17	/* Control Wrapper		    */
#define CTRL_BLOCK_ACK_REQ   0x18	/* Block ack Request		    */
#define CTRL_BLOCK_ACK	      0x19	/* Block ack			    */
#define CTRL_PS_POLL         0x1A	/* power-save poll               */
#define CTRL_RTS             0x1B	/* request to send               */
#define CTRL_CTS             0x1C	/* clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 0x1D	/* acknowledgement               */
#define CTRL_CFP_END         0x1E	/* contention-free period end    */
#define CTRL_CFP_ENDACK      0x1F	/* contention-free period end/ack */

/*
 * COMPOSE_FRAME_TYPE() values for data frames.
 */
#define DATA                        0x20	/* Data                       */
#define DATA_CF_ACK                 0x21	/* Data + CF-Ack              */
#define DATA_CF_POLL                0x22	/* Data + CF-Poll             */
#define DATA_CF_ACK_POLL            0x23	/* Data + CF-Ack + CF-Poll    */
#define DATA_NULL_FUNCTION          0x24	/* Null function (no data)    */
#define DATA_CF_ACK_NOD             0x25	/* CF-Ack (no data)           */
#define DATA_CF_POLL_NOD            0x26	/* CF-Poll (No data)          */
#define DATA_CF_ACK_POLL_NOD        0x27	/* CF-Ack + CF-Poll (no data) */

#define DATA_QOS_DATA               0x28	/* QoS Data                   */
#define DATA_QOS_DATA_CF_ACK        0x29	/* QoS Data + CF-Ack	      */
#define DATA_QOS_DATA_CF_POLL       0x2A	/* QoS Data + CF-Poll		  */
#define DATA_QOS_DATA_CF_ACK_POLL   0x2B	/* QoS Data + CF-Ack + CF-Poll	  */
#define DATA_QOS_NULL               0x2C	/* QoS Null			  */
#define DATA_QOS_CF_POLL_NOD        0x2E	/* QoS CF-Poll (No Data)		  */
#define DATA_QOS_CF_ACK_POLL_NOD    0x2F	/* QoS CF-Ack + CF-Poll (No Data) */


/* ************************************************************************* */
/*          Macros used to extract information about fixed fields            */
/* ************************************************************************* */
#define ESS_SET(x) ((x) & 0x0001)
#define IBSS_SET(x) ((x) & 0x0002)



/* ************************************************************************* */
/*        Logical field codes (dissector's encoding of fixed fields)         */
/* ************************************************************************* */
#define FIELD_TIMESTAMP       0x01	/* 64-bit timestamp                       */
#define FIELD_BEACON_INTERVAL 0x02	/* 16-bit beacon interval                 */
#define FIELD_CAP_INFO        0x03	/* Add capability information tree        */
#define FIELD_AUTH_ALG        0x04	/* Authentication algorithm used          */
#define FIELD_AUTH_TRANS_SEQ  0x05	/* Authentication sequence number         */
#define FIELD_CURRENT_AP_ADDR 0x06
#define FIELD_LISTEN_IVAL     0x07
#define FIELD_REASON_CODE     0x08
#define FIELD_ASSOC_ID        0x09
#define FIELD_STATUS_CODE     0x0A
#define FIELD_CATEGORY_CODE   0x0B	/* Management action category */
#define FIELD_ACTION_CODE     0x0C	/* Management action code */
#define FIELD_DIALOG_TOKEN    0x0D	/* Management action dialog token */
#define FIELD_WME_ACTION_CODE	0x0E	/* Management notification action code */
#define FIELD_WME_DIALOG_TOKEN	0x0F	/* Management notification dialog token */
#define FIELD_WME_STATUS_CODE	0x10	/* Management notification setup response status code */
#define FIELD_QOS_ACTION_CODE	0x11
#define FIELD_QOS_TS_INFO	0x12
#define FIELD_DLS_ACTION_CODE	0x13
#define FIELD_DST_MAC_ADDR	0X14	/* DLS destination MAC address */
#define FIELD_SRC_MAC_ADDR	0X15	/* DLS source MAC address */
#define FIELD_DLS_TIMEOUT	0X16	/* DLS timeout value */
#define FIELD_SCHEDULE_INFO	0X17	/* Schedule Info field */
#define FIELD_ACTION	0X18	/* Action field */

/* ************************************************************************* */
/*        Logical field codes (IEEE 802.11 encoding of tags)                 */
/* ************************************************************************* */
#define TAG_SSID                 0x00
#define TAG_SUPP_RATES           0x01
#define TAG_FH_PARAMETER         0x02
#define TAG_DS_PARAMETER         0x03
#define TAG_CF_PARAMETER         0x04
#define TAG_TIM                  0x05
#define TAG_IBSS_PARAMETER       0x06
#define TAG_COUNTRY_INFO         0x07
#define TAG_FH_HOPPING_PARAMETER 0x08
#define TAG_FH_HOPPING_TABLE     0x09
#define TAG_REQUEST		 0x0A
#define TAG_QBSS_LOAD		 0x0B
#define TAG_EDCA_PARAM_SET	 0x0C
#define TAG_TSPEC		 0x0D
#define TAG_TCLAS		 0x0E
#define TAG_SCHEDULE		 0x0F
#define TAG_CHALLENGE_TEXT       0x10
#define TAG_POWER_CONSTRAINT	 0x20
#define TAG_POWER_CAPABILITY	 0x21
#define TAG_TPC_REQUEST		 0x22
#define TAG_TPC_REPORT		 0x23
#define TAG_SUPPORTED_CHANNELS	 0x24
#define TAG_CHANNEL_SWITCH_ANN	 0x25
#define TAG_MEASURE_REQ		 0x26
#define TAG_MEASURE_REP		 0x27
#define TAG_QUIET		 0x28
#define TAG_IBSS_DFS		 0x29
#define TAG_ERP_INFO             0x2A
#define TAG_TS_DELAY		 0x2B
#define TAG_TCLAS_PROCESS	 0x2C
#define TAG_HT_CAPABILITY              0x2D	/* IEEE Stc 802.11n/D2.0 */
#define TAG_QOS_CAPABILITY	 0x2E
#define TAG_ERP_INFO_OLD         0x2F	/* IEEE Std 802.11g/D4.0 */
#define TAG_RSN_IE               0x30
#define TAG_EXT_SUPP_RATES       0x32
#define TAG_NEIGHBOR_REPORT      0x34
#define TAG_HT_INFO              0x3D	/* IEEE Stc 802.11n/D2.0 */
#define TAG_SECONDARY_CHANNEL_OFFSET 0x3E	/* IEEE Stc 802.11n/D1.10/D2.0 */
#define TAG_EXTENDED_CAPABILITIES    0X7F   /* IEEE Stc 802.11n/D1.10/D2.0 */
#define TAG_AGERE_PROPRIETARY	 0x80
#define TAG_CISCO_UNKNOWN_1	 0x85	/* Cisco Compatible eXtensions */
#define TAG_CISCO_UNKNOWN_2	 0x88	/* Cisco Compatible eXtensions? */
#define TAG_CISCO_UNKNOWN_3	 0x95	/* Cisco Compatible eXtensions */
#define TAG_VENDOR_SPECIFIC_IE	 0xDD
#define TAG_SYMBOL_PROPRIETARY	 0xAD
#if 0 /* Not yet assigned tag numbers by ANA */
#define TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT	 0xFF
#define TAG_SUPPORTED_REGULATORY_CLASSES	 0xFE
#endif

#define WPA_OUI	 (const guint8 *) "\x00\x50\xF2"
#define RSN_OUI (const guint8 *) "\x00\x0F\xAC"
#define WME_OUI (const guint8 *) "\x00\x50\xF2"
#define PRE_11N_OUI (const guint8 *) "\x00\x90\x4c" /* 802.11n pre 1 oui */

#define PMKID_LEN 16

/* ************************************************************************* */
/*                         Frame types, and their names                      */
/* ************************************************************************* */
static const value_string frame_type_subtype_vals[] = {
	{MGT_ASSOC_REQ,        "Association Request"},
	{MGT_ASSOC_RESP,       "Association Response"},
	{MGT_REASSOC_REQ,      "Reassociation Request"},
	{MGT_REASSOC_RESP,     "Reassociation Response"},
	{MGT_PROBE_REQ,        "Probe Request"},
	{MGT_PROBE_RESP,       "Probe Response"},
	{MGT_BEACON,           "Beacon frame"},
	{MGT_ATIM,             "ATIM"},
	{MGT_DISASS,           "Dissassociate"},
	{MGT_AUTHENTICATION,   "Authentication"},
	{MGT_DEAUTHENTICATION, "Deauthentication"},
	{MGT_ACTION,           "Action"},
	{MGT_ACTION_NO_ACK,         "Action No Ack"},

	{CTRL_CONTROL_WRAPPER,      "Control Wrapper"},
	{CTRL_BLOCK_ACK_REQ,   "802.11 Block Ack Req"},
	{CTRL_BLOCK_ACK,       "802.11 Block Ack"},
	{CTRL_PS_POLL,         "Power-Save poll"},
	{CTRL_RTS,             "Request-to-send"},
	{CTRL_CTS,             "Clear-to-send"},
	{CTRL_ACKNOWLEDGEMENT, "Acknowledgement"},
	{CTRL_CFP_END,         "CF-End (Control-frame)"},
	{CTRL_CFP_ENDACK,      "CF-End + CF-Ack (Control-frame)"},

	{DATA,                 "Data"},
	{DATA_CF_ACK,          "Data + CF-Ack"},
	{DATA_CF_POLL,         "Data + CF-Poll"},
	{DATA_CF_ACK_POLL,     "Data + CF-Ack + CF-Poll"},
	{DATA_NULL_FUNCTION,   "Null function (No data)"},
	{DATA_CF_ACK_NOD,      "Acknowledgement (No data)"},
	{DATA_CF_POLL_NOD,     "CF-Poll (No data)"},
	{DATA_CF_ACK_POLL_NOD, "CF-Ack/Poll (No data)"},
	{DATA_QOS_DATA,        "QoS Data"},
	{DATA_QOS_DATA_CF_ACK,	"QoS Data + CF-Acknowledgment"},
	{DATA_QOS_DATA_CF_POLL,	"QoS Data + CF-Poll"},
	{DATA_QOS_DATA_CF_ACK_POLL, "QoS Data + CF-Ack + CF-Poll"},
	{DATA_QOS_NULL,        "QoS Null function (No data)"},
	{DATA_QOS_CF_POLL_NOD,	"QoS CF-Poll (No Data)"},
	{DATA_QOS_CF_ACK_POLL_NOD,  "QoS CF-Ack + CF-Poll (No data)"},
	{0,                    NULL}
};

/* ************************************************************************* */
/*                             802.1D Tag Names                              */
/* ************************************************************************* */
static const char *qos_tags[8] = {
	"Best Effort",
	"Background",
	"Spare",
	"Excellent Effort",
	"Controlled Load",
	"Video",
	"Voice",
	"Network Control"
};

/* ************************************************************************* */
/*                 WME Access Category Names (by 802.1D Tag)                 */
/* ************************************************************************* */
static const char *qos_acs[8] = {
	"Best Effort",
	"Background",
	"Background",
	"Video",
	"Video",
	"Video",
	"Voice",
	"Voice"
};

/* ************************************************************************* */
/*                   WME Access Category Names (by WME ACI)                  */
/* ************************************************************************* */
static const char *wme_acs[4] = {
	"Best Effort",
	"Background",
	"Video",
	"Voice",
};


#define CAT_SPECTRUM_MGMT	0
#define CAT_QOS			1
#define CAT_DLS			2
#define CAT_BLOCK_ACK		3
#define CAT_MGMT_NOTIFICATION	17

#define SM_ACTION_MEASUREMENT_REQUEST	0
#define SM_ACTION_MEASUREMENT_REPORT	1
#define SM_ACTION_TPC_REQUEST		2
#define SM_ACTION_TPC_REPORT		3
#define SM_ACTION_CHAN_SWITCH_ANNC	4

#define SM_ACTION_ADDTS_REQUEST		0
#define SM_ACTION_ADDTS_RESPONSE	1
#define SM_ACTION_DELTS			2
#define SM_ACTION_QOS_SCHEDULE		3

#define SM_ACTION_DLS_REQUEST		0
#define SM_ACTION_DLS_RESPONSE		1
#define SM_ACTION_DLS_TEARDOWN		2

static int proto_wlan = -1;
static int proto_aggregate = -1;
static packet_info * g_pinfo;

/* ************************************************************************* */
/*                Header field info values for radio information             */
/* ************************************************************************* */
static int hf_data_rate = -1;
static int hf_channel = -1;
static int hf_signal_strength = -1;

/* ************************************************************************* */
/*                Header field info values for FC-field                      */
/* ************************************************************************* */
static int hf_fc_field = -1;
static int hf_fc_proto_version = -1;
static int hf_fc_frame_type = -1;
static int hf_fc_frame_subtype = -1;
static int hf_fc_frame_type_subtype = -1;

static int hf_fc_flags = -1;
static int hf_fc_to_ds = -1;
static int hf_fc_from_ds = -1;
static int hf_fc_data_ds = -1;

static int hf_fc_more_frag = -1;
static int hf_fc_retry = -1;
static int hf_fc_pwr_mgt = -1;
static int hf_fc_more_data = -1;
static int hf_fc_protected = -1;
static int hf_fc_order = -1;


/* ************************************************************************* */
/*                   Header values for Duration/ID field                     */
/* ************************************************************************* */
static int hf_did_duration = -1;
static int hf_assoc_id = -1;


/* ************************************************************************* */
/*         Header values for different address-fields (all 4 of them)        */
/* ************************************************************************* */
static int hf_addr_da = -1;	/* Destination address subfield */
static int hf_addr_sa = -1;	/* Source address subfield */
static int hf_addr_ra = -1;	/* Receiver address subfield */
static int hf_addr_ta = -1;	/* Transmitter address subfield */
static int hf_addr_addr1 = -1;
static int hf_addr_bssid = -1;	/* address is bssid */

static int hf_addr = -1;	/* Source or destination address subfield */


/* ************************************************************************* */
/*                Header values for QoS control field                        */
/* ************************************************************************* */
static int hf_qos_priority = -1;
static int hf_qos_ack_policy = -1;
static int hf_qos_amsdu_present = -1;
static int hf_qos_eosp = -1;
static int hf_qos_field_content = -1;
/*static int hf_qos_txop_limit = -1;*/
/*	FIXME: hf_ values not defined
static int hf_qos_buf_state = -1;
static int hf_qos_buf_ac = -1;
static int hf_qos_buf_load = -1;
*/
/*static int hf_qos_txop_dur_req = -1;
static int hf_qos_queue_size = -1;*/

/* ************************************************************************* */
/*                Header values for HT control field (+HTC)                  */
/* ************************************************************************* */
/* 802.11nD-1.10 & 802.11nD-2.0 7.1.3.5a */
static int hf_htc = -1;
static int hf_htc_lac = -1;
static int hf_htc_lac_trq = -1;
static int hf_htc_lac_mai_aseli = -1;
static int hf_htc_lac_mai_mrq = -1;
static int hf_htc_lac_mai_msi = -1;
static int hf_htc_lac_mfsi = -1;
static int hf_htc_lac_mfb = -1;
static int hf_htc_lac_asel_command = -1;
static int hf_htc_lac_asel_data = -1;
static int hf_htc_cal_pos = -1;
static int hf_htc_cal_seq = -1;
static int hf_htc_csi_steering = -1;
static int hf_htc_ndp_announcement = -1;
static int hf_htc_ac_constraint = -1;
static int hf_htc_rdg_more_ppdu = -1;

/* ************************************************************************* */
/*                Header values for sequence number field                    */
/* ************************************************************************* */
static int hf_frag_number = -1;
static int hf_seq_number = -1;

/* ************************************************************************* */
/*                   Header values for Frame Check field                     */
/* ************************************************************************* */
static int hf_fcs = -1;
static int hf_fcs_good = -1;
static int hf_fcs_bad = -1;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_fragments = -1;
static int hf_fragment = -1;
static int hf_fragment_overlap = -1;
static int hf_fragment_overlap_conflict = -1;
static int hf_fragment_multiple_tails = -1;
static int hf_fragment_too_long_fragment = -1;
static int hf_fragment_error = -1;
static int hf_reassembled_in = -1;


static int proto_wlan_mgt = -1;
/* ************************************************************************* */
/*                      Fixed fields found in mgt frames                     */
/* ************************************************************************* */
static int ff_auth_alg = -1;	/* Authentication algorithm field            */
static int ff_auth_seq = -1;	/* Authentication transaction sequence       */
static int ff_current_ap = -1;	/* Current AP MAC address                    */
static int ff_listen_ival = -1;	/* Listen interval fixed field               */
static int ff_timestamp = -1;	/* 64 bit timestamp                          */
static int ff_beacon_interval = -1;	/* 16 bit Beacon interval            */
static int ff_assoc_id = -1;	/* 16 bit AID field                          */
static int ff_reason = -1;	/* 16 bit reason code                        */
static int ff_status_code = -1;	/* Status code                               */
static int ff_category_code = -1;	/* 8 bit Category code */
static int ff_action_code = -1;		/* 8 bit Action code */
static int ff_dialog_token = -1;	/* 8 bit Dialog token */
static int ff_wme_action_code = -1;	/* Management notification action code */
static int ff_wme_status_code = -1;	/* Management notification setup response status code */
static int ff_qos_action_code = -1;
static int ff_dls_action_code = -1;
static int ff_dst_mac_addr = -1;	/* DLS destination MAC addressi */
static int ff_src_mac_addr = -1;	/* DLS source MAC addressi */
static int ff_dls_timeout = -1;		/* DLS timeout value */

/* ************************************************************************* */
/*            Flags found in the capability field (fixed field)              */
/* ************************************************************************* */
static int ff_capture = -1;
static int ff_cf_ess = -1;
static int ff_cf_ibss = -1;
static int ff_cf_sta_poll = -1; /* CF pollable status for a STA            */
static int ff_cf_ap_poll = -1;	/* CF pollable status for an AP            */
static int ff_cf_privacy = -1;
static int ff_cf_preamble = -1;
static int ff_cf_pbcc = -1;
static int ff_cf_agility = -1;
static int ff_short_slot_time = -1;
static int ff_dsss_ofdm = -1;
static int ff_cf_spec_man = -1;
static int ff_cf_apsd = -1;
static int ff_cf_del_blk_ack = -1;
static int ff_cf_imm_blk_ack = -1;

/* ************************************************************************* */
/*                       A-MSDU fields                                             */
/* ************************************************************************* */
static int amsdu_msdu_header_text = -1;


/* ************************************************************************* */
/*                       Tagged value format fields                          */
/* ************************************************************************* */
static int tag_number = -1;
static int tag_length = -1;
static int tag_interpretation = -1;
static int tag_oui = -1;


static int tim_length = -1;
static int tim_dtim_count = -1;
static int tim_dtim_period = -1;
static int tim_bmapctl = -1;


static int hf_fixed_parameters = -1;	/* Protocol payload for management frames */
static int hf_tagged_parameters = -1;	/* Fixed payload item */
static int hf_wep_iv = -1;
static int hf_wep_iv_weak = -1;
static int hf_tkip_extiv = -1;
static int hf_ccmp_extiv = -1;
static int hf_wep_key = -1;
static int hf_wep_icv = -1;

/*** Begin: Block Ack Request/Block Ack  - Dustin Johnson***/
static int hf_block_ack_request_control = -1;
static int hf_block_ack_control_ack_policy = -1;
static int hf_block_ack_control_multi_tid = -1;
static int hf_block_ack_control_compressed_bitmap = -1;
static int hf_block_ack_control_reserved = -1;

static int hf_block_ack_control_basic_tid_info = -1;
static int hf_block_ack_control_compressed_tid_info = -1;
static int hf_block_ack_control_multi_tid_info = -1;
static int hf_block_ack_control_basic_fragment = -1;
static int hf_block_ack_control_basic_sequence = -1;

static int hf_tag_measure_request_measurement_mode = -1;
static int hf_tag_measure_request_bssid = -1;
static int hf_tag_measure_request_reporting_condition = -1;
static int hf_tag_measure_request_threshold_offset_unsigned = -1;
static int hf_tag_measure_request_threshold_offset_signed = -1;

static int hf_tag_measure_request_report_mac = -1;

static int hf_tag_measure_request_group_id = -1;

static int hf_block_ack_multi_tid_info = -1;
static int hf_block_ack_request_type = -1;
static int hf_block_ack_multi_tid_reserved = -1;
static int hf_block_ack_multi_tid_value = -1;
static int hf_block_ack_request_multi_tid_ssc = -1;
static int hf_block_ack_ssc = -1;
static int hf_block_ack_type = -1;
/*** End: Block Ack Request/Block Ack  - Dustin Johnson***/

static int ht_cap = -1;
static int ht_ldpc_coding = -1;
static int ht_chan_width = -1;
static int ht_sm_pwsave = -1;
static int ht_green = -1;
static int ht_short20 = -1;
static int ht_short40 = -1;
static int ht_tx_stbc = -1;
static int ht_rx_stbc = -1;
static int ht_delayed_block_ack = -1;
static int ht_max_amsdu = -1;
static int ht_dss_cck_40 = -1;
static int ht_psmp = -1;
static int ht_40_mhz_intolerant = -1;
static int ht_l_sig = -1;

static int ampduparam = -1;
static int ampduparam_mpdu = -1;
static int ampduparam_mpdu_start_spacing = -1;

static int mcsset = -1;
static int mcsset_highest_data_rate = -1;
static int mcsset_tx_mcs_set_defined = -1;
static int mcsset_tx_rx_mcs_set_not_equal = -1;
static int mcsset_tx_max_spatial_streams = -1;
static int mcsset_tx_unequal_modulation = -1;

static int htex_cap = -1;
static int htex_pco = -1;
static int htex_transtime = -1;
static int htex_mcs = -1;
static int htex_htc_support = -1;
static int htex_rd_responder = -1;

static int txbf = -1;
static int txbf_cap = -1;
static int txbf_rcv_ssc = -1;
static int txbf_tx_ssc = -1;
static int txbf_rcv_ndp = -1;
static int txbf_tx_ndp = -1;
static int txbf_impl_txbf = -1;
static int txbf_calib = -1;
static int txbf_expl_csi = -1;
static int txbf_expl_uncomp_fm = -1;
static int txbf_expl_comp_fm = -1;
static int txbf_expl_bf_csi = -1;
static int txbf_expl_uncomp_fm_feed = -1;
static int txbf_expl_comp_fm_feed = -1;
static int txbf_csi_num_bf_ant = -1;
static int txbf_min_group = -1;
static int txbf_uncomp_sm_bf_ant = -1;
static int txbf_comp_sm_bf_ant = -1;
static int txbf_csi_max_rows_bf = -1;
static int txbf_chan_est = -1;
static int txbf_resrv = -1;

/*** Begin: 802.11n D1.10 - HT Information IE  ***/
static int ht_info_primary_channel = -1;

static int ht_info_delimiter1 = -1;
static int ht_info_secondary_channel_offset = -1;
static int ht_info_channel_width = -1;
static int ht_info_rifs_mode = -1;
static int ht_info_psmp_stas_only = -1;
static int ht_info_service_interval_granularity = -1;

static int ht_info_delimiter2 = -1;
static int ht_info_operating_mode = -1;
static int ht_info_non_greenfield_sta_present = -1;
static int ht_info_transmit_burst_limit = -1;
static int ht_info_obss_non_ht_stas_present = -1;
static int ht_info_reserved_1 = -1;

static int ht_info_delimiter3 = -1;
static int ht_info_reserved_2 = -1;
static int ht_info_dual_beacon = -1;
static int ht_info_dual_cts_protection = -1;
static int ht_info_secondary_beacon = -1;
static int ht_info_lsig_txop_protection_full_support = -1;
static int ht_info_pco_active = -1;
static int ht_info_pco_phase = -1;
static int ht_info_reserved_3 = -1;
static int ht_basic_mcs_set = -1;
/*** End: 802.11n D1.10 - HT Information IE  ***/

/*** Begin: 802.11n D1.10 - Secondary Channel Offset Tag  - Dustin Johnson***/
static int hf_tag_secondary_channel_offset = -1;
/*** End: 802.11n D1.10 - Secondary Channel Offset Tag  - Dustin Johnson***/

/*** Begin: Measurement Request Tag  - Dustin Johnson***/
static int hf_tag_measure_request_measurement_token = -1;
static int hf_tag_measure_request_mode = -1;
static int hf_tag_measure_request_mode_reserved1 = -1;
static int hf_tag_measure_request_mode_enable = -1;
static int hf_tag_measure_request_mode_request = -1;
static int hf_tag_measure_request_mode_report = -1;
static int hf_tag_measure_request_mode_reserved2 = -1;
static int hf_tag_measure_request_type = -1;

static int hf_tag_measure_request_channel_number = -1;
static int hf_tag_measure_request_start_time = -1;
static int hf_tag_measure_request_duration = -1;

static int hf_tag_measure_request_regulatory_class = -1;
static int hf_tag_measure_request_randomization_interval = -1;
/*** End: Measurement Request Tag  - Dustin Johnson***/

/*** Begin: Measurement Report Tag  - Dustin Johnson***/
static int hf_tag_measure_report_measurement_token = -1;
static int hf_tag_measure_report_mode = -1;
static int hf_tag_measure_report_mode_late = -1;
static int hf_tag_measure_report_mode_incapable = -1;
static int hf_tag_measure_report_mode_refused = -1;
static int hf_tag_measure_report_mode_reserved = -1;
static int hf_tag_measure_report_type = -1;
static int hf_tag_measure_report_channel_number = -1;
static int hf_tag_measure_report_start_time = -1;
static int hf_tag_measure_report_duration = -1;

static int hf_tag_measure_basic_map_field = -1;
static int hf_tag_measure_map_field_bss = -1;
static int hf_tag_measure_map_field_odfm = -1;
static int hf_tag_measure_map_field_unident_signal = -1;
static int hf_tag_measure_map_field_radar = -1;
static int hf_tag_measure_map_field_unmeasured = -1;
static int hf_tag_measure_map_field_reserved = -1;

static int hf_tag_measure_cca_busy_fraction = -1;

static int hf_tag_measure_rpi_histogram_report = -1;
static int hf_tag_measure_rpi_histogram_report_0 = -1;
static int hf_tag_measure_rpi_histogram_report_1 = -1;
static int hf_tag_measure_rpi_histogram_report_2 = -1;
static int hf_tag_measure_rpi_histogram_report_3 = -1;
static int hf_tag_measure_rpi_histogram_report_4 = -1;
static int hf_tag_measure_rpi_histogram_report_5 = -1;
static int hf_tag_measure_rpi_histogram_report_6 = -1;
static int hf_tag_measure_rpi_histogram_report_7 = -1;

static int hf_tag_measure_report_regulatory_class = -1;
static int hf_tag_measure_report_channel_load = -1;
static int hf_tag_measure_report_frame_info = -1;
static int hf_tag_measure_report_frame_info_phy_type = -1;
static int hf_tag_measure_report_frame_info_frame_type = -1;
static int hf_tag_measure_report_rcpi = -1;
static int hf_tag_measure_report_rsni = -1;
static int hf_tag_measure_report_bssid = -1;
static int hf_tag_measure_report_ant_id = -1;
static int hf_tag_measure_report_parent_tsf = -1;
/*** End: Measurement Report Tag  - Dustin Johnson***/

/*** Begin: Extended Capabilities Tag - Dustin Johnson ***/
static int hf_tag_extended_capabilities = -1;
/*** End: Extended Capabilities Tag - Dustin Johnson ***/

/*** Begin: Neighbor Report Tag - Dustin Johnson ***/
static int hf_tag_neighbor_report_bssid = -1;
static int hf_tag_neighbor_report_bssid_info = -1;
static int hf_tag_neighbor_report_bssid_info_reachability = -1;
static int hf_tag_neighbor_report_bssid_info_security = -1;
static int hf_tag_neighbor_report_bssid_info_key_scope = -1;
static int hf_tag_neighbor_report_bssid_info_capability = -1;
static int hf_tag_neighbor_report_bssid_info_capability_spec_mng = -1;
static int hf_tag_neighbor_report_bssid_info_capability_qos = -1;
static int hf_tag_neighbor_report_bssid_info_capability_apsd = -1;
static int hf_tag_neighbor_report_bssid_info_capability_radio_msnt = -1;
static int hf_tag_neighbor_report_bssid_info_capability_dback = -1;
static int hf_tag_neighbor_report_bssid_info_capability_iback = -1;
static int hf_tag_neighbor_report_bssid_info_mobility_domain = -1;
static int hf_tag_neighbor_report_bssid_info_high_throughput = -1;
static int hf_tag_neighbor_report_bssid_info_reserved = -1;
static int hf_tag_neighbor_report_reg_class = -1;
static int hf_tag_neighbor_report_channel_number = -1;
static int hf_tag_neighbor_report_phy_type = -1;
/*** End: Neighbor Report Tag - Dustin Johnson ***/

/*** Begin: Extended Channel Switch Announcement Tag - Dustin Johnson ***/
static int hf_tag_ext_channel_switch_announcement_switch_mode = -1;
static int hf_tag_ext_channel_switch_announcement_new_reg_class = -1;
static int hf_tag_ext_channel_switch_announcement_new_chan_number = -1;
static int hf_tag_ext_channel_switch_announcement_switch_count = -1;
/*** End: Extended Channel Switch Announcement Tag - Dustin Johnson ***/

/*** Begin: Supported Regulatory Classes Tag - Dustin Johnson ***/
static int hf_tag_supported_reg_classes_current = -1;
static int hf_tag_supported_reg_classes_alternate = -1;
/*** End: Supported Regulatory Classes Tag - Dustin Johnson ***/

/* 802.11n 7.3.2.48 */
static int hta_cap = -1;
static int hta_ext_chan_offset = -1;
static int hta_rec_tx_width = -1;
static int hta_rifs_mode = -1;
static int hta_controlled_access = -1;
static int hta_service_interval = -1;
static int hta_operating_mode = -1;
static int hta_non_gf_devices = -1;
static int hta_basic_stbc_mcs = -1;
static int hta_dual_stbc_protection = -1;
static int hta_secondary_beacon = -1;
static int hta_lsig_txop_protection = -1;
static int hta_pco_active = -1;
static int hta_pco_phase = -1;


static int antsel = -1;
static int antsel_b0 = -1;
static int antsel_b1 = -1;
static int antsel_b2 = -1;
static int antsel_b3 = -1;
static int antsel_b4 = -1;
static int antsel_b5 = -1;
static int antsel_b6 = -1;
static int antsel_b7 = -1;

static int rsn_cap = -1;
static int rsn_cap_preauth = -1;
static int rsn_cap_no_pairwise = -1;
static int rsn_cap_ptksa_replay_counter = -1;
static int rsn_cap_gtksa_replay_counter = -1;

static int hf_aironet_ie_type = -1;
static int hf_aironet_ie_version = -1;
static int hf_aironet_ie_data = -1;
static int hf_aironet_ie_qos_unk1 = -1;
static int hf_aironet_ie_qos_paramset = -1;
static int hf_aironet_ie_qos_val = -1;

/*QBSS - Version 1,2,802.11e*/

static int hf_qbss2_cal = -1;
static int hf_qbss2_gl = -1;
static int hf_qbss_cu = -1;
static int hf_qbss2_cu = -1;
static int hf_qbss_scount = -1;
static int hf_qbss2_scount = -1;
static int hf_qbss_version = -1;
static int hf_qbss_adc = -1;

static int hf_ts_info = -1;
static int hf_tsinfo_type = -1;
static int hf_tsinfo_tsid = -1;
static int hf_tsinfo_dir = -1;
static int hf_tsinfo_access = -1;
static int hf_tsinfo_agg = -1;
static int hf_tsinfo_apsd = -1;
static int hf_tsinfo_up = -1;
static int hf_tsinfo_ack = -1;
static int hf_tsinfo_sched = -1;
static int tspec_nor_msdu = -1;
static int tspec_max_msdu = -1;
static int tspec_min_srv = -1;
static int tspec_max_srv = -1;
static int tspec_inact_int = -1;
static int tspec_susp_int = -1;
static int tspec_srv_start = -1;
static int tspec_min_data = -1;
static int tspec_mean_data = -1;
static int tspec_peak_data = -1;
static int tspec_burst_size = -1;
static int tspec_delay_bound = -1;
static int tspec_min_phy = -1;
static int tspec_surplus = -1;
static int tspec_medium = -1;
static int ts_delay = -1;
static int hf_class_type = -1;
static int hf_class_mask = -1;
static int hf_ether_type = -1;
static int hf_tclas_process = -1;
static int hf_sched_info = -1;
static int hf_sched_srv_start = -1;
static int hf_sched_srv_int = -1;
static int hf_sched_spec_int = -1;
static int hf_action = -1;
static int cf_version = -1;
static int cf_ipv4_src = -1;
static int cf_ipv4_dst = -1;
static int cf_src_port = -1;
static int cf_dst_port = -1;
static int cf_dscp = -1;
static int cf_protocol = -1;
static int cf_ipv6_src = -1;
static int cf_ipv6_dst = -1;
static int cf_flow = -1;
static int cf_tag_type = -1;

/* ************************************************************************* */
/*                               Protocol trees                              */
/* ************************************************************************* */
static gint ett_80211 = -1;
static gint ett_proto_flags = -1;
static gint ett_cap_tree = -1;
static gint ett_fc_tree = -1;
static gint ett_cntrl_wrapper_fc = -1;
static gint ett_fragments = -1;
static gint ett_fragment = -1;
static gint ett_block_ack = -1;


static gint ett_80211_mgt = -1;
static gint ett_fixed_parameters = -1;
static gint ett_tagged_parameters = -1;
static gint ett_qos_parameters = -1;
static gint ett_qos_ps_buf_state = -1;
static gint ett_wep_parameters = -1;

static gint ett_rsn_cap_tree = -1;

static gint ett_ht_cap_tree = -1;
static gint ett_ampduparam_tree = -1;
static gint ett_mcsset_tree = -1;
static gint ett_htex_cap_tree = -1;
static gint ett_txbf_tree = -1;
static gint ett_antsel_tree = -1;
static gint ett_hta_cap_tree = -1;
static gint ett_hta_cap1_tree = -1;
static gint ett_hta_cap2_tree = -1;
static gint ett_htc_tree = -1;

/*** Start: 802.11n D1.10 - HT Information IE - Dustin Johnson ***/
static gint ett_ht_info_delimiter1_tree = -1;
static gint ett_ht_info_delimiter2_tree = -1;
static gint ett_ht_info_delimiter3_tree = -1;
/*** End: 802.11n D1.10 - HT Information IE  - Dustin Johnson ***/

/*** Start: 802.11n D1.10 - Tag Measure Request IE - Dustin Johnson ***/
static gint ett_tag_measure_request_tree = -1;
/*** End: 802.11n D1.10 - Tag Measure Request IE  - Dustin Johnson ***/

/*** Begin: Neighbor Report Tag - Dustin Johnson ***/
static gint ett_tag_neighbor_report_bssid_info_tree = -1;
static gint ett_tag_neighbor_report_bssid_info_capability_tree = -1;
static gint ett_tag_neighbor_report_sub_tag_tree = -1;
/*** End: Neighbor Report Tag - Dustin Johnson ***/

static gint ett_80211_mgt_ie = -1;
static gint ett_tsinfo_tree = -1;
static gint ett_sched_tree = -1;

static gint ett_fcs = -1;

static const fragment_items frag_items = {
	&ett_fragment,
	&ett_fragments,
	&hf_fragments,
	&hf_fragment,
	&hf_fragment_overlap,
	&hf_fragment_overlap_conflict,
	&hf_fragment_multiple_tails,
	&hf_fragment_too_long_fragment,
	&hf_fragment_error,
	&hf_reassembled_in,
	"fragments"
};

static enum_val_t wlan_ignore_wep_options[] = {
  { "no",         "No",               WLAN_IGNORE_WEP_NO    },
  { "without_iv", "Yes - without IV", WLAN_IGNORE_WEP_WO_IV },
  { "with_iv",    "Yes - with IV",    WLAN_IGNORE_WEP_W_IV  },
  { NULL,         NULL,               0                     }
};

static dissector_handle_t llc_handle;
static dissector_handle_t ipx_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t data_handle;

static int wlan_tap = -1;

/*     Davide Schiera (2006-11-22): including AirPDcap project                */
#ifdef HAVE_AIRPDCAP
#include <epan/crypt/airpdcap_ws.h>
AIRPDCAP_CONTEXT airpdcap_ctx;
#else
int airpdcap_ctx;
#endif
/* Davide Schiera (2006-11-22) ---------------------------------------------- */


/* ************************************************************************* */
/*            Return the length of the current header (in bytes)             */
/* ************************************************************************* */
static int
find_header_length (guint16 fcf)
{
  int len;

  switch (FCF_FRAME_TYPE (fcf)) {

  case MGT_FRAME:
    return MGT_FRAME_HDR_LEN;

  case CONTROL_FRAME:
    switch (COMPOSE_FRAME_TYPE (fcf)) {

    case CTRL_CTS:
    case CTRL_ACKNOWLEDGEMENT:
      return 10;

    case CTRL_RTS:
    case CTRL_PS_POLL:
    case CTRL_CFP_END:
    case CTRL_CFP_ENDACK:
    case CTRL_BLOCK_ACK_REQ:
    case CTRL_BLOCK_ACK:
      return 16;
    }
    return 4;	/* XXX */

  case DATA_FRAME:
    len = (FCF_ADDR_SELECTOR(fcf) == DATA_ADDR_T4) ? DATA_LONG_HDR_LEN :
						      DATA_SHORT_HDR_LEN;

    if (DATA_FRAME_IS_QOS(COMPOSE_FRAME_TYPE(fcf))) {
      len += 2;
    }

    return len;

  default:
    return 4;	/* XXX */
  }
}


/* ************************************************************************* */
/*          This is the capture function used to update packet counts        */
/* ************************************************************************* */
static void
capture_ieee80211_common (const guchar * pd, int offset, int len,
			  packet_counts * ld, gboolean fixed_length_header,
			  gboolean datapad)
{
  guint16 fcf, hdr_length;

  if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
    ld->other++;
    return;
  }

  fcf = pletohs (&pd[offset]);

  if (IS_PROTECTED(FCF_FLAGS(fcf)) && wlan_ignore_wep == WLAN_IGNORE_WEP_NO)
    {
      ld->other++;
      return;
    }

  switch (COMPOSE_FRAME_TYPE (fcf))
    {

    case DATA:			/* We got a data frame */
    case DATA_CF_ACK:		/* Data with ACK */
    case DATA_CF_POLL:
    case DATA_CF_ACK_POLL:
    case DATA_QOS_DATA:
      if (fixed_length_header)
        hdr_length = DATA_LONG_HDR_LEN;
      else
        hdr_length = find_header_length (fcf);
      if (datapad)
        hdr_length = roundup2(hdr_length, 4);
      /* I guess some bridges take Netware Ethernet_802_3 frames,
         which are 802.3 frames (with a length field rather than
         a type field, but with no 802.2 header in the payload),
         and just stick the payload into an 802.11 frame.  I've seen
         captures that show frames of that sort.

         This means we have to do the same check for Netware 802.3 -
         or, if you will, "Netware 802.11" - that we do in the
         Ethernet dissector, i.e. checking for 0xffff as the first
         four bytes of the payload and, if we find it, treating it
         as an IPX frame. */
      if (!BYTES_ARE_IN_FRAME(offset+hdr_length, len, 2)) {
        ld->other++;
        return;
      }
      if (pd[offset+hdr_length] == 0xff && pd[offset+hdr_length+1] == 0xff) {
        capture_ipx (ld);
      }
      else {
        capture_llc (pd, offset + hdr_length, len, ld);
      }
      break;

    default:
      ld->other++;
      break;
    }
}

/*
 * Handle 802.11 with a variable-length link-layer header.
 */
void
capture_ieee80211 (const guchar * pd, int offset, int len, packet_counts * ld)
{
  capture_ieee80211_common (pd, offset, len, ld, FALSE, FALSE);
}

/*
 * Handle 802.11 with a variable-length link-layer header and data padding.
 */
void
capture_ieee80211_datapad (const guchar * pd, int offset, int len,
                           packet_counts * ld)
{
  capture_ieee80211_common (pd, offset, len, ld, FALSE, TRUE);
}

/*
 * Handle 802.11 with a fixed-length link-layer header (padded to the
 * maximum length).
 */
void
capture_ieee80211_fixed (const guchar * pd, int offset, int len, packet_counts * ld)
{
  capture_ieee80211_common (pd, offset, len, ld, TRUE, FALSE);
}


/* ************************************************************************* */
/*          Add the subtree used to store the fixed parameters               */
/* ************************************************************************* */
static proto_tree *
get_fixed_parameter_tree (proto_tree * tree, tvbuff_t *tvb, int start, int size)
{
  proto_item *fixed_fields;
  fixed_fields =
    proto_tree_add_uint_format (tree, hf_fixed_parameters, tvb, start,
				size, size, "Fixed parameters (%d bytes)",
				size);

  return proto_item_add_subtree (fixed_fields, ett_fixed_parameters);
}


/* ************************************************************************* */
/*            Add the subtree used to store tagged parameters                */
/* ************************************************************************* */
static proto_tree *
get_tagged_parameter_tree (proto_tree * tree, tvbuff_t *tvb, int start, int size)
{
  proto_item *tagged_fields;

  tagged_fields = proto_tree_add_uint_format (tree, hf_tagged_parameters,
					      tvb,
					      start,
					      size,
					      size,
					      "Tagged parameters (%d bytes)",
					      size);

  return proto_item_add_subtree (tagged_fields, ett_tagged_parameters);
}


/* ************************************************************************* */
/*              Dissect and add fixed mgmt fields to protocol tree           */
/* ************************************************************************* */
static guint
add_fixed_field(proto_tree * tree, tvbuff_t * tvb, int offset, int lfcode)
{
  const guint8 *dataptr;
  char out_buff[SHORT_STR];
  guint16 capability;
  proto_item *cap_item;
  static proto_tree *cap_tree;
  double temp_double;
  guint length = 0;

  switch (lfcode)
    {
    case FIELD_TIMESTAMP:
      dataptr = tvb_get_ptr (tvb, offset, 8);
      memset (out_buff, 0, SHORT_STR);
      g_snprintf (out_buff, SHORT_STR, "0x%02X%02X%02X%02X%02X%02X%02X%02X",
		dataptr[7],
		dataptr[6],
		dataptr[5],
		dataptr[4],
		dataptr[3],
		dataptr[2],
		dataptr[1],
		dataptr[0]);

      proto_tree_add_string (tree, ff_timestamp, tvb, offset, 8, out_buff);
      length += 8;
      break;

    case FIELD_BEACON_INTERVAL:
      capability = tvb_get_letohs (tvb, offset);
      temp_double = (double)capability;
      temp_double = temp_double * 1024 / 1000000;
      proto_tree_add_double_format (tree, ff_beacon_interval, tvb, offset, 2,
				    temp_double,"Beacon Interval: %f [Seconds]",
				    temp_double);
      if (check_col (g_pinfo->cinfo, COL_INFO)) {
          col_append_fstr(g_pinfo->cinfo, COL_INFO, ",BI=%d", capability);
      }
      length += 2;
      break;


    case FIELD_CAP_INFO:
      capability = tvb_get_letohs (tvb, offset);

      cap_item = proto_tree_add_uint_format (tree, ff_capture,
					     tvb, offset, 2,
					     capability,
					     "Capability Information: 0x%04X",
					     capability);
      cap_tree = proto_item_add_subtree (cap_item, ett_cap_tree);
      proto_tree_add_boolean (cap_tree, ff_cf_ess, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_ibss, tvb, offset, 2,
			      capability);
      if (ESS_SET (capability) != 0)	/* This is an AP */
	proto_tree_add_uint (cap_tree, ff_cf_ap_poll, tvb, offset, 2,
			     capability);

      else			/* This is a STA */
	proto_tree_add_uint (cap_tree, ff_cf_sta_poll, tvb, offset, 2,
			     capability);
      proto_tree_add_boolean (cap_tree, ff_cf_privacy, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_preamble, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_pbcc, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_agility, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_spec_man, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_short_slot_time, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_apsd, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_dsss_ofdm, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_del_blk_ack, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_imm_blk_ack, tvb, offset, 2,
			      capability);
      length += 2;
      break;

    case FIELD_AUTH_ALG:
      proto_tree_add_item (tree, ff_auth_alg, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_AUTH_TRANS_SEQ:
      proto_tree_add_item (tree, ff_auth_seq, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_CURRENT_AP_ADDR:
      proto_tree_add_item (tree, ff_current_ap, tvb, offset, 6, FALSE);
      length += 6;
      break;

    case FIELD_LISTEN_IVAL:
      proto_tree_add_item (tree, ff_listen_ival, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_REASON_CODE:
      proto_tree_add_item (tree, ff_reason, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_ASSOC_ID:
      proto_tree_add_uint(tree, ff_assoc_id, tvb, offset, 2,
			  ASSOC_ID(tvb_get_letohs(tvb,offset)));
      /* proto_tree_add_item (tree, ff_assoc_id, tvb, offset, 2, TRUE); */
      length += 2;
      break;

    case FIELD_STATUS_CODE:
      proto_tree_add_item (tree, ff_status_code, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_CATEGORY_CODE:
      proto_tree_add_item (tree, ff_category_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_ACTION_CODE:
      proto_tree_add_item (tree, ff_action_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_DIALOG_TOKEN:
      proto_tree_add_item (tree, ff_dialog_token, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_WME_ACTION_CODE:
      proto_tree_add_item (tree, ff_wme_action_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_WME_STATUS_CODE:
      proto_tree_add_item (tree, ff_wme_status_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_QOS_ACTION_CODE:
      proto_tree_add_item (tree, ff_qos_action_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_QOS_TS_INFO:
      {
	proto_item *tsinfo_item;
	proto_tree *tsinfo_tree;
	guint32 tsi;

	tsinfo_item = proto_tree_add_item(tree, hf_ts_info, tvb,
					  offset, 3, TRUE);
	tsinfo_tree = proto_item_add_subtree(tsinfo_item, ett_tsinfo_tree);
	tsi = tvb_get_letoh24(tvb, offset);
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_type, tvb,
			    offset, 3, TSI_TYPE (tsi));
	if (TSI_TSID (tsi) < 8)
	{
	  proto_tree_add_text(tsinfo_tree, tvb, offset, 3,
	  		      "TSID: %u (< 8 is invalid)", TSI_TSID (tsi));
	}
	else
	{
	  proto_tree_add_uint(tsinfo_tree, hf_tsinfo_tsid, tvb,
			      offset, 3, TSI_TSID (tsi));
	}
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_dir, tvb,
			    offset, 3, TSI_DIR (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_access, tvb,
			    offset, 3, TSI_ACCESS (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_agg, tvb,
			    offset, 3, TSI_AGG (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_apsd, tvb,
			    offset, 3, TSI_APSD (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_up, tvb,
			    offset, 3, TSI_UP (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_ack, tvb,
			    offset, 3, TSI_ACK (tsi));
	proto_tree_add_uint(tsinfo_tree, hf_tsinfo_sched, tvb,
			    offset, 3, TSI_SCHED (tsi));
      }
      length += 3;
      break;

    case FIELD_DLS_ACTION_CODE:
      proto_tree_add_item (tree, ff_dls_action_code, tvb, offset, 1, TRUE);
      length += 1;
      break;

    case FIELD_DST_MAC_ADDR:
      proto_tree_add_item (tree, ff_dst_mac_addr, tvb, offset, 6, TRUE);
      length += 6;
      break;

    case FIELD_SRC_MAC_ADDR:
      proto_tree_add_item (tree, ff_src_mac_addr, tvb, offset, 6, TRUE);
      length += 6;
      break;

    case FIELD_DLS_TIMEOUT:
      proto_tree_add_item (tree, ff_dls_timeout, tvb, offset, 2, TRUE);
      length += 2;
      break;

    case FIELD_SCHEDULE_INFO:
      {
	proto_item *sched_item;
	proto_tree *sched_tree;
	guint16 sched;

	sched_item = proto_tree_add_item(tree, hf_sched_info,
					 tvb, offset, 2, TRUE);
	sched_tree = proto_item_add_subtree(sched_item, ett_sched_tree);
	sched = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(sched_tree, hf_tsinfo_agg, tvb, offset,
			    2, sched & 0x0001);
	if (sched & 0x0001)
	{
	  proto_tree_add_uint(sched_tree, hf_tsinfo_tsid, tvb, offset,
			      2, (sched & 0x001E) >> 1);
	  proto_tree_add_uint(sched_tree, hf_tsinfo_dir, tvb, offset,
			      2, (sched & 0x0060) >> 5);
	}
      }
      length += 2;
    break;
	case FIELD_ACTION:
	{
	  proto_item *action_item;
	  proto_tree *action_tree, *fixed_tree;

	  action_item = proto_tree_add_item(tree, hf_action,
					                   tvb, offset, 2, TRUE);
	  action_tree = proto_item_add_subtree(action_item, ett_sched_tree);
	  switch (tvb_get_guint8(tvb, 0))
	  {
	  case CAT_SPECTRUM_MGMT:
	    switch (tvb_get_guint8(tvb, 1))
		{
		case SM_ACTION_MEASUREMENT_REQUEST:
		case SM_ACTION_MEASUREMENT_REPORT:
		case SM_ACTION_TPC_REQUEST:
		case SM_ACTION_TPC_REPORT:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 3);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  length += 3;	/* Size of fixed fields */
		  break;

		case SM_ACTION_CHAN_SWITCH_ANNC:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 2);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  length += 2;	/* Size of fixed fields */
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 2);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  length += 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_QOS:
	      switch (tvb_get_guint8(tvb, 1))
	        {
		case SM_ACTION_ADDTS_REQUEST:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 3);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  length += 3;
		  break;

		case SM_ACTION_ADDTS_RESPONSE:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 5);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  add_fixed_field(fixed_tree, tvb, 3, FIELD_STATUS_CODE);
		  length += 5;
		  break;

		case SM_ACTION_DELTS:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 7);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_QOS_TS_INFO);
		  add_fixed_field(fixed_tree, tvb, 5, FIELD_REASON_CODE);
		  length += 7;
		  break;

		case SM_ACTION_QOS_SCHEDULE:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 2);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  length += 2;
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 2);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  length += 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_DLS:
	      switch (tvb_get_guint8(tvb, 1))
	        {
		case SM_ACTION_DLS_REQUEST:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 18);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_DST_MAC_ADDR);
		  add_fixed_field(fixed_tree, tvb, 8, FIELD_SRC_MAC_ADDR);
		  add_fixed_field(fixed_tree, tvb, 14, FIELD_CAP_INFO);
		  add_fixed_field(fixed_tree, tvb, 16, FIELD_DLS_TIMEOUT);
		  length += 18;
		  break;

		case SM_ACTION_DLS_RESPONSE:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 16);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_STATUS_CODE);
		  add_fixed_field(fixed_tree, tvb, 4, FIELD_DST_MAC_ADDR);
		  add_fixed_field(fixed_tree, tvb, 10, FIELD_SRC_MAC_ADDR);
		  length += 16;
		  if (!ff_status_code)
		    add_fixed_field(fixed_tree, tvb, 16, FIELD_CAP_INFO);
		  break;

		case SM_ACTION_DLS_TEARDOWN:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 18);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field(fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field(fixed_tree, tvb, 2, FIELD_DST_MAC_ADDR);
		  add_fixed_field(fixed_tree, tvb, 8, FIELD_SRC_MAC_ADDR);
		  add_fixed_field(fixed_tree, tvb, 14, FIELD_REASON_CODE);
		  length += 16;
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 2);
		  add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  length += 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_MGMT_NOTIFICATION:	/* Management notification frame */
	      fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 4);
	      add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
	      add_fixed_field(fixed_tree, tvb, 1, FIELD_WME_ACTION_CODE);
	      add_fixed_field(fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
	      add_fixed_field(fixed_tree, tvb, 3, FIELD_WME_STATUS_CODE);
	      length += 4;	/* Size of fixed fields */
	      break;

	    default:
	      fixed_tree = get_fixed_parameter_tree (action_tree, tvb, 0, 1);
	      add_fixed_field(fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
	      length += 1;	/* Size of fixed fields */
	      break;
	    }
	}
  }
  return length;
}

static const value_string wpa_cipher_vals[] =
{
	{0, "NONE"},
	{1, "WEP (40-bit)"},
	{2, "TKIP"},
	{3, "AES (OCB)"},
	{4, "AES (CCM)"},
	{5, "WEP (104-bit)"},
	{0, NULL}
};

static const value_string wpa_keymgmt_vals[] =
{
	{0, "NONE"},
	{1, "WPA"},
	{2, "PSK"},
	{0, NULL}
};

static void
dissect_vendor_ie_wpawme(proto_tree * ietree, proto_tree * tree, tvbuff_t * tag_tvb)
{
      gint tag_off = 0;
      gint tag_len = tvb_length_remaining(tag_tvb, 0);
      gchar out_buff[SHORT_STR];
      guint i, byte1, byte2;

      /* Wi-Fi Protected Access (WPA) Information Element */
      if (tag_off + 6 <= tag_len && !tvb_memeql(tag_tvb, tag_off, WPA_OUI"\x01", 4)) {
        g_snprintf(out_buff, SHORT_STR, "WPA IE, type %u, version %u",
		tvb_get_guint8(tag_tvb, tag_off + 3), tvb_get_letohs(tag_tvb, tag_off + 4));
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 6, out_buff);
        tag_off += 6;
        if (tag_off + 4 <= tag_len) {
          /* multicast cipher suite */
          if (!tvb_memeql(tag_tvb, tag_off, WPA_OUI, 3)) {
            g_snprintf(out_buff, SHORT_STR, "Multicast cipher suite: %s",
		    val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3), wpa_cipher_vals,
			    "UNKNOWN"));
            proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4,
		    out_buff);
            tag_off += 4;
            /* unicast cipher suites */
            if (tag_off + 2 <= tag_len) {
              g_snprintf(out_buff, SHORT_STR,
		      "# of unicast cipher suites: %u", tvb_get_letohs(tag_tvb, tag_off));
              proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		      out_buff);
              tag_off += 2;
              i = 1;
              while (tag_off + 4 <= tag_len) {
                if (!tvb_memeql(tag_tvb, tag_off, WPA_OUI, 3)) {
                  g_snprintf(out_buff, SHORT_STR,
			   "Unicast cipher suite %u: %s", i,
			   val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3),
				   wpa_cipher_vals, "UNKNOWN"));
                  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4,
			  out_buff);
                  tag_off += 4;
                  i ++;
                }
                else
                  break;
              }
	      /* authenticated key management suites */
              if (tag_off + 2 <= tag_len) {
                g_snprintf(out_buff, SHORT_STR,
			"# of auth key management suites: %u", tvb_get_letohs(tag_tvb, tag_off));
                proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
			out_buff);
                tag_off += 2;
                i = 1;
                while (tag_off + 4 <= tag_len) {
                  if (!tvb_memeql(tag_tvb, tag_off, WPA_OUI, 3)) {
                    g_snprintf(out_buff, SHORT_STR,
			    "auth key management suite %u: %s", i,
			    val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3),
				    wpa_keymgmt_vals, "UNKNOWN"));
                    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4,
			    out_buff);
                    tag_off += 4;
                    i ++;
                  }
                  else
                    break;
                }
              }
            }
          }
        }
        if (tag_off < tag_len)
          proto_tree_add_string(tree, tag_interpretation, tag_tvb,
                                 tag_off, tag_len - tag_off, "Not interpreted");
	proto_item_append_text(ietree, ": WPA");
      } else if (tag_off + 7 <= tag_len && !tvb_memeql(tag_tvb, tag_off, WME_OUI"\x02\x00", 5)) {
      /* Wireless Multimedia Enhancements (WME) Information Element */
        g_snprintf(out_buff, SHORT_STR,
		"WME IE: type %u, subtype %u, version %u, parameter set %u",
		tvb_get_guint8(tag_tvb, tag_off+3), tvb_get_guint8(tag_tvb, tag_off+4),
		tvb_get_guint8(tag_tvb, tag_off+5), tvb_get_guint8(tag_tvb, tag_off+6));
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 7,
		out_buff);
        proto_item_append_text(ietree, ": WME");
      } else if (tag_off + 24 <= tag_len && !tvb_memeql(tag_tvb, tag_off, WME_OUI"\x02\x01", 5)) {
      /* Wireless Multimedia Enhancements (WME) Parameter Element */
        g_snprintf(out_buff, SHORT_STR,
		"WME PE: type %u, subtype %u, version %u, parameter set %u",
		tvb_get_guint8(tag_tvb, tag_off+3), tvb_get_guint8(tag_tvb, tag_off+4),
		tvb_get_guint8(tag_tvb, tag_off+5), tvb_get_guint8(tag_tvb, tag_off+6));
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 7,
		out_buff);
	tag_off += 8;
	for (i = 0; i < 4; i++) {
	  byte1 = tvb_get_guint8(tag_tvb, tag_off);
	  byte2 = tvb_get_guint8(tag_tvb, tag_off + 1);
	  g_snprintf(out_buff, SHORT_STR,
		  "WME AC Parameters: ACI %u (%s), Admission Control %sMandatory, AIFSN %u, ECWmin %u, ECWmax %u, TXOP %u",
		   (byte1 & 0x60) >> 5, wme_acs[(byte1 & 0x60) >> 5],
		   (byte1 & 0x10) ? "" : "not ", byte1 & 0x0f,
		   byte2 & 0x0f, byte2 & 0xf0 >> 4,
		   tvb_get_letohs(tag_tvb, tag_off + 2));
	  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4,
		  out_buff);
	  tag_off += 4;
	}
	proto_item_append_text(ietree, ": WME");
      } else if (tag_off + 56 <= tag_len && !tvb_memeql(tag_tvb, tag_off, WME_OUI"\x02\x02", 5)) {
      /* Wireless Multimedia Enhancements (WME) TSPEC Element */
	guint16 ts_info, msdu_size, surplus_bandwidth;
	const char *direction[] = { "Uplink", "Downlink", "Reserved", "Bi-directional" };
	const value_string fields[] = {
	  {12, "Minimum Service Interval"},
	  {16, "Maximum Service Interval"},
	  {20, "Inactivity Interval"},
	  {24, "Service Start Time"},
	  {28, "Minimum Data Rate"},
	  {32, "Mean Data Rate"},
	  {36, "Maximum Burst Size"},
	  {40, "Minimum PHY Rate"},
	  {44, "Peak Data Rate"},
	  {48, "Delay Bound"},
	  {0, NULL}
	};
	const char *field;

        g_snprintf(out_buff, SHORT_STR,
		"WME TSPEC: type %u, subtype %u, version %u",
		tvb_get_guint8(tag_tvb, tag_off+3), tvb_get_guint8(tag_tvb, tag_off+4),
		tvb_get_guint8(tag_tvb, tag_off+5));
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 6,
		out_buff);
	tag_off += 6;

	ts_info = tvb_get_letohs(tag_tvb, tag_off);
	byte1 = (ts_info >> 11) & 0x7;
	g_snprintf(out_buff, SHORT_STR,
		"WME TS Info: Priority %u (%s) (%s), Contention-based access %sset, %s",
		 byte1, qos_tags[byte1], qos_acs[byte1],
		 (ts_info & 0x0080) ? "" : "not ",
		 direction[(ts_info >> 5) & 0x3]);
	proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		out_buff);
	tag_off += 2;

	msdu_size = tvb_get_letohs(tag_tvb, tag_off);
	g_snprintf(out_buff, SHORT_STR,
		"WME TSPEC: %s MSDU Size %u",
		(msdu_size & 0x8000) ? "Fixed" : "Nominal", msdu_size & 0x7fff);
	proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		out_buff);
	tag_off += 2;

	g_snprintf(out_buff, SHORT_STR,
		"WME TSPEC: Maximum MSDU Size %u", tvb_get_letohs(tag_tvb, tag_off));
	proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		out_buff);
	tag_off += 2;

	while ((field = val_to_str(tag_off, fields, "Unknown"))) {
	  g_snprintf(out_buff, SHORT_STR,
		  "WME TSPEC: %s %u", field, tvb_get_letohl(tag_tvb, tag_off));
	  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4,
		  out_buff);
	  tag_off += 4;
	  if (tag_off == 52)
	    break;
	}

	surplus_bandwidth = tvb_get_letohs(tag_tvb, tag_off);
	g_snprintf(out_buff, SHORT_STR,
		"WME TSPEC: Surplus Bandwidth Allowance Factor %u.%u",
		 (surplus_bandwidth >> 13) & 0x7, (surplus_bandwidth & 0x1fff));
	proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		out_buff);
	tag_off += 2;

	g_snprintf(out_buff, SHORT_STR,
		"WME TSPEC: Medium Time %u", tvb_get_letohs(tag_tvb, tag_off));
	proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2,
		out_buff);
	tag_off += 2;
	proto_item_append_text(ietree, ": WME");
      }
}

static void
dissect_vendor_ie_rsn(proto_tree * ietree, proto_tree * tree, tvbuff_t * tag_tvb)
{
	guint tag_off = 0;
	guint tag_len = tvb_length_remaining(tag_tvb, 0);
	guint pmkid_len = tag_len - 4;
	char out_buff[SHORT_STR], valid_str[SHORT_STR] = "";

	if (tag_len >= 4 && !tvb_memeql(tag_tvb, tag_off, RSN_OUI"\x04", 4)) {
		/* IEEE 802.11i / Key Data Encapsulation / Data Type=4 - PMKID.
		 * This is only used within EAPOL-Key frame Key Data. */
		if (pmkid_len != PMKID_LEN) {
			g_snprintf(valid_str, SHORT_STR,
				"(invalid PMKID len=%d, expected 16) ", pmkid_len);
		}
		g_snprintf(out_buff, SHORT_STR, "RSN PMKID: %s%s", valid_str,
			tvb_bytes_to_str(tag_tvb, 4, pmkid_len));
		proto_tree_add_string(tree, tag_interpretation, tag_tvb, 0,
			tag_len, out_buff);
	}
	proto_item_append_text(ietree, ": RSN");
}

typedef enum {
	AIRONET_IE_VERSION = 3,
	AIRONET_IE_QOS,
	AIRONET_IE_QBSS_V2 = 14
} aironet_ie_type_t;

static const value_string aironet_ie_type_vals[] = {
        { AIRONET_IE_VERSION,	"CCX version"},
        { AIRONET_IE_QOS,	"Qos"},
        { AIRONET_IE_QBSS_V2,	"QBSS V2 - CCA"},

	{ 0,			NULL }
};

static void
dissect_vendor_ie_aironet(proto_item * aironet_item, proto_tree * ietree,
	tvbuff_t * tvb, int offset, guint32 tag_len)
{
	guint8	type;
	int i;
	gboolean dont_change = FALSE; /* Don't change the IE item text to default */

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item (ietree, hf_aironet_ie_type, tvb, offset, 1, TRUE);
	offset += 1;

	switch (type) {
	case AIRONET_IE_VERSION:
		proto_tree_add_item (ietree, hf_aironet_ie_version, tvb, offset, 1, TRUE);
		proto_item_append_text(aironet_item, ": Aironet CCX version = %d",
			tvb_get_guint8(tvb, offset));
		dont_change = TRUE;
		break;
	case AIRONET_IE_QOS:
		proto_tree_add_item (ietree, hf_aironet_ie_qos_unk1, tvb, offset, 1, TRUE);
		offset += 1;
		proto_tree_add_item (ietree, hf_aironet_ie_qos_paramset, tvb, offset, 1, TRUE);
		offset += 1;

		/* XXX: just copied over from WME. Maybe "Best Effort" and "Background"
		 *	need to be swapped. Also, the "TXOP" may be TXOP - or not.
		 */
		for (i = 0; i < 4; i++) {
			guint8 byte1, byte2;
			guint16 txop;
			byte1 = tvb_get_guint8(tvb, offset);
			byte2 = tvb_get_guint8(tvb, offset + 1);
			txop = tvb_get_letohs(tvb, offset + 2);
			proto_tree_add_bytes_format(ietree, hf_aironet_ie_qos_val, tvb, offset, 4,
				tvb_get_ptr(tvb, offset, 4),
		  		"CCX QoS Parameters??: ACI %u (%s), Admission Control %sMandatory, AIFSN %u, ECWmin %u, ECWmax %u, TXOP %u",
				(byte1 & 0x60) >> 5, wme_acs[(byte1 & 0x60) >> 5],
				(byte1 & 0x10) ? "" : "not ", byte1 & 0x0f,
				byte2 & 0x0f, (byte2 & 0xf0) >> 4,
				txop);
			offset += 4;
		}
		break;
	case AIRONET_IE_QBSS_V2:
		/* Extract Values */
		proto_tree_add_item (ietree, hf_qbss2_scount, tvb, offset, 2, TRUE);
		proto_tree_add_item (ietree, hf_qbss2_cu, tvb, offset + 2, 1, FALSE);
		proto_tree_add_item (ietree, hf_qbss2_cal, tvb, offset + 3, 1, FALSE);
		proto_tree_add_item (ietree, hf_qbss2_gl, tvb, offset + 4, 1, FALSE);
		break;
	default:
		proto_tree_add_item(ietree, hf_aironet_ie_data, tvb, offset,
			tag_len - 1, FALSE);
		break;
	}
	if (!dont_change) {
		proto_item_append_text(aironet_item, ": Aironet %s",
			val_to_str(type, aironet_ie_type_vals, "Unknown"));
	}
}

static void
dissect_rsn_ie(proto_tree * tree, tvbuff_t * tag_tvb)
{
  guint tag_off = 0;
  guint tag_len = tvb_length_remaining(tag_tvb, 0);
  guint16 rsn_capab;
  char out_buff[SHORT_STR];
  int i, count;
  proto_item *cap_item;
  proto_tree *cap_tree;

  if (tag_off + 2 > tag_len) {
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, tag_len,
			  "Not interpreted");
    return;
  }

  g_snprintf(out_buff, SHORT_STR, "RSN IE, version %u",
	   tvb_get_letohs(tag_tvb, tag_off));
  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2, out_buff);

  tag_off += 2;

  if (tag_off + 4 > tag_len)
    goto done;

  /* multicast cipher suite */
  if (!tvb_memeql(tag_tvb, tag_off, RSN_OUI, 3)) {
    g_snprintf(out_buff, SHORT_STR, "Multicast cipher suite: %s",
	     val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3),
		     wpa_cipher_vals, "UNKNOWN"));
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4, out_buff);
    tag_off += 4;
  }

  if (tag_off + 2 > tag_len)
    goto done;

  /* unicast cipher suites */
  count = tvb_get_letohs(tag_tvb, tag_off);
  g_snprintf(out_buff, SHORT_STR, "# of unicast cipher suites: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2, out_buff);
  tag_off += 2;
  i = 1;
  while (tag_off + 4 <= tag_len && i <= count) {
    if (tvb_memeql(tag_tvb, tag_off, RSN_OUI, 3) != 0)
      goto done;
    g_snprintf(out_buff, SHORT_STR, "Unicast cipher suite %u: %s",
	     i, val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3),
		     wpa_cipher_vals, "UNKNOWN"));
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4, out_buff);
    tag_off += 4;
    i++;
  }

  if (i <= count || tag_off + 2 > tag_len)
    goto done;

  /* authenticated key management suites */
  count = tvb_get_letohs(tag_tvb, tag_off);
  g_snprintf(out_buff, SHORT_STR, "# of auth key management suites: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2, out_buff);
  tag_off += 2;
  i = 1;
  while (tag_off + 4 <= tag_len && i <= count) {
    if (tvb_memeql(tag_tvb, tag_off, RSN_OUI, 3) != 0)
      goto done;
    g_snprintf(out_buff, SHORT_STR, "auth key management suite %u: %s",
	     i, val_to_str(tvb_get_guint8(tag_tvb, tag_off + 3),
		     wpa_keymgmt_vals, "UNKNOWN"));
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 4, out_buff);
    tag_off += 4;
    i++;
  }

  if (i <= count || tag_off + 2 > tag_len)
    goto done;

  rsn_capab = tvb_get_letohs(tag_tvb, tag_off);
  g_snprintf(out_buff, SHORT_STR, "RSN Capabilities 0x%04x", rsn_capab);
  cap_item = proto_tree_add_uint_format(tree, rsn_cap, tag_tvb,
					tag_off, 2, rsn_capab,
					"RSN Capabilities: 0x%04X", rsn_capab);
  cap_tree = proto_item_add_subtree(cap_item, ett_rsn_cap_tree);
  proto_tree_add_boolean(cap_tree, rsn_cap_preauth, tag_tvb, tag_off, 2,
			 rsn_capab);
  proto_tree_add_boolean(cap_tree, rsn_cap_no_pairwise, tag_tvb, tag_off, 2,
			 rsn_capab);
  proto_tree_add_uint(cap_tree, rsn_cap_ptksa_replay_counter, tag_tvb, tag_off, 2,
		      rsn_capab);
  proto_tree_add_uint(cap_tree, rsn_cap_gtksa_replay_counter, tag_tvb, tag_off, 2,
		      rsn_capab);
  tag_off += 2;

  if (tag_off + 2 > tag_len)
    goto done;

  count = tvb_get_letohs(tag_tvb, tag_off);
  g_snprintf(out_buff, SHORT_STR, "# of PMKIDs: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off, 2, out_buff);
  tag_off += 2;

  /* PMKID List (16 * n octets) */
  for (i = 0; i < count; i++) {
    if (tag_off + PMKID_LEN > tag_len)
      break;
    g_snprintf(out_buff, SHORT_STR, "PMKID %u: %s", i,
        tvb_bytes_to_str(tag_tvb, tag_off, PMKID_LEN));
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off,
			  PMKID_LEN, out_buff);
    tag_off += PMKID_LEN;
  }

done:
  if (tag_off < tag_len)
    proto_tree_add_string(tree, tag_interpretation, tag_tvb, tag_off,
			  tag_len - tag_off, "Not interpreted");
}

/*  802.11n D1.10 - HT Information IE  */
static void
dissect_ht_info_ie_1_1(proto_tree * tree, tvbuff_t * tvb, int offset,
	       guint32 tag_len)
{
  proto_item *cap_item;
  proto_tree *cap_tree;
  guint32 tag_val_init_off = 0;
  guint16 info = 0;

  tag_val_init_off = offset;
  cap_tree = tree;

  if (tag_len < 22) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
              "HT Information IE content length must be at least 22 bytes");
    return;
  }

  info = tvb_get_guint8 (tvb, offset);
  proto_tree_add_uint_format(cap_tree, ht_info_primary_channel, tvb, offset, 1,
             info, "Primary channel: 0x%02X", info);

  info = tvb_get_guint8 (tvb, ++offset);
  cap_item = proto_tree_add_uint_format(tree, ht_info_delimiter1, tvb,
                    offset, 1, info,
                    "HT Information Subset (1 of 3): 0x%02X", info);
  cap_tree = proto_item_add_subtree(cap_item, ett_ht_info_delimiter1_tree);
  proto_tree_add_uint(cap_tree, ht_info_secondary_channel_offset, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_channel_width, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_rifs_mode, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_psmp_stas_only, tvb, offset, 1,
             info);
  proto_tree_add_uint(cap_tree, ht_info_service_interval_granularity, tvb, offset, 1,
             info);

  info = tvb_get_letohs (tvb, ++offset);
  cap_item = proto_tree_add_uint_format(tree, ht_info_delimiter2, tvb,
                    offset, 2, info,
                    "HT Information Subset (2 of 3): 0x%04X", info);
  cap_tree = proto_item_add_subtree(cap_item, ett_ht_info_delimiter2_tree);
  proto_tree_add_uint(cap_tree, ht_info_operating_mode, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_non_greenfield_sta_present, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_transmit_burst_limit, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_obss_non_ht_stas_present, tvb, offset, 1,
             info);
  proto_tree_add_uint(cap_tree, ht_info_reserved_1, tvb, offset, 2,
             info);

  offset += 2;
  info = tvb_get_letohs (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, ht_info_delimiter3, tvb,
                    offset, 2, info,
                    "HT Information Subset (3 of 3): 0x%04X", info);
  cap_tree = proto_item_add_subtree(cap_item, ett_ht_info_delimiter3_tree);
  proto_tree_add_uint(cap_tree, ht_info_reserved_2, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_dual_beacon, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_dual_cts_protection, tvb, offset, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_secondary_beacon, tvb, offset+1, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_lsig_txop_protection_full_support, tvb, offset+1, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_pco_active, tvb, offset+1, 1,
             info);
  proto_tree_add_boolean(cap_tree, ht_info_pco_phase, tvb, offset+1, 1,
             info);
  proto_tree_add_uint(cap_tree, ht_info_reserved_3, tvb, offset+1, 1,
             info);

  offset += 2;
  cap_tree = tree;
  proto_tree_add_string(cap_tree, ht_basic_mcs_set, tvb, offset, 16,
              "Basic MCS Set");

  offset += 16;
  if (tag_val_init_off - offset < tag_len){
    proto_tree_add_string(cap_tree, tag_interpretation, tvb, offset,
			 tag_len + tag_val_init_off - offset, "Unparsed Extra Data");
  }
}

/*** Begin: Secondary Channel Offset Tag - Dustin Johnson ***/
static void secondary_channel_offset_ie(proto_tree * tree, tvbuff_t * tvb, int offset, guint32 tag_len)
{
  if (tag_len != 1)
  {
    proto_tree_add_text (tree, tvb, offset, tag_len, "Secondary Channel Offset: Error: Tag length must be at least 1 byte long");
	return;
  }

  proto_tree_add_uint(tree, hf_tag_secondary_channel_offset, tvb, offset, 1, tvb_get_guint8 (tvb, offset));

  offset++;
  if ((tag_len - offset) > 0)
  {
    proto_tree_add_text (tree, tvb, offset, tag_len - offset, "Unkown Data");
	return;
  }
}
/*** End: Secondary Channel Offset Tag - Dustin Johnson ***/

static void
dissect_ht_capability_ie(proto_tree * tree, tvbuff_t * tvb, int offset,
	       guint32 tag_len)
{
  proto_item *cap_item;
  proto_tree *cap_tree;
  guint16 capability;
  guint32 txbfcap;
  guint32 tag_val_off = 0;

  if (tag_val_off + 2 > tag_len) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
			  "Not interpreted");
    return;
  }

  if (tag_len != 26) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
              "HT Capabilities IE content length must be exactly 26 bytes");
    return;
  }

  /* 2 byte HT Capabilities  Info*/
  capability = tvb_get_letohs (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, ht_cap, tvb,
                    offset, 2, capability,
                    "HT Capabilities Info: 0x%04X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_ht_cap_tree);
  proto_tree_add_boolean(cap_tree, ht_ldpc_coding, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_chan_width, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, ht_sm_pwsave, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_green, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_short20, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_short40, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_tx_stbc, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, ht_rx_stbc, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_delayed_block_ack, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_max_amsdu, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_dss_cck_40, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_psmp, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_40_mhz_intolerant, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, ht_l_sig, tvb, offset+1, 1,
             capability);

  offset += 2;
  tag_val_off += 2;

  /* 1 byte A-MPDU Parameters */
  capability = tvb_get_guint8 (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, ampduparam, tvb,
                    offset, 1, capability,
                    "A-MPDU Parameters: 0x%02X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_ampduparam_tree);
  proto_tree_add_uint(cap_tree, ampduparam_mpdu, tvb, offset, 1, capability);
  proto_tree_add_uint(cap_tree, ampduparam_mpdu_start_spacing, tvb, offset, 1, capability);

  offset += 1;
  tag_val_off += 1;

  /* 16 byte Supported MCS set */
  cap_item = proto_tree_add_string(tree, mcsset, tvb, offset,
                    16, "Supported Modulation Coding Streams (MCS) Set");
  cap_tree = proto_item_add_subtree(cap_item, ett_mcsset_tree);
  proto_tree_add_string(cap_tree, tag_interpretation, tvb, offset,
                    10, "Modulation Coding Streams (One bit per modulation)");
  capability = tvb_get_letohs (tvb, offset+10);
  proto_tree_add_uint_format(cap_tree, mcsset_highest_data_rate, tvb, offset + 10, 2,
                    capability, "Highest Supported Data Rate: 0x%04X", capability);
  capability = tvb_get_letohs (tvb, offset+12);
  proto_tree_add_boolean(cap_tree, mcsset_tx_mcs_set_defined, tvb, offset + 12, 1,
                    capability);
  proto_tree_add_boolean(cap_tree, mcsset_tx_rx_mcs_set_not_equal, tvb, offset + 12, 1,
                    capability);
  proto_tree_add_uint(cap_tree, mcsset_tx_max_spatial_streams, tvb, offset + 12, 1,
                    capability);
  proto_tree_add_boolean(cap_tree, mcsset_tx_unequal_modulation, tvb, offset + 12, 1,
                    capability);

  offset += 16;
  tag_val_off += 16;

  /* 2 byte HT Extended Capabilities */
  capability = tvb_get_letohs (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, htex_cap, tvb,
                    offset, 2, capability,
                    "HT Extended Capabilities: 0x%04X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_htex_cap_tree);
  proto_tree_add_boolean(cap_tree, htex_pco, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, htex_transtime, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, htex_mcs, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, htex_htc_support, tvb, offset+1, 1,
             capability);
  proto_tree_add_boolean(cap_tree, htex_rd_responder, tvb, offset+1, 1,
             capability);

  offset += 2;
  tag_val_off += 2;

  /* 4 byte TxBF capabilities */
  txbfcap = tvb_get_letohl (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, txbf, tvb,
                    offset, 4, txbfcap, "Transmit Beam Forming (TxBF) Capabilities: 0x%04X", txbfcap);
  cap_tree = proto_item_add_subtree(cap_item, ett_txbf_tree);
  proto_tree_add_boolean(cap_tree, txbf_cap, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_rcv_ssc, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_tx_ssc, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_rcv_ndp, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_tx_ndp, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_impl_txbf, tvb, offset, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_calib, tvb, offset, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_expl_csi, tvb, offset+1, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_expl_uncomp_fm, tvb, offset+1, 1,
             txbfcap);
  proto_tree_add_boolean(cap_tree, txbf_expl_comp_fm, tvb, offset+1, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_expl_bf_csi, tvb, offset+1, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_expl_uncomp_fm_feed, tvb, offset+1, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_expl_comp_fm_feed, tvb, offset+1, 2,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_min_group, tvb, offset+2, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_csi_num_bf_ant, tvb, offset+2, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_uncomp_sm_bf_ant, tvb, offset+2, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_comp_sm_bf_ant, tvb, offset+2, 2,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_csi_max_rows_bf, tvb, offset+3, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_chan_est, tvb, offset+3, 1,
             txbfcap);
  proto_tree_add_uint(cap_tree, txbf_resrv, tvb, offset+3, 1,
             txbfcap);

  offset += 4;
  tag_val_off += 4;

  /* 1 byte Antenna Selection (ASEL) capabilities */
  capability = tvb_get_guint8 (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, antsel, tvb,
                    offset, 1, capability,
                    "Antenna Selection (ASEL) Capabilties: 0x%02X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_antsel_tree);
  proto_tree_add_boolean(cap_tree, antsel_b0, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b1, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b2, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b3, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b4, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b5, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, antsel_b6, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, antsel_b7, tvb, offset, 1,
             capability);

  offset += 1;
  tag_val_off += 1;

  if (tag_val_off < tag_len)
    proto_tree_add_string(tree, tag_interpretation, tvb, offset,
			  tag_len - tag_val_off, "Not interpreted");
}

static void
dissect_ht_info_ie_1_0(proto_tree * tree, tvbuff_t * tvb, int offset,
	       guint32 tag_len)
{
  proto_item *cap_item;
  proto_tree *cap_tree;
  guint16 capability;
  guint32 tag_val_off = 0;
  gchar out_buff[SHORT_STR];

  if (tag_val_off + 2 > tag_len) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
			  "Not interpreted");
    return;
  }

  if (tag_len < 22) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
              "HT Additional Capabilities IE content length must be 22");
    return;
  }

  g_snprintf(out_buff, SHORT_STR, "Control Channel %d",
             tvb_get_guint8(tvb, offset));
  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 1, out_buff);
  offset += 1;
  tag_val_off += 1;

  /* 1 byte HT additional capabilities */
  capability = tvb_get_guint8 (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, hta_cap, tvb,
                    offset, 1, capability,
                    "HT Additional Capabilities: 0x%04X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_hta_cap_tree);
  proto_tree_add_uint(cap_tree, hta_ext_chan_offset, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, hta_rec_tx_width, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, hta_rifs_mode, tvb, offset, 1,
             capability);
  proto_tree_add_boolean(cap_tree, hta_controlled_access, tvb, offset, 1,
             capability);
  proto_tree_add_uint(cap_tree, hta_service_interval, tvb, offset, 1,
             capability);
  offset += 1;
  tag_val_off += 1;

  /* 2 byte HT additional capabilities */
  capability = tvb_get_letohs (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, hta_cap, tvb,
                    offset, 2, capability,
                    "HT Additional Capabilities: 0x%04X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_hta_cap1_tree);
  proto_tree_add_uint(cap_tree, hta_operating_mode, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_non_gf_devices, tvb, offset, 2,
             capability);

  offset += 2;
  tag_val_off += 2;

  /* 2 byte HT additional capabilities */
  capability = tvb_get_letohs (tvb, offset);
  cap_item = proto_tree_add_uint_format(tree, hta_cap, tvb,
                    offset, 2, capability,
                    "HT Additional Capabilities: 0x%04X", capability);
  cap_tree = proto_item_add_subtree(cap_item, ett_hta_cap2_tree);
  proto_tree_add_uint(cap_tree, hta_basic_stbc_mcs, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_dual_stbc_protection, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_secondary_beacon, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_lsig_txop_protection, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_pco_active, tvb, offset, 2,
             capability);
  proto_tree_add_boolean(cap_tree, hta_pco_phase, tvb, offset, 2,
             capability);
  offset += 2;
  tag_val_off += 2;

  /* 16 byte Supported MCS set */
  proto_tree_add_string(tree, tag_interpretation, tvb, offset,
            16, "Modulation Coding Streams (One bit per modulation)");
  offset += 16;
  tag_val_off += 16;

   if (tag_val_off < tag_len)
     proto_tree_add_string(tree, tag_interpretation, tvb, offset,
               tag_len - tag_val_off, "Not interpreted");
}

/* 802.11n-D1.10 and 802.11n-D2.0, 7.1.3.5a */

/*
 * 7.1.3.1.10 says:
 * "The Order field is 1 bit in length and is set to 1 in any non-QoS Data
 * frame that contains an MSDU, or fragment thereof, which is being
 * transferred using the StrictlyOrdered service class. The presence of the
 * HT Control field in frames is indicated by setting the Order field to 1
 * in any Data type or Management type frame that  is transmitted with a
 * value of HT_GF or HT_MM for the FORMAT parameter of the TXVECTOR except
 * a non-QoS Data frame or a Control Wrapper frame. The Order field is set
 * to 0 in all other frames. All non-HT QoS STAs [1] set the Order field to
 * 0."
 *
 * ...so does this mean that we can check for the presence of +HTC by
 * looking for QoS frames with the Order bit set, or do we need extra
 * information from the PHY (which would be monumentally silly)?
 *
 * At any rate, it doesn't look like any equipment we have produces
 * +HTC frames, so the code is #if 0'ed out (and completely untested)
 * for now.
 */

#if 0
static void
dissect_ht_control(proto_tree *tree, tvbuff_t * tvb, int offset)
{
    proto_item *ti;
    proto_tree *htc_tree, *htc_subtree;
    guint32 htc;

    htc = tvb_get_ntohl(tvb, offset);

    ti = proto_tree_add_item(tree, hf_htc, tvb, offset, 4, TRUE);
    htc_tree = proto_item_add_subtree(ti, ett_htc_tree);

    /* Link Adaptation Control */
    ti = proto_tree_add_item(htc_tree, hf_htc_lac, tvb, offset, 2, TRUE);
    htc_subtree = proto_item_add_subtree(ti, ett_htc_tree);
    proto_tree_add_item(htc_subtree, hf_htc_lac_trq, tvb, offset, 2, TRUE);

    if (IS_ASELI(htc)) {
	proto_tree_add_boolean(htc_subtree, hf_htc_lac_mai_aseli, tvb, offset, 2, TRUE);
    } else {
	proto_tree_add_item(htc_subtree, hf_htc_lac_mai_mrq, tvb, offset, 2, TRUE);
	proto_tree_add_uint(htc_subtree, hf_htc_lac_mai_msi, tvb, offset, 2, HTC_LAC_MAI_MSI(htc));
    }

    proto_tree_add_uint(htc_subtree, hf_htc_lac_mfsi, tvb, offset, 2, HTC_LAC_MFSI(htc));

    if (IS_ASELI(htc)) {
	proto_tree_add_uint(htc_subtree, hf_htc_lac_asel_command, tvb, offset, 2, HTC_LAC_ASEL_CMD(htc));
	proto_tree_add_uint(htc_subtree, hf_htc_lac_asel_data, tvb, offset, 2, HTC_LAC_ASEL_DATA(htc));
    } else {
	proto_tree_add_uint(htc_subtree, hf_htc_lac_mfb, tvb, offset, 2, HTC_LAC_MFB(htc));
    }

    proto_tree_add_uint(htc_subtree, hf_htc_cal_pos, tvb, offset + 2, 1,
	HTC_CAL_POS(htc));
    proto_tree_add_uint(htc_subtree, hf_htc_cal_seq, tvb, offset + 2, 1,
	HTC_CAL_SEQ(htc));
    proto_tree_add_uint(htc_subtree, hf_htc_csi_steering, tvb, offset + 2, 1
	HTC_CSI_STEERING(htc));

    proto_tree_add_boolean(htc_subtree, hf_htc_ndp_announcement, tvb,
	offset + 3, 1, HTC_NDP_ANN(htc));
    proto_tree_add_boolean(htc_subtree, hf_htc_ac_constraint, tvb,
	offset + 3, 1, HTC_AC_CONSTRAINT(htc));
    proto_tree_add_boolean(htc_subtree, hf_htc_rdg_more_ppdu, tvb,
	offset + 3, 1, HTC_RDG_MORE_PPDU(htc));
}
#endif

static void
dissect_frame_control(proto_tree * tree, tvbuff_t * tvb, gboolean wlan_broken_fc,
                      guint32 offset)
{
  guint16 fcf, flags, frame_type_subtype;
  proto_tree *fc_tree, *flag_tree;
  proto_item *fc_item, *flag_item;

  fcf = tvb_get_letohs (tvb, offset);
  if (wlan_broken_fc) {
    /* Swap bytes */
    fcf = ((fcf & 0xff) << 8) | (((fcf & 0xff00) >> 8) & 0xff);
  }

  flags = FCF_FLAGS (fcf);
  frame_type_subtype = COMPOSE_FRAME_TYPE(fcf);

  proto_tree_add_uint (tree, hf_fc_frame_type_subtype,
			           tvb, wlan_broken_fc?offset+1:offset, 1,
			           frame_type_subtype);

  fc_item = proto_tree_add_uint_format (tree, hf_fc_field, tvb,
		      			    offset, 2, fcf, "Frame Control: 0x%04X (%s)",
					        fcf, wlan_broken_fc?"Swapped":"Normal");

  fc_tree = proto_item_add_subtree (fc_item, ett_fc_tree);

  proto_tree_add_uint (fc_tree, hf_fc_proto_version, tvb, wlan_broken_fc?offset+1:offset, 1,
			           FCF_PROT_VERSION (fcf));

  proto_tree_add_uint (fc_tree, hf_fc_frame_type, tvb, wlan_broken_fc?offset+1:offset, 1,
			           FCF_FRAME_TYPE (fcf));

  proto_tree_add_uint (fc_tree, hf_fc_frame_subtype, tvb, wlan_broken_fc?offset+1:offset, 1,
			           FCF_FRAME_SUBTYPE (fcf));

  flag_item = proto_tree_add_uint_format (fc_tree, hf_fc_flags, tvb,
                                          wlan_broken_fc?offset:offset+1, 1,
				                          flags, "Flags: 0x%X", flags);

  flag_tree = proto_item_add_subtree (flag_item, ett_proto_flags);

  proto_tree_add_uint (flag_tree, hf_fc_data_ds, tvb, wlan_broken_fc?offset:+1, 1,
			           FLAGS_DS_STATUS (flags));
  proto_tree_add_boolean_hidden (flag_tree, hf_fc_to_ds, tvb, offset+1, 1, flags);
  proto_tree_add_boolean_hidden (flag_tree, hf_fc_from_ds, tvb, offset+1, 1, flags);
  proto_tree_add_boolean (flag_tree, hf_fc_more_frag, tvb, wlan_broken_fc?offset:offset+1, 1,
                          flags);
  proto_tree_add_boolean (flag_tree, hf_fc_retry, tvb, wlan_broken_fc?offset:offset+1, 1,
                          flags);
  proto_tree_add_boolean (flag_tree, hf_fc_pwr_mgt, tvb, wlan_broken_fc?offset:offset+1, 1,
                          flags);
  proto_tree_add_boolean (flag_tree, hf_fc_more_data, tvb, wlan_broken_fc?offset:offset+1, 1,
			              flags);
  proto_tree_add_boolean (flag_tree, hf_fc_protected, tvb, wlan_broken_fc?offset:offset+1, 1,
                          flags);
  proto_tree_add_boolean (flag_tree, hf_fc_order, tvb, wlan_broken_fc?offset:offset+1, 1,
                          flags);
}

static void
dissect_vendor_ie_ht(proto_tree * ietree, proto_tree * tree, tvbuff_t * tag_tvb)
{
      gint tag_len = tvb_length_remaining(tag_tvb, 0);
      gchar out_buff[SHORT_STR];

      g_snprintf(out_buff, SHORT_STR, "802.11n (Pre) OUI");
      proto_tree_add_string(tree, tag_interpretation, tag_tvb, 0, 3, out_buff);
      /* 802.11n OUI  Information Element */
      if (4 <= tag_len && !tvb_memeql(tag_tvb, 0, PRE_11N_OUI"\x33", 4)) {
        g_snprintf(out_buff, SHORT_STR, "802.11n (Pre) HT information");
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, 3, 1, out_buff);

        dissect_ht_capability_ie(tree, tag_tvb, 4, tag_len - 4);
        proto_item_append_text(ietree, ": HT Capabilities (802.11n D1.10)");
      }
      else
      if (4 <= tag_len && !tvb_memeql(tag_tvb, 0, PRE_11N_OUI"\x34", 4)) {
        g_snprintf(out_buff, SHORT_STR, "HT additional information (802.11n D1.00)");
        proto_tree_add_string(tree, tag_interpretation, tag_tvb, 3, 1, out_buff);

        dissect_ht_info_ie_1_0(tree, tag_tvb, 4, tag_len - 4);
        proto_item_append_text(ietree, ": HT Additional Capabilities (802.11n D1.00)");
      }
      else
      {
          g_snprintf(out_buff, SHORT_STR, "Unknown type");
          proto_tree_add_string(tree, tag_interpretation, tag_tvb, 3, 1, out_buff);
          proto_item_append_text(ietree, ": 802.11n (pre) Unknown type");
          proto_tree_add_string(tree, tag_interpretation, tag_tvb, 4,
                    tag_len - 4, "Not interpreted");
      }
}


/* ************************************************************************* */
/*           Dissect and add tagged (optional) fields to proto tree          */
/* ************************************************************************* */

static const value_string tag_num_vals[] = {
	{ TAG_SSID,                 "SSID parameter set" },
	{ TAG_SUPP_RATES,           "Supported Rates" },
	{ TAG_FH_PARAMETER,         "FH Parameter set" },
	{ TAG_DS_PARAMETER,         "DS Parameter set" },
	{ TAG_CF_PARAMETER,         "CF Parameter set" },
	{ TAG_TIM,                  "(TIM) Traffic Indication Map" },
	{ TAG_IBSS_PARAMETER,       "IBSS Parameter set" },
	{ TAG_COUNTRY_INFO,         "Country Information" },
	{ TAG_FH_HOPPING_PARAMETER, "Hopping Pattern Parameters" },
	{ TAG_CHALLENGE_TEXT,       "Challenge text" },
	{ TAG_ERP_INFO,             "ERP Information" },
	{ TAG_ERP_INFO_OLD,         "ERP Information" },
	{ TAG_RSN_IE,               "RSN Information" },
	{ TAG_EXT_SUPP_RATES,       "Extended Supported Rates" },
	{ TAG_CISCO_UNKNOWN_1,      "Cisco Unknown 1 + Device Name" },
	{ TAG_CISCO_UNKNOWN_2,      "Cisco Unknown 2" },
	{ TAG_CISCO_UNKNOWN_3,      "Cisco Unknown 3" },
	{ TAG_VENDOR_SPECIFIC_IE,   "Vendor Specific" },
	{ TAG_SYMBOL_PROPRIETARY,   "Symbol Proprietary"},
	{ TAG_AGERE_PROPRIETARY,    "Agere Proprietary"},
	{ TAG_REQUEST,		    	"Request"},
	{ TAG_QBSS_LOAD,	    	"QBSS Load Element"},
	{ TAG_EDCA_PARAM_SET,	    "EDCA Parameter Set"},
	{ TAG_TSPEC,		    	"Traffic Specification"},
	{ TAG_TCLAS,		    	"Traffic Classification"},
	{ TAG_SCHEDULE,		    	"Schedule"},
	{ TAG_TS_DELAY,		    	"TS Delay"},
	{ TAG_TCLAS_PROCESS,	    "TCLAS Processing"},
    { TAG_HT_CAPABILITY,		"HT Capabilities (802.11n D1.10)"},
	{ TAG_NEIGHBOR_REPORT,      "Neighbor Report"},
	{ TAG_HT_INFO,       		"HT Information (802.11n D1.10)"},
	{ TAG_SECONDARY_CHANNEL_OFFSET, "Secondary Channel Offset (802.11n D1.10)"},
	{ TAG_QOS_CAPABILITY,	    "QoS Capability"},
	{ TAG_POWER_CONSTRAINT,	    "Power Constraint"},
	{ TAG_POWER_CAPABILITY,	    "Power Capability"},
	{ TAG_TPC_REQUEST,	    	"TPC Request"},
	{ TAG_TPC_REPORT,	    	"TPC Report"},
	{ TAG_SUPPORTED_CHANNELS,   "Supported Channels"},
	{ TAG_CHANNEL_SWITCH_ANN,   "Channel Switch Announcement"},
	{ TAG_MEASURE_REQ,	    	"Measurement Request"},
	{ TAG_MEASURE_REP,	    	"Measurement Report"},
	{ TAG_QUIET,		    	"Quiet"},
	{ TAG_IBSS_DFS,		    	"IBSS DFS"},
	{ TAG_EXTENDED_CAPABILITIES,    "Extended Capabilities"},
	#if 0 /*Not yet assigned tag numbers by ANA */
	{ TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT, "Extended Channel Switch Announcement"},
	{ TAG_SUPPORTED_REGULATORY_CLASSES, "Supported Regulatory Classes"},
	#endif
	{ 0,                        NULL }
};

static const value_string environment_vals[] = {
	{ 0x20, "Any" },
	{ 0x4f, "Outdoor" },
	{ 0x49, "Indoor" },
	{ 0,    NULL }
};

static int beacon_padding = 0; /* beacon padding bug */
static int
add_tagged_field (packet_info * pinfo, proto_tree * tree, tvbuff_t * tvb, int offset)
{
  guint32 oui;
  tvbuff_t *tag_tvb;
  const guint8 *tag_data_ptr;
  guint32 tag_no, tag_len;
  unsigned int i;
  int n, ret;
  char out_buff[SHORT_STR];
  char print_buff[SHORT_STR];
  proto_tree * orig_tree=tree;
  proto_item *ti;

  tag_no = tvb_get_guint8(tvb, offset);
  tag_len = tvb_get_guint8(tvb, offset + 1);

  ti=proto_tree_add_text(orig_tree,tvb,offset,tag_len+2,"%s",
                         val_to_str(tag_no, tag_num_vals,
                         (tag_no >= 17 && tag_no <= 31) ?
                         "Reserved for challenge text" : "Reserved tag number" ));
  tree=proto_item_add_subtree(ti,ett_80211_mgt_ie);

  proto_tree_add_uint_format (tree, tag_number, tvb, offset, 1, tag_no,
			      "Tag Number: %u (%s)",
			      tag_no,
			      val_to_str(tag_no, tag_num_vals,
					 (tag_no >= 17 && tag_no <= 31) ?
					 "Reserved for challenge text" :
					 "Reserved tag number"));
  proto_tree_add_uint (tree, (tag_no==TAG_TIM ? tim_length : tag_length), tvb, offset + 1, 1, tag_len);

  switch (tag_no)
    {

    case TAG_SSID:
      if(beacon_padding == 0) /* padding bug */
      {
        guint8 *ssid; /* The SSID may consist of arbitrary bytes */

        ssid = tvb_get_ephemeral_string(tvb, offset + 2, tag_len);
#ifdef HAVE_AIRPDCAP
        AirPDcapSetLastSSID(&airpdcap_ctx, (CHAR *) ssid, tag_len);
#endif
        proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
                               tag_len, (char *) ssid);
        if (check_col (pinfo->cinfo, COL_INFO)) {
          if (tag_len > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", SSID: \"%s\"",
                            format_text(ssid, tag_len));
          } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", SSID: Broadcast");
          }
        }
        if (tag_len > 0) {
          proto_item_append_text(ti, ": \"%s\"",
                                 format_text(ssid, tag_len));
        } else {
          proto_item_append_text(ti, ": Broadcast");
        }
	beacon_padding++; /* padding bug */
      }
      break;

    case TAG_SUPP_RATES:
    case TAG_EXT_SUPP_RATES:
      if (tag_len < 1)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Tag length %u too short, must be greater than 0", tag_len);
        break;
      }

      tag_data_ptr = tvb_get_ptr (tvb, offset + 2, tag_len);
      for (i = 0, n = 0; i < tag_len && n < SHORT_STR; i++) {
	    if (tag_data_ptr[i] == 0xFF){
		  proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2 + i,
			     1, "BSS requires support for mandatory features of HT PHY (IEEE 802.11 - Clause 20)");
		} else {
        ret = g_snprintf (print_buff + n, SHORT_STR - n, "%2.1f%s ",
                        (tag_data_ptr[i] & 0x7F) * 0.5,
                        (tag_data_ptr[i] & 0x80) ? "(B)" : "");
        if (ret == -1 || ret >= SHORT_STR - n) {
          /* Some versions of snprintf return -1 if they'd truncate
             the output. Others return <buf_size> or greater.  */
          break;
        }
        n += ret;
      }
      }
      g_snprintf (out_buff, SHORT_STR, "Supported rates: %s [Mbit/sec]", print_buff);
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      proto_item_append_text(ti, ": %s", print_buff);
      break;

    case TAG_FH_PARAMETER:
      if (tag_len < 5)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 5",
                             tag_len);
        break;
      }
      g_snprintf (out_buff, SHORT_STR,
		"Dwell time 0x%04X, Hop Set %2d, Hop Pattern %2d, Hop Index %2d",
		tvb_get_letohs(tvb, offset + 2),
		tvb_get_guint8(tvb, offset + 4),
		tvb_get_guint8(tvb, offset + 5),
		tvb_get_guint8(tvb, offset + 6));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
                             tag_len, out_buff);
      break;

    case TAG_DS_PARAMETER:
      if (tag_len < 1)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 1",
                             tag_len);
        break;
      }
      g_snprintf (out_buff, SHORT_STR, "Current Channel: %u",
                tvb_get_guint8(tvb, offset + 2));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
                             tag_len, out_buff);
      proto_item_append_text(ti, ": %s", out_buff);
      break;

    case TAG_CF_PARAMETER:
      if (tag_len < 6)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 6",
                             tag_len);
        break;
      }
      g_snprintf (out_buff, SHORT_STR, "CFP count: %u",
                tvb_get_guint8(tvb, offset + 2));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 2,
                                   1, out_buff, "%s", out_buff);
      g_snprintf (out_buff, SHORT_STR, "CFP period: %u",
                tvb_get_guint8(tvb, offset + 3));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 3,
                                   1, out_buff, "%s", out_buff);
      g_snprintf (out_buff, SHORT_STR, "CFP max duration: %u",
                tvb_get_letohs(tvb, offset + 4));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 4,
                                   2, out_buff, "%s", out_buff);
      g_snprintf (out_buff, SHORT_STR, "CFP Remaining: %u",
                tvb_get_letohs(tvb, offset + 6));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 6,
                                   2, out_buff, "%s", out_buff);
      proto_item_append_text(ti, ": CFP count %u, CFP period %u, CFP max duration %u, "
                             "CFP Remaining %u",
                             tvb_get_guint8(tvb, offset + 2),
                             tvb_get_guint8(tvb, offset + 3),
                             tvb_get_letohs(tvb, offset + 4),
                             tvb_get_letohs(tvb, offset + 6));
      break;

    case TAG_TIM:
      if (tag_len < 4)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 4",
                             tag_len);
        break;
      }
      {
        guint8 bmapctl;
        guint8 bmapoff;
        guint8 bmaplen;
        const guint8* bmap;

        proto_tree_add_item(tree, tim_dtim_count, tvb,
                            offset + 2, 1, TRUE);
        proto_tree_add_item(tree, tim_dtim_period, tvb,
                            offset + 3, 1, TRUE);
        proto_item_append_text(ti, ": DTIM %u of %u bitmap",
                               tvb_get_guint8(tvb, offset + 2),
                               tvb_get_guint8(tvb, offset + 3));

        bmapctl = tvb_get_guint8(tvb, offset + 4);
        bmapoff = bmapctl>>1;
        proto_tree_add_uint_format(tree, tim_bmapctl, tvb,
                            offset + 4, 1, bmapctl,
                            "Bitmap Control: 0x%02X (mcast:%u, bitmap offset %u)",
                            bmapctl, bmapctl&1, bmapoff);

        bmaplen = tag_len - 3;
        bmap = tvb_get_ptr(tvb, offset + 5, bmaplen);
        if (bmaplen==1 && 0==bmap[0] && !(bmapctl&1)) {
          proto_item_append_text(ti, " empty");
        } else {
          if (bmapctl&1) {
            proto_item_append_text(ti, " mcast");
          }
        }
        if (bmaplen>1 || bmap[0]) {
          int len=g_snprintf (out_buff, SHORT_STR,
                            "Bitmap: traffic for AID's:");
          int i=0;
          for (i=0;i<bmaplen*8;i++) {
            if (bmap[i/8] & (1<<(i%8))) {
              int aid=i+2*bmapoff*8;
              len+=g_snprintf (out_buff+len, SHORT_STR-len," %u", aid);
              proto_item_append_text(ti, " %u", aid);
              if (len>=SHORT_STR) {
                break;
              }
            }
          }
          out_buff[SHORT_STR-1] = '\0';
          proto_tree_add_string_format (tree, tag_interpretation, tvb, offset + 5,
               bmaplen, out_buff, "%s", out_buff);
        }
      }
      break;

    case TAG_IBSS_PARAMETER:
      if (tag_len < 2)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 2",
                             tag_len);
        break;
      }
      g_snprintf (out_buff, SHORT_STR, "ATIM window 0x%X",
                tvb_get_letohs(tvb, offset + 2));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      proto_item_append_text(ti, ": %s", out_buff);
      break;

    case TAG_COUNTRY_INFO: /* IEEE 802.11d-2001 and IEEE 802.11j-2004 */
      {
        guint8 ccode[2+1];

        if (tag_len < 3)
        {
          proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 3",
                               tag_len);
          break;
        }
        tvb_memcpy(tvb, ccode, offset + 2, 2);
        ccode[2] = '\0';
        g_snprintf (out_buff, SHORT_STR, "Country Code: %s, %s Environment",
                 format_text(ccode, 2),
                 val_to_str(tvb_get_guint8(tvb, offset + 4), environment_vals,"Unknown (0x%02x)"));
        out_buff[SHORT_STR-1] = '\0';
        proto_item_append_text(ti, ": %s", out_buff);
        proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,3, out_buff);

        for (i = 3; (i + 3) <= tag_len; i += 3)
        {
	  guint8 val1, val2, val3;
	  val1 = tvb_get_guint8(tvb, offset + 2 + i);
	  val2 = tvb_get_guint8(tvb, offset + 3 + i);
	  val3 = tvb_get_guint8(tvb, offset + 4 + i);

	  if (val1 <= 200) {  /* 802.11d */
            proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 2+i,3, out_buff,
                                       "  Start Channel: %u, Channels: %u, Max TX Power: %d dBm",
                                       val1, val2, (gint) val3);
	  } else {  /* 802.11j */
            proto_tree_add_string_format(tree, tag_interpretation, tvb, offset + 2+i,3, out_buff,
                                       "  Reg Extension Id: %u, Regulatory Class: %u, Coverage Class: %u",
                                       val1, val2, val3);
	  }
        }
      }
      break;

    case TAG_QBSS_LOAD:
      if (tag_len < 4 || tag_len >5)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Wrong QBSS Tag Length %u", tag_len);
        break;
      }

      if (tag_len == 4)
      {
        /* QBSS Version 1 */
        proto_tree_add_string (tree, tag_interpretation, tvb, offset + 1,
          tag_len, "Cisco QBSS Version 1 - non CCA");

        /* Extract Values */
        proto_tree_add_uint (tree, hf_qbss_version, tvb, offset + 2, tag_len, 1);
        proto_tree_add_item (tree, hf_qbss_scount, tvb, offset + 2, 2, TRUE);
        proto_tree_add_item (tree, hf_qbss_cu, tvb, offset + 4, 1, FALSE);
        proto_tree_add_item (tree, hf_qbss_adc, tvb, offset + 5, 1, FALSE);
      }
      else if (tag_len == 5)
      {
         /* QBSS Version 2 */
         proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
           tag_len, "802.11e CCA Version");

         /* Extract Values */
         proto_tree_add_uint (tree, hf_qbss_version, tvb, offset + 2, tag_len, 2);
         proto_tree_add_item (tree, hf_qbss_scount, tvb, offset + 2, 2, TRUE);
         proto_tree_add_item (tree, hf_qbss_cu, tvb, offset + 4, 1, FALSE);
         proto_tree_add_item (tree, hf_qbss_adc, tvb, offset + 5, 2, FALSE);
      }
      break;

    case TAG_FH_HOPPING_PARAMETER:
      if (tag_len < 2)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 2",
                             tag_len);
        break;
      }
      g_snprintf (out_buff, SHORT_STR, "Prime Radix: %u, Number of Channels: %u",
                tvb_get_guint8(tvb, offset + 2),
                tvb_get_guint8(tvb, offset + 3));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2, tag_len, out_buff);
      proto_item_append_text(ti, ": %s", out_buff);
      break;

    case TAG_TSPEC:
      if (tag_len != 55)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"TSPEC tag length %u != 55", tag_len);
	break;
      }
      add_fixed_field(tree, tvb, offset + 2, FIELD_QOS_TS_INFO);
      proto_tree_add_item(tree, tspec_nor_msdu, tvb, offset + 5, 2, TRUE);
      proto_tree_add_item(tree, tspec_max_msdu, tvb, offset + 7, 2, TRUE);
      proto_tree_add_item(tree, tspec_min_srv, tvb, offset + 9, 4, TRUE);
      proto_tree_add_item(tree, tspec_max_srv, tvb, offset + 13, 4, TRUE);
      proto_tree_add_item(tree, tspec_inact_int, tvb, offset + 17, 4, TRUE);
      proto_tree_add_item(tree, tspec_susp_int, tvb, offset + 21, 4, TRUE);
      proto_tree_add_item(tree, tspec_srv_start, tvb, offset + 25, 4, TRUE);
      proto_tree_add_item(tree, tspec_min_data, tvb, offset + 29, 4, TRUE);
      proto_tree_add_item(tree, tspec_mean_data, tvb, offset + 33, 4, TRUE);
      proto_tree_add_item(tree, tspec_peak_data, tvb, offset + 37, 4, TRUE);
      proto_tree_add_item(tree, tspec_burst_size, tvb, offset + 41, 4, TRUE);
      proto_tree_add_item(tree, tspec_delay_bound, tvb, offset + 45, 4, TRUE);
      proto_tree_add_item(tree, tspec_min_phy, tvb, offset + 49, 4, TRUE);
      proto_tree_add_item(tree, tspec_surplus, tvb, offset + 53, 2, TRUE);
      proto_tree_add_item(tree, tspec_medium, tvb, offset + 55, 2, TRUE);
      break;

    case TAG_TS_DELAY:
      if (tag_len != 4)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"TS_DELAY tag length %u != 4", tag_len);
	break;
      }
      proto_tree_add_item(tree, ts_delay, tvb, offset + 2, 4, TRUE);
      break;

    case TAG_TCLAS:
      if (tag_len < 6)
      {
	proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"TCLAS element is too small %u", tag_len);
	break;
      }
      {
	guint8 type;
	guint8 version;

	type = tvb_get_guint8(tvb, offset + 2);
	proto_tree_add_item(tree, hf_tsinfo_up, tvb, offset + 2, 1, TRUE);
	proto_tree_add_item(tree, hf_class_type, tvb, offset + 3, 1, TRUE);
	proto_tree_add_item(tree, hf_class_mask, tvb, offset + 4, 1, TRUE);
	switch (type)
	  {
	    case 0:
	      proto_tree_add_item(tree, ff_src_mac_addr, tvb, offset + 5,
	      			  6, TRUE);
	      proto_tree_add_item(tree, ff_dst_mac_addr, tvb, offset + 11,
	      			  6, TRUE);
	      proto_tree_add_item(tree, hf_ether_type, tvb, offset + 17,
	      			  2, TRUE);
	      break;

	    case 1:
	      version = tvb_get_guint8(tvb, offset + 5);
	      proto_tree_add_item(tree, cf_version, tvb, offset + 5, 1, TRUE);
	      if (version == 4)
	      {
	        proto_tree_add_item(tree, cf_ipv4_src, tvb, offset + 6,
				    4, FALSE);
	        proto_tree_add_item(tree, cf_ipv4_dst, tvb, offset + 10,
				    4, FALSE);
	        proto_tree_add_item(tree, cf_src_port, tvb, offset + 14,
				    2, FALSE);
	        proto_tree_add_item(tree, cf_dst_port, tvb, offset + 16,
				    2, FALSE);
	        proto_tree_add_item(tree, cf_dscp, tvb, offset + 18,
				    1, FALSE);
	        proto_tree_add_item(tree, cf_protocol, tvb, offset + 19,
				    1, FALSE);
	      }
	      else if (version == 6)
	      {
	        proto_tree_add_item(tree, cf_ipv6_src, tvb, offset + 6,
				    16, FALSE);
	        proto_tree_add_item(tree, cf_ipv6_dst, tvb, offset + 22,
				    16, FALSE);
	        proto_tree_add_item(tree, cf_src_port, tvb, offset + 38,
				    2, FALSE);
	        proto_tree_add_item(tree, cf_dst_port, tvb, offset + 40,
				    2, FALSE);
	        proto_tree_add_item(tree, cf_flow, tvb, offset + 42,
				    3, FALSE);
	      }
	      break;

	    case 2:
	      proto_tree_add_item(tree, cf_tag_type, tvb, offset + 5,
	      			  2, TRUE);
	      break;

	    default:
	      break;
	  }
      }
      break;

    case TAG_TCLAS_PROCESS:
      if (tag_len != 1)
      {
	proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"TCLAS_PROCESS element length %u != 1", tag_len);
	break;
      }
      proto_tree_add_item(tree, hf_tclas_process, tvb, offset + 2, 1, TRUE);
      break;

    case TAG_SCHEDULE:
      if (tag_len != 14)
      {
	proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"TCLAS_PROCESS element length %u != 14", tag_len);
	break;
      }
      add_fixed_field(tree, tvb, offset + 2, FIELD_SCHEDULE_INFO);
      proto_tree_add_item(tree, hf_sched_srv_start, tvb, offset + 4, 4, TRUE);
      proto_tree_add_item(tree, hf_sched_srv_int, tvb, offset + 8, 4, TRUE);
      proto_tree_add_item(tree, hf_sched_spec_int, tvb, offset + 12, 2, TRUE);
      break;

    case TAG_CHALLENGE_TEXT:
      g_snprintf (out_buff, SHORT_STR, "Challenge text: %s",
                tvb_bytes_to_str(tvb, offset + 2, tag_len));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;

    case TAG_ERP_INFO:
    case TAG_ERP_INFO_OLD:
      {
        guint8 erp_info;

        if (tag_len < 1)
        {
          proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 1",
                               tag_len);
          break;
        }
        erp_info = tvb_get_guint8 (tvb, offset + 2);
        g_snprintf (print_buff, SHORT_STR, "%sNon-ERP STAs, %suse protection, %s preambles",
                  erp_info & 0x01 ? "" : "no ",
                  erp_info & 0x02 ? "" : "do not ",
                  /* 802.11g, 7.3.2.13: 1 means "one or more ... STAs
                   * are not short preamble capable" */
                  erp_info & 0x04 ? "long": "short or long");
        print_buff[SHORT_STR-1] = '\0';
        g_snprintf (out_buff, SHORT_STR,
                  "ERP info: 0x%x (%s)",erp_info,print_buff);
        out_buff[SHORT_STR-1] = '\0';
        proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
                               tag_len, out_buff);
        proto_item_append_text(ti, ": %s", print_buff);
      }
      break;

    case TAG_CISCO_UNKNOWN_1:
	/* From WCS manual:
         * If Aironet IE support is enabled, the access point sends an Aironet
         * IE 0x85 (which contains the access point name, load, number of
         * associated clients, and so on) in the beacon and probe responses of
         * this WLAN, and the controller sends Aironet IEs 0x85 and 0x95
         * (which contains the management IP address of the controller and
         * the IP address of the access point) in the reassociation response
         * if it receives Aironet IE 0x85 in the reassociation request.
         */

      /* The Name of the sending device starts at offset 10 and is up to
         15 or 16 bytes in length, \0 padded */
      if (tag_len < 26)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len, "Tag length %u too short, must be >= 26",
                             tag_len);
        break;
      }
      /* A cisco AP transmits the first 15 bytes of the AP name, probably
         followed by '\0' for ASCII termination */
      g_snprintf (out_buff, SHORT_STR, "%.16s",
                tvb_format_stringzpad(tvb, offset + 12, 16));
      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string_format (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, "", "Tag interpretation: Unknown + Name: %s #Clients: %u",
			     out_buff,
			     /* Total number off associated clients and
				repeater access points */
			     tvb_get_guint8(tvb, offset + 28));
      if (check_col (pinfo->cinfo, COL_INFO)) {
          col_append_fstr(pinfo->cinfo, COL_INFO, ", Name: \"%s\"", out_buff);
      }
      break;

    case TAG_VENDOR_SPECIFIC_IE:
      tvb_ensure_bytes_exist (tvb, offset + 2, tag_len);
      if (tag_len >= 3) {
		oui = tvb_get_ntoh24(tvb, offset + 2);
		tag_tvb = tvb_new_subset(tvb, offset + 2, tag_len, tag_len);

#define WPAWME_OUI	0x0050F2
#define RSNOUI_VAL	0x000FAC
#define PRE11N_OUI  0x00904c

		switch (oui) {
		case WPAWME_OUI:
			dissect_vendor_ie_wpawme(ti, tree, tag_tvb);
			break;
		case RSNOUI_VAL:
			dissect_vendor_ie_rsn(ti, tree, tag_tvb);
			break;
		case OUI_CISCOWL:	/* Cisco Wireless (Aironet) */
			dissect_vendor_ie_aironet(ti, tree, tvb, offset + 5, tag_len - 3);
			break;
        case PRE11N_OUI:
            dissect_vendor_ie_ht(ti, tree, tag_tvb);
            break;
		default:
			tag_data_ptr = tvb_get_ptr(tag_tvb, 0, 3);
			proto_tree_add_bytes_format (tree, tag_oui, tvb, offset + 2, 3,
				tag_data_ptr, "Vendor: %s", get_manuf_name(tag_data_ptr));
			proto_item_append_text(ti, ": %s", get_manuf_name(tag_data_ptr));
			proto_tree_add_string (tree, tag_interpretation, tvb, offset + 5,
				tag_len - 3, "Not interpreted");
			break;
		}

      }
      break;

    case TAG_RSN_IE:
      tag_tvb = tvb_new_subset(tvb, offset + 2, tag_len, tag_len);
      dissect_rsn_ie(tree, tag_tvb);
      break;

  case TAG_HT_CAPABILITY:
    dissect_ht_capability_ie(tree, tvb, offset + 2, tag_len);
    break;

  case TAG_HT_INFO:
    dissect_ht_info_ie_1_1(tree, tvb, offset + 2, tag_len);
    break;
  /*** Begin: Secondary Channel Offset Tag - Dustin Johnson ***/
  case TAG_SECONDARY_CHANNEL_OFFSET:
    secondary_channel_offset_ie(tree, tvb, offset + 2, tag_len);
    break;
  /*** End: Secondary Channel Offset Tag - Dustin Johnson ***/
  /*** Begin: Measure Request Tag - Dustin Johnson ***/
  case TAG_MEASURE_REQ:
      if (tag_len < 3)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Measurement Request: Error: Tag length must be at least 3 bytes long");
      } else {
	    guint8 info, request_type;
		guint tag_offset;
		proto_item *parent_item;
		proto_tree *sub_tree;

		offset += 2;
		tag_offset = offset;
	    info = tvb_get_guint8 (tvb, offset);
	    proto_tree_add_uint_format(tree, hf_tag_measure_request_measurement_token, tvb,
		                           offset, 1, info, "Measurement Token: 0x%02X", info);

		info = tvb_get_guint8 (tvb, ++offset);
	    parent_item = proto_tree_add_uint_format(tree, hf_tag_measure_request_mode, tvb,
		                    offset, 1, info, "Measurement Request Mode: 0x%02X", info);
		sub_tree = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);
		proto_tree_add_uint(sub_tree, hf_tag_measure_request_mode_reserved1, tvb, offset, 1, info);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_request_mode_enable, tvb, offset, 1, info);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_request_mode_request, tvb, offset, 1, info);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_request_mode_report, tvb, offset, 1, info);
		proto_tree_add_uint(sub_tree, hf_tag_measure_request_mode_reserved2, tvb, offset, 1, info);

        request_type = tvb_get_guint8 (tvb, ++offset);
	    parent_item = proto_tree_add_uint(tree, hf_tag_measure_request_type, tvb, offset, 1, request_type);
	    sub_tree = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);

		offset++;
	    switch (request_type){
		case 0: /* Basic Request */
		case 1: /* Clear channel assessment (CCA) request */
		case 2: /* Receive power indication (RPI) histogram request */
		{
		  guint8 channel_number;
		  guint64 start_time;
		  guint16 duration;

		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_request_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016llX", start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_duration, tvb, offset, 2, duration, "Measurement Duration: 0x%04X TU (1 TU = 1024 us)", duration);
		  break;
		}
		case 3: /* Channel Load Request */
		case 4: /* Noise Histogram Request */
		{
		  guint8 regulatory_class, channel_number;
		  guint16 rand_interval, duration;

		  regulatory_class = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_regulatory_class, tvb, offset, 1, regulatory_class, "Regulatory Class: 0x%02X", regulatory_class);

		  offset++;
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  rand_interval = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_randomization_interval, tvb, offset, 2, rand_interval, "Randomization Interval: 0x%02X TU (1 TU = 1024 us)", rand_interval);

		  offset += 2;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_duration, tvb, offset, 2, duration, "Measurement Duration: 0x%04X TU (1 TU = 1024 us)", duration);
		  break;
		}
		case 5: /* Beacon Request */
		{
		  guint8 regulatory_class, channel_number, measurement_mode, reporting_condition, threshold_offset;
		  guint16 rand_interval, duration;
		  const guint8 *bssid = NULL;

		  regulatory_class = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_regulatory_class, tvb, offset, 1, regulatory_class, "Regulatory Class: 0x%02X", regulatory_class);

		  offset++;
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  rand_interval = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_randomization_interval, tvb, offset, 2, rand_interval, "Randomization Interval: 0x%02X TU (1 TU = 1024 us)", rand_interval);

		  offset += 2;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_duration, tvb, offset, 2, duration, "Measurement Duration: 0x%04X TU (1 TU = 1024 us)", duration);

		  offset+=2;
		  measurement_mode = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_request_measurement_mode, tvb, offset, 1, measurement_mode);

		  offset++;
		  bssid = tvb_get_ptr (tvb, offset, 6);
		  proto_tree_add_ether(sub_tree, hf_tag_measure_request_bssid, tvb, offset, 6, bssid);

		  offset+=6;
		  reporting_condition = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_request_reporting_condition, tvb, offset, 1, reporting_condition);

		  offset++;
		  threshold_offset = tvb_get_guint8 (tvb, offset);
		  if (reporting_condition == 0){
		  } else if (reporting_condition >= 1 && reporting_condition <= 4){ /* Unsigned dBm */
		    proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_threshold_offset_unsigned, tvb, offset, 1, threshold_offset, "Threshold/Offset: 0x%02X dBm", threshold_offset);
	      } else if (reporting_condition == 5 || reporting_condition == 6 || reporting_condition == 9){ /* Signed dBm */
		    proto_tree_add_int_format(sub_tree, hf_tag_measure_request_threshold_offset_signed, tvb, offset, 1, threshold_offset, "Threshold/Offset: 0x%02X dBm", threshold_offset);
		  } else if (reporting_condition == 7 || reporting_condition == 8 || reporting_condition == 10){ /* Signed dB */
		    proto_tree_add_int_format(sub_tree, hf_tag_measure_request_threshold_offset_signed, tvb, offset, 1, threshold_offset, "Threshold/Offset: 0x%02X dB", threshold_offset);
		  } else {
		    /* Not Defined */
		  }
		  offset++;

		  add_tagged_field (pinfo, sub_tree, tvb, offset);

		  break;
		}
		case 6: /* Frame Request */
		{
		  guint8 regulatory_class, channel_number;
		  guint16 rand_interval, duration;
		  const guint8 *mac = NULL;

		  regulatory_class = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_regulatory_class, tvb, offset, 1, regulatory_class, "Regulatory Class: 0x%02X", regulatory_class);

		  offset++;
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  rand_interval = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_randomization_interval, tvb, offset, 2, rand_interval, "Randomization Interval: 0x%02X TU (1 TU = 1024 us)", rand_interval);

		  offset += 2;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_duration, tvb, offset, 2, duration, "Measurement Duration: 0x%04X TU (1 TU = 1024 us)", duration);

		  offset += 2;
		  if (tag_len >= ((offset-tag_offset)+6)){
		    mac = tvb_get_ptr (tvb, offset, 6);
		    proto_tree_add_ether(sub_tree, hf_tag_measure_request_bssid, tvb, offset, 6, mac);
		  }
		  break;
		}
		case 7: /* BSTA Statistics Request */
		{
		  guint8 group_id;
		  guint16 rand_interval, duration;

		  offset++;
		  rand_interval = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_randomization_interval, tvb, offset, 2, rand_interval, "Randomization Interval: 0x%02X TU (1 TU = 1024 us)", rand_interval);

		  offset += 2;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_request_duration, tvb, offset, 2, duration, "Measurement Duration: 0x%04X TU (1 TU = 1024 us)", duration);

		  offset++;
		  group_id = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_request_group_id, tvb, offset, 1, group_id);
		  break;
		}
		case 8: /* Location Configuration Indication (LCI) Request */
		  /* TODO */
		case 9: /* Transmit Stream Measurement Request */
		  /* TODO */
		case 255: /* Measurement Pause Request*/
		  /* TODO */
		default: /* unkown */
		  proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Undissected Data");
		  break;
		}
	  }

    break;
  /* End: Measure Request Tag - Dustin Johnson */
  /* Begin: Measure Report Tag - Dustin Johnson */
  case TAG_MEASURE_REP:
      if (tag_len < 5)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Measurement Report: Error: Tag length must be at least 5 bytes long");
      } else {
	    guint8 info, report_type, channel_number;
		guint16 duration;
		guint64 start_time;
		proto_item *parent_item;
		proto_tree *sub_tree;
		guint tag_offset;

		offset += 2;
		tag_offset = offset;
	    info = tvb_get_guint8 (tvb, offset);
	    proto_tree_add_uint_format(tree, hf_tag_measure_report_measurement_token, tvb,
		                           offset, 1, info, "Measurement Token: 0x%02X", info);

		offset++;
		info = tvb_get_guint8 (tvb, offset);
	    parent_item = proto_tree_add_uint_format(tree, hf_tag_measure_report_mode, tvb,
		                    offset, 1, info, "Measurement Report Mode: 0x%02X", info);
		sub_tree = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_report_mode_late, tvb, offset, 1, info);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_report_mode_incapable, tvb, offset, 1, info);
		proto_tree_add_boolean(sub_tree, hf_tag_measure_report_mode_refused, tvb, offset, 1, info);
		proto_tree_add_uint(sub_tree, hf_tag_measure_report_mode_reserved, tvb, offset, 1, info);

		offset++;
        report_type = tvb_get_guint8 (tvb, offset);
	    parent_item = proto_tree_add_uint(tree, hf_tag_measure_report_type, tvb, offset, 1, report_type);
	    sub_tree = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);

		offset++;
	    switch (report_type){
		case 0: /* Basic Report */
		{
		  proto_tree *sub_tree_map_field;

          channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_report_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016" PRIx64, start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_duration, tvb, offset, 2, duration, "Measurement Duration in TUs (1TU = 1024 us): 0x%04X", duration);

		  offset+=2;
		  info = tvb_get_guint8 (tvb, offset);
		  parent_item = proto_tree_add_uint_format(tree, hf_tag_measure_basic_map_field, tvb,
		                    offset, 1, info, "Map Field: 0x%02X", info);
		  sub_tree_map_field = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);
		  proto_tree_add_boolean(sub_tree_map_field, hf_tag_measure_map_field_bss, tvb, offset, 1, info);
		  proto_tree_add_boolean(sub_tree_map_field, hf_tag_measure_map_field_odfm, tvb, offset, 1, info);
		  proto_tree_add_boolean(sub_tree_map_field, hf_tag_measure_map_field_unident_signal, tvb, offset, 1, info);
		  proto_tree_add_boolean(sub_tree_map_field, hf_tag_measure_map_field_radar, tvb, offset, 1, info);
		  proto_tree_add_boolean(sub_tree_map_field, hf_tag_measure_map_field_unmeasured, tvb, offset, 1, info);
		  proto_tree_add_uint(sub_tree_map_field, hf_tag_measure_map_field_reserved, tvb, offset, 1, info);
		  break;
		}
		case 1: /* Clear channel assessment (CCA) report */
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_report_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016llX", start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_duration, tvb, offset, 2, duration, "Measurement Duration in TUs (1TU = 1024 us): 0x%04X", duration);

		  offset+=2;
		  info = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(tree, hf_tag_measure_cca_busy_fraction, tvb, offset, 1, info, "CCA Busy Fraction: 0x%02X", info);
		  break;
		case 2: /* Receive power indication (RPI) histogram report */
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_report_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016llX", start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_duration, tvb, offset, 2, duration, "Measurement Duration in TUs (1TU = 1024 us): 0x%04X", duration);

		  offset+=2;
		  parent_item = proto_tree_add_string(tree, hf_tag_measure_rpi_histogram_report, tvb,
		                    offset, 8, "RPI Histogram Report");
		  sub_tree = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);
		  info = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_0, tvb, offset, 1, info, "RPI 0 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_1, tvb, offset, 1, info, "RPI 1 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_2, tvb, offset, 1, info, "RPI 2 Density: 0x%02X", info);
	      info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_3, tvb, offset, 1, info, "RPI 3 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_4, tvb, offset, 1, info, "RPI 4 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_5, tvb, offset, 1, info, "RPI 5 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_6, tvb, offset, 1, info, "RPI 6 Density: 0x%02X", info);
		  info = tvb_get_guint8 (tvb, ++offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_rpi_histogram_report_7, tvb, offset, 1, info, "RPI 7 Density: 0x%02X", info);
			break;
		case 3: /* Channel Load Report */
        {
		  guint8 regulatory_class, channel_load;

          regulatory_class = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_report_regulatory_class, tvb, offset, 1, regulatory_class);

		  offset++;
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_report_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016llX", start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_duration, tvb, offset, 2, duration, "Measurement Duration in TUs (1TU = 1024 us): 0x%04X", duration);

		  offset+=2;
		  channel_load = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(tree, hf_tag_measure_report_channel_load, tvb, offset, 1, channel_load);
		  break;
		}
		case 4: /* Noise Histogram Report */
          /* TODO */
		  proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Undissected Data");
		  break;
		case 5: /* Beacon Report */
        {
		  guint8 regulatory_class, reported_frame_info, rcpi, rsni, ant_id;
		  guint32 parent_tsf;
		  proto_tree *sub_tree_frame_info;
		  const guint8 *bssid = NULL;

          regulatory_class = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_report_regulatory_class, tvb, offset, 1, regulatory_class);

		  offset++;
		  channel_number = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_channel_number, tvb, offset, 1, channel_number, "Measurement Channel Number: 0x%02X", channel_number);

		  offset++;
		  start_time = tvb_get_letoh64 (tvb, offset);
		  proto_tree_add_uint64_format(sub_tree, hf_tag_measure_report_start_time, tvb, offset, 8, start_time, "Measurement Start Time: 0x%016llX", start_time);

		  offset += 8;
		  duration = tvb_get_letohs (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_duration, tvb, offset, 2, duration, "Measurement Duration in TUs (1TU = 1024 us): 0x%04X", duration);

		  offset+=2;
		  reported_frame_info = tvb_get_guint8 (tvb, offset);
		  parent_item = proto_tree_add_uint(sub_tree, hf_tag_measure_report_frame_info, tvb, offset, 1, reported_frame_info);
		    sub_tree_frame_info = proto_item_add_subtree(parent_item, ett_tag_measure_request_tree);
		    proto_tree_add_uint(sub_tree_frame_info, hf_tag_measure_report_frame_info_phy_type, tvb, offset, 1, reported_frame_info);
		    proto_tree_add_uint(sub_tree_frame_info, hf_tag_measure_report_frame_info_frame_type, tvb, offset, 1, reported_frame_info);

		  offset++;
		  rcpi = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_rcpi, tvb, offset, 1, rcpi, "Received Channel Power Indicator (RCPI): 0x%02X dBm", rcpi);

		  offset++;
		  rsni = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint_format(sub_tree, hf_tag_measure_report_rsni, tvb, offset, 1, rsni, "Received Signal to Noise Indicator (RSNI): 0x%02X dB", rsni);

		  offset++;
		  bssid = tvb_get_ptr (tvb, offset, 6);
		  proto_tree_add_ether(sub_tree, hf_tag_measure_request_bssid, tvb, offset, 6, bssid);

		  offset+=6;
		  ant_id = tvb_get_guint8 (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_report_ant_id, tvb, offset, 1, ant_id);

		  offset++;
		  parent_tsf = tvb_get_letohl (tvb, offset);
		  proto_tree_add_uint(sub_tree, hf_tag_measure_report_parent_tsf, tvb, offset, 4, parent_tsf);

		  offset+=4;
		  /* TODO - Must determine frame type and dissect this */
		  if (tag_len > (offset - tag_offset))
          {
            proto_tree_add_text (sub_tree, tvb, offset, tag_len - (offset - tag_offset), "Reported Frame Body");
	      }
		  break;
		}
		case 6: /* Frame Report */
          /* TODO */
		case 7: /* BSTA Statistics Report */
          /* TODO */
		case 8: /* Location Configuration Information Report element */
          /* TODO */
		case 9: /* Transmit Stream Measurement Report */
          /* TODO */
		default: /* unkown */
		  proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Undissected Data");
		  break;
		}
	  }

    break;
    /*** End: Measure Report Tag - Dustin Johnson ***/
	/*** Begin: Extended Capabilities Tag - Dustin Johnson ***/
    case TAG_EXTENDED_CAPABILITIES:
	{
	  guint tag_offset;
	  guint8 info_exchange;

	  if (tag_len < 1)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Extendend Capabilities: Error: Tag length must be at least 1 byte long");
		break;
	  }
	  offset+=2;
	  tag_offset = offset;

	  info_exchange = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_extended_capabilities, tvb, offset, 1, info_exchange);

	  if (tag_len > (offset - tag_offset))
      {
        proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Unkown Data");
		break;
	  }
	  break;
	}
	/*** End: Extended Capabilities Tag - Dustin Johnson ***/
	/*** Begin: Neighbor Report Tag - Dustin Johnson ***/
	case TAG_NEIGHBOR_REPORT:
	{
	  #define SUB_TAG_TSF_INFO                 0x01
	  #define SUB_TAG_MEASUREMENT_PILOT_INFO   0x02
	  #define SUB_TAG_HT_CAPABILITIES          0x03
	  #define SUB_TAG_HT_INFO                  0x04
	  #define SUB_TAG_SEC_CHANNEL_OFFSET       0x05
	  #define SUB_TAG_VENDOR_SPECIFIC          0xDD


	  guint tag_offset;
	  guint8 sub_tag_id;
	  guint32 bssid_info, info, sub_tag_length;
	  const guint8 *bssid = NULL;
	  proto_item *parent_item;
	  proto_tree *bssid_info_subtree, *sub_tag_tree;
	  tvbuff_t *volatile sub_tag_tvb = NULL;

	  if (tag_len < 13)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Neighbor Report: Error: Tag length must be at least 13 bytes long");
		break;
	  }
	  offset+=2;
	  tag_offset = offset;

	  bssid = tvb_get_ptr (tvb, offset, 6);
	  proto_tree_add_ether(tree, hf_tag_neighbor_report_bssid, tvb, offset, 6, bssid);

	  /*** Begin: BSSID Information ***/
	  offset+=6;
	  bssid_info = tvb_get_letohl (tvb, offset);
	  parent_item = proto_tree_add_uint_format(tree, hf_tag_neighbor_report_bssid_info, tvb, offset, 4, bssid_info, "BSSID Information: 0x%08X", bssid_info);
	  bssid_info_subtree = proto_item_add_subtree(parent_item, ett_tag_neighbor_report_bssid_info_tree);

	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_reachability, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_security, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_key_scope, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_spec_mng, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_qos, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_apsd, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_radio_msnt, tvb, offset, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_dback, tvb, offset+1, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_capability_iback, tvb, offset+1, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_mobility_domain, tvb, offset+1, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_high_throughput, tvb, offset+1, 1, bssid_info);
	  proto_tree_add_uint(bssid_info_subtree, hf_tag_neighbor_report_bssid_info_reserved, tvb, offset+1, 3, (bssid_info & 0xfffff000) >> 12);
      /*** End: BSSID Information ***/

	  offset+=4;
	  info = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint_format(tree, hf_tag_neighbor_report_reg_class, tvb, offset, 1, info, "Regulatory Class: 0x%02X", info);

	  offset++;
	  info = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint_format(tree, hf_tag_neighbor_report_channel_number, tvb, offset, 1, info, "Channel Number: 0x%02X", info);

	  offset++;
	  info = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint_format(tree, hf_tag_neighbor_report_phy_type, tvb, offset, 1, info, "PHY Type: 0x%02X", info);

	  offset++;
	  sub_tag_id = tvb_get_guint8 (tvb, offset);
	  offset++;
	  sub_tag_length = tvb_get_guint8 (tvb, offset);

      offset++;
	  sub_tag_tvb = tvb_new_subset(tvb, offset, sub_tag_length, -1);

	  switch (sub_tag_id){
	  case SUB_TAG_TSF_INFO:
	    /* TODO */
	    break;
	  case SUB_TAG_MEASUREMENT_PILOT_INFO:
	    /* TODO */
	    break;
	  case SUB_TAG_HT_CAPABILITIES:
	    parent_item = proto_tree_add_text (tree, tvb, offset, sub_tag_length, "HT Capabilities");
		sub_tag_tree = proto_item_add_subtree(parent_item, ett_tag_neighbor_report_sub_tag_tree);
	    dissect_ht_capability_ie(sub_tag_tree, sub_tag_tvb, 0, sub_tag_length);
	    break;
	  case SUB_TAG_HT_INFO:
	    parent_item = proto_tree_add_text (tree, tvb, offset, sub_tag_length, "HT Information");
		sub_tag_tree = proto_item_add_subtree(parent_item, ett_tag_neighbor_report_sub_tag_tree);
	    dissect_ht_info_ie_1_1(sub_tag_tree, sub_tag_tvb, 0, sub_tag_length);
	    break;
	  case SUB_TAG_SEC_CHANNEL_OFFSET:
	    parent_item = proto_tree_add_text (tree, tvb, offset, sub_tag_length, "Secondary Channel Offset");
		sub_tag_tree = proto_item_add_subtree(parent_item, ett_tag_neighbor_report_sub_tag_tree);
	    secondary_channel_offset_ie(sub_tag_tree, sub_tag_tvb, 0, sub_tag_length);
	    break;
	  case SUB_TAG_VENDOR_SPECIFIC:
	  default:
	    break;
	  }

	  offset += sub_tag_length;

	  if (tag_len > (offset - tag_offset))
      {
        proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Unkown Data");
		break;
	  }
	  break;
	}
	/*** End: Neighbor Report Tag - Dustin Johnson ***/
	#if 0 /*Not yet assigned tag numbers by ANA */
	/*** Begin: Extended Channel Switch Announcement Tag - Dustin Johnson ***/
	case TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT:
	{
	  guint tag_offset;
	  guint8 current_field;

	  if (tag_len != 4)
      {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Extended Channel Switch Announcement: Error: Tag length must be exactly 4 bytes long");
		break;
	  }

	  offset+=2;
	  tag_offset = offset;

	  current_field = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_ext_channel_switch_announcement_switch_mode, tvb, offset, 1, current_field);

	  offset++;
	  current_field = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_ext_channel_switch_announcement_new_reg_class, tvb, offset, 1, current_field);

	  offset++;
	  current_field = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_ext_channel_switch_announcement_new_chan_number, tvb, offset, 1, current_field);

	  offset++;
	  current_field = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_ext_channel_switch_announcement_switch_count, tvb, offset, 1, current_field);

	  offset++;
	  if (tag_len > (offset - tag_offset))
      {
        proto_tree_add_text (tree, tvb, offset, tag_len - (offset - tag_offset), "Unkown Data");
		break;
	  }
	  break;
	}
	/*** End: Extended Channel Switch Announcement Tag - Dustin Johnson ***/
	#endif
	#if 0 /*Not yet assigned tag numbers by ANA */
	/*** Begin: Supported Regulatory Classes Tag - Dustin Johnson ***/
	case TAG_SUPPORTED_REGULATORY_CLASSES:
	{
	  guint tag_offset;
	  guint8 current_field;

	  if (tag_len < 2) {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Supported Regulatory Classes: Error: Tag length must be at least 2 bytes long");
		break;
	  }else if (tag_len > 32) {
        proto_tree_add_text (tree, tvb, offset + 2, tag_len,
		"Supported Regulatory Classes: Error: Tag length must be no more than 32 bytes long");
		break;
	  }

	  offset+=2;
	  tag_offset = offset;

	  current_field = tvb_get_guint8 (tvb, offset);
	  proto_tree_add_uint(tree, hf_tag_supported_reg_classes_current, tvb, offset, 1, current_field);

	  offset++;
	  /* Partially taken from the ssid section */
	  tag_data_ptr = tvb_get_ptr (tvb, offset, tag_len);
	  for (i = 0, n = 0; i < tag_len && n < SHORT_STR; i++) {
        ret = g_snprintf (print_buff + n, SHORT_STR - n, (i == tag_len-1)?"%d":"%d, ", tag_data_ptr[i]);
        if (ret == -1 || ret >= SHORT_STR - n) {
          /* Some versions of snprintf return -1 if they'd truncate
             the output. Others return <buf_size> or greater.  */
          break;
        }
        n += ret;
      }
	  print_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, hf_tag_supported_reg_classes_alternate, tvb, offset, tag_len, print_buff);

	  break;
	}
	/*** End: Supported Regulatory Classes Tag - Dustin Johnson ***/
	#endif
    default:
      tvb_ensure_bytes_exist (tvb, offset + 2, tag_len);
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, "Not interpreted");
      proto_item_append_text(ti, ": Tag %u Len %u", tag_no, tag_len);
      break;
    }

  return tag_len + 2;
}

void
ieee_80211_add_tagged_parameters (tvbuff_t * tvb, int offset, packet_info * pinfo,
	proto_tree * tree, int tagged_parameters_len)
{
  int next_len;

  beacon_padding = 0; /* this is for the beacon padding confused with ssid fix */
  while (tagged_parameters_len > 0) {
    if ((next_len=add_tagged_field (pinfo, tree, tvb, offset))==0)
      break;
    if (next_len > tagged_parameters_len) {
      /* XXX - flag this as an error? */
      next_len = tagged_parameters_len;
    }
    offset += next_len;
    tagged_parameters_len -= next_len;
  }
}

/* ************************************************************************* */
/*                     Dissect 802.11 management frame                       */
/* ************************************************************************* */
static void
dissect_ieee80211_mgt (guint16 fcf, tvbuff_t * tvb, packet_info * pinfo,
	proto_tree * tree)
{
      proto_item *ti = NULL;
      proto_tree *mgt_tree;
      proto_tree *fixed_tree;
      proto_tree *tagged_tree;
      int offset = 0;
      int tagged_parameter_tree_len;

      g_pinfo = pinfo;

      CHECK_DISPLAY_AS_X(data_handle,proto_wlan_mgt, tvb, pinfo, tree);

      ti = proto_tree_add_item (tree, proto_wlan_mgt, tvb, 0, -1, FALSE);
      mgt_tree = proto_item_add_subtree (ti, ett_80211_mgt);

      switch (COMPOSE_FRAME_TYPE(fcf))
	{

	case MGT_ASSOC_REQ:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 4);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field(fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);
	  offset = 4;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_ASSOC_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field(fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field(fixed_tree, tvb, 4, FIELD_ASSOC_ID);
	  offset = 6;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_REASSOC_REQ:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 10);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field(fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);
	  add_fixed_field(fixed_tree, tvb, 4, FIELD_CURRENT_AP_ADDR);
	  offset = 10;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;

	case MGT_REASSOC_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field(fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field(fixed_tree, tvb, 4, FIELD_ASSOC_ID);
	  offset = 6;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_PROBE_REQ:
	  offset = 0;
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_PROBE_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 12);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field(fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field(fixed_tree, tvb, 10, FIELD_CAP_INFO);
	  offset = 12;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_BEACON:		/* Dissect protocol payload fields  */
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 12);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field(fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field(fixed_tree, tvb, 10, FIELD_CAP_INFO);
	  offset = 12;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);
	  ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
	      tagged_parameter_tree_len);
	  break;

	case MGT_ATIM:
	  break;

	case MGT_DISASS:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;

	case MGT_AUTHENTICATION:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_AUTH_ALG);
	  add_fixed_field(fixed_tree, tvb, 2, FIELD_AUTH_TRANS_SEQ);
	  add_fixed_field(fixed_tree, tvb, 4, FIELD_STATUS_CODE);
	  offset = 6;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
		  tvb_reported_length_remaining(tvb, offset);
	  if (tagged_parameter_tree_len != 0)
	    {
	      tagged_tree = get_tagged_parameter_tree (mgt_tree,
						       tvb,
						       offset,
						       tagged_parameter_tree_len);
	      ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
		tagged_parameter_tree_len);
	    }
	  break;

	case MGT_DEAUTHENTICATION:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
	  add_fixed_field(fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;

	case MGT_ACTION:
	{

      fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 56);
	  proto_tree_add_text(fixed_tree, tvb, 0, 2, "Contained Frame Control");
      offset += add_fixed_field(fixed_tree, tvb, 0, FIELD_ACTION);

	  tagged_parameter_tree_len = tvb_reported_length_remaining(tvb, offset);
	    if (tagged_parameter_tree_len != 0)
	      {
		tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
							 tagged_parameter_tree_len);
		ieee_80211_add_tagged_parameters (tvb, offset, pinfo, tagged_tree,
						  tagged_parameter_tree_len);
	      }

	  break;
	    }

	}
}

static void
set_src_addr_cols(packet_info *pinfo, const guint8 *addr, const char *type)
{
  if (check_col(pinfo->cinfo, COL_RES_DL_SRC))
    col_add_fstr(pinfo->cinfo, COL_RES_DL_SRC, "%s (%s)",
		    get_ether_name(addr), type);
  if (check_col(pinfo->cinfo, COL_UNRES_DL_SRC))
    col_add_fstr(pinfo->cinfo, COL_UNRES_DL_SRC, "%s",
		     ether_to_str(addr));
}

static void
set_dst_addr_cols(packet_info *pinfo, const guint8 *addr, const char *type)
{
  if (check_col(pinfo->cinfo, COL_RES_DL_DST))
    col_add_fstr(pinfo->cinfo, COL_RES_DL_DST, "%s (%s)",
		     get_ether_name(addr), type);
  if (check_col(pinfo->cinfo, COL_UNRES_DL_DST))
    col_add_fstr(pinfo->cinfo, COL_UNRES_DL_DST, "%s",
		     ether_to_str(addr));
}

static guint32
crc32_802_tvb_padded(tvbuff_t *tvb, guint hdr_len, guint hdr_size, guint len)
{
  guint32 c_crc;

  c_crc = crc32_ccitt_tvb(tvb, hdr_len);
  c_crc = crc32_ccitt_seed(tvb_get_ptr(tvb, hdr_size, len), len, ~c_crc);

  /* Byte reverse. */
  c_crc = ((unsigned char)(c_crc>>0)<<24) |
    ((unsigned char)(c_crc>>8)<<16) |
    ((unsigned char)(c_crc>>16)<<8) |
    ((unsigned char)(c_crc>>24)<<0);

  return ( c_crc );
}

typedef enum {
    ENCAP_802_2,
    ENCAP_IPX,
    ENCAP_ETHERNET
} encap_t;

/* ************************************************************************* */
/*                          Dissect 802.11 frame                             */
/* ************************************************************************* */
static void
dissect_ieee80211_common (tvbuff_t * tvb, packet_info * pinfo,
			  proto_tree * tree, gboolean fixed_length_header,
			  gboolean has_radio_information, gint fcs_len,
			  gboolean wlan_broken_fc, gboolean datapad)
{
  guint16 fcf, flags, frame_type_subtype;
  guint16 seq_control;
  guint32 seq_number, frag_number;
  gboolean more_frags;
  const guint8 *src = NULL;
  const guint8 *dst = NULL;
  const guint8 *bssid = NULL;
  proto_item *ti = NULL;
  proto_item *fcs_item;
  proto_tree *hdr_tree = NULL;
  proto_tree *fcs_tree;
  guint16 hdr_len, ohdr_len;
  gboolean has_fcs, fcs_good, fcs_bad;
  gint len, reported_len, ivlen;
  gboolean is_amsdu = 0;
  gboolean save_fragmented;
  tvbuff_t *volatile next_tvb = NULL;
  guint32 addr_type;
  volatile encap_t encap_type;
  guint8 octet1, octet2;
  char out_buff[SHORT_STR];
  gint is_iv_bad;
  guchar iv_buff[4];
  wlan_hdr *volatile whdr;
  static wlan_hdr whdrs[4];

  whdr= &whdrs[0];

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "IEEE 802.11");
  if (check_col (pinfo->cinfo, COL_INFO))
    col_clear (pinfo->cinfo, COL_INFO);

  /* Add the radio information, if present, to the column information */
  if (has_radio_information) {
    if (check_col(pinfo->cinfo, COL_TX_RATE)) {
	col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%u.%u",
	   pinfo->pseudo_header->ieee_802_11.data_rate / 2,
	   pinfo->pseudo_header->ieee_802_11.data_rate & 1 ? 5 : 0);
    }
    if (check_col(pinfo->cinfo, COL_RSSI)) {
      /* XX - this is a percentage, not a dBm or normalized or raw RSSI */
      col_add_fstr(pinfo->cinfo, COL_RSSI, "%u",
	   pinfo->pseudo_header->ieee_802_11.signal_level);
    }
  }

  fcf = tvb_get_letohs (tvb, 0);
  if (wlan_broken_fc) {
    /* Swap bytes */
    fcf = ((fcf & 0xff) << 8) | (((fcf & 0xff00) >> 8) & 0xff);
  }
  if (fixed_length_header)
    hdr_len = DATA_LONG_HDR_LEN;
  else
    hdr_len = find_header_length (fcf);
  ohdr_len = hdr_len;
  if (datapad)
    hdr_len = roundup2(hdr_len, 4);
  frame_type_subtype = COMPOSE_FRAME_TYPE(fcf);

  if (check_col (pinfo->cinfo, COL_INFO))
      col_set_str (pinfo->cinfo, COL_INFO,
          val_to_str(frame_type_subtype, frame_type_subtype_vals,
              "Unrecognized (Reserved frame)"));

  flags = FCF_FLAGS (fcf);
  more_frags = HAVE_FRAGMENTS (flags);


  /* Add the radio information, if present, and the FC to the current tree */
  if (tree)
    {
      ti = proto_tree_add_protocol_format (tree, proto_wlan, tvb, 0, hdr_len,
					   "IEEE 802.11");
      hdr_tree = proto_item_add_subtree (ti, ett_80211);

      if (has_radio_information) {
	proto_tree_add_uint_format(hdr_tree, hf_data_rate,
				   tvb, 0, 0,
				   pinfo->pseudo_header->ieee_802_11.data_rate,
				   "Data Rate: %u.%u Mb/s",
				   pinfo->pseudo_header->ieee_802_11.data_rate / 2,
				   pinfo->pseudo_header->ieee_802_11.data_rate & 1 ? 5 : 0);

	proto_tree_add_uint(hdr_tree, hf_channel,
			    tvb, 0, 0,
			    pinfo->pseudo_header->ieee_802_11.channel);

	proto_tree_add_uint_format(hdr_tree, hf_signal_strength,
				   tvb, 0, 0,
				   pinfo->pseudo_header->ieee_802_11.signal_level,
				   "Signal Strength: %u%%",
				   pinfo->pseudo_header->ieee_802_11.signal_level);
      }

    dissect_frame_control(hdr_tree, tvb, wlan_broken_fc, 0);

      if (frame_type_subtype == CTRL_PS_POLL)
	proto_tree_add_uint(hdr_tree, hf_assoc_id,tvb,2,2,
			    ASSOC_ID(tvb_get_letohs(tvb,2)));

      else
	  proto_tree_add_uint (hdr_tree, hf_did_duration, tvb, 2, 2,
			       tvb_get_letohs (tvb, 2));
    }

  /*
   * Decode the part of the frame header that isn't the same for all
   * frame types.
   */
  seq_control = 0;
  frag_number = 0;
  seq_number = 0;

  switch (FCF_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      /*
       * All management frame types have the same header.
       */
      src = tvb_get_ptr (tvb, 10, 6);
      dst = tvb_get_ptr (tvb, 4, 6);

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      /* for tap */
      SET_ADDRESS(&whdr->bssid, AT_ETHER, 6, tvb_get_ptr(tvb, 16,6));
      SET_ADDRESS(&whdr->src, AT_ETHER, 6, src);
      SET_ADDRESS(&whdr->dst, AT_ETHER, 6, dst);
      whdr->type = frame_type_subtype;

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = SEQCTL_FRAGMENT_NUMBER(seq_control);
      seq_number = SEQCTL_SEQUENCE_NUMBER(seq_control);

      if (check_col (pinfo->cinfo, COL_INFO))
      {
	col_append_fstr(pinfo->cinfo, COL_INFO,
          ",SN=%d", seq_number);

  	col_append_fstr(pinfo->cinfo, COL_INFO,
          ",FN=%d",frag_number);
      }

      if (tree)
	{
	  proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);

	  proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);

	  /* add items for wlan.addr filter */
	  proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	  proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);

	  proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 16, 6,
				tvb_get_ptr (tvb, 16, 6));

	  proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
			       frag_number);

	  proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
			       seq_number);
	}
      break;

    case CONTROL_FRAME:
      switch (frame_type_subtype)
	{

	case CTRL_PS_POLL:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "BSSID");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 4, 6, dst);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_RTS:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "TA");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_CTS:
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	  break;


	case CTRL_ACKNOWLEDGEMENT:
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	  break;


	case CTRL_CFP_END:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_CFP_ENDACK:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6, src);
	    }
	  break;
	/*** Begin: Control Wrapper - Dustin Johnson ***/
	case CTRL_CONTROL_WRAPPER:
	{
	  const guint8 *addr1 = NULL;
	  proto_tree *cntrl_wrap_tree;
      proto_item *cntrl_wrap_item;
	  guint32 offset = 4;

      fcs_len = 4;

	  if (tree){
	    addr1 = tvb_get_ptr (tvb, 4, 6);
		offset += 6;

		proto_tree_add_ether (hdr_tree, hf_addr_addr1, tvb, 4, 6, addr1);
	    cntrl_wrap_item = proto_tree_add_text(hdr_tree, tvb, offset, 2, "Contained Frame Control");
		cntrl_wrap_tree = proto_item_add_subtree (cntrl_wrap_item, ett_cntrl_wrapper_fc);
	    dissect_frame_control(cntrl_wrap_tree, tvb, FALSE, offset);
		offset += 2;

	    /*dissect_ht_control(hdr_tree, tvb, offset);*/
	    /* TODO: Complete this crap - Grrarr asdgadsfgadagdsfg!!!*/
	  }
	  break;
	}
	/*** End: Control Wrapper - Dustin Johnson ***/
	/*** Begin: Block Ack Request - Dustin Johnson ***/
	case CTRL_BLOCK_ACK_REQ:
	  {
	    src = tvb_get_ptr (tvb, 10, 6);
	    dst = tvb_get_ptr (tvb, 4, 6);

	    set_src_addr_cols(pinfo, src, "TA");
	    set_dst_addr_cols(pinfo, dst, "RA");

	    if (tree)
	    {
		  guint16 bar_control;
		  guint8 block_ack_type;
		  gint offset;
		  proto_item *bar_parent_item;
		  proto_tree *bar_sub_tree;

	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, dst);
		  offset = 16;

		  bar_control = tvb_get_letohs(tvb, offset);
		  block_ack_type = (bar_control & 0x0006) >> 1;
		  proto_tree_add_uint(hdr_tree, hf_block_ack_request_type, tvb, offset, 1, block_ack_type);
		  bar_parent_item = proto_tree_add_uint_format(hdr_tree, hf_block_ack_request_control, tvb,
		                    offset, 2, bar_control, "Block Ack Request Control: 0x%04X", bar_control);
		  bar_sub_tree = proto_item_add_subtree(bar_parent_item, ett_block_ack);
		  proto_tree_add_boolean(bar_sub_tree, hf_block_ack_control_ack_policy, tvb, offset, 1, bar_control);
		  proto_tree_add_boolean(bar_sub_tree, hf_block_ack_control_multi_tid, tvb, offset, 1, bar_control);
		  proto_tree_add_boolean(bar_sub_tree, hf_block_ack_control_compressed_bitmap, tvb, offset, 1, bar_control);
		  proto_tree_add_uint(bar_sub_tree, hf_block_ack_control_reserved, tvb, offset, 2, bar_control);

	      switch(block_ack_type){
		  case 0: /*Basic BlockAckReq */
		    proto_tree_add_uint(bar_sub_tree, hf_block_ack_control_basic_tid_info, tvb, offset+1, 1, bar_control);
			offset += 2;

			bar_control = tvb_get_letohs(tvb, offset);

			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_fragment, tvb, offset, 1, bar_control);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_sequence, tvb, offset, 2, bar_control);
		    break;
		  case 2: /* Compressed BlockAckReq */
		    proto_tree_add_uint(bar_sub_tree, hf_block_ack_control_compressed_tid_info, tvb, offset+1, 1, bar_control);
			offset += 2;

		    bar_control = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_fragment, tvb, offset, 1, bar_control);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_sequence, tvb, offset, 2, bar_control);
		    break;
		  case 3: /* Multi-TID BlockAckReq */
          {
		    guint8 tid_count, i;
		    proto_tree *bar_mtid_tree, *bar_mtid_sub_tree;

			tid_count = ((bar_control & 0xF000) >> 12) + 1;
            proto_tree_add_uint_format(bar_sub_tree, hf_block_ack_control_compressed_tid_info, tvb, offset+1, 1, bar_control,
			    decode_numeric_bitfield(bar_control, 0xF000, 16,"Number of TIDs Present: 0x%%X"), tid_count);
			offset += 2;

			bar_parent_item = proto_tree_add_text (hdr_tree, tvb, offset, tid_count*4, "Per TID Info");
			bar_mtid_tree = proto_item_add_subtree(bar_parent_item, ett_block_ack);
			for(i=1; i<=tid_count; i++){
			  bar_parent_item = proto_tree_add_uint(bar_mtid_tree, hf_block_ack_multi_tid_info, tvb, offset, 4, i);
			  bar_mtid_sub_tree = proto_item_add_subtree(bar_parent_item, ett_block_ack);

			  bar_control = tvb_get_letohs(tvb, offset);
			  proto_tree_add_uint(bar_mtid_sub_tree, hf_block_ack_multi_tid_reserved, tvb, offset, 2, bar_control);
			  proto_tree_add_uint(bar_mtid_sub_tree, hf_block_ack_multi_tid_value, tvb, offset+1, 1, bar_control);
			  offset += 2;

			  bar_control = tvb_get_letohs(tvb, offset);
			  proto_tree_add_uint(bar_mtid_sub_tree, hf_block_ack_request_multi_tid_ssc, tvb, offset, 2, bar_control);
			  offset += 2;
			}
		    break;
		  }
		  }

	    }
	  break;
	  }
    /*** End: Block Ack Request - Dustin Johnson ***/
	/*** Begin: Block Ack - Dustin Johnson ***/
	case CTRL_BLOCK_ACK:
	  {
	    src = tvb_get_ptr (tvb, 10, 6);
	    dst = tvb_get_ptr (tvb, 4, 6);

	    set_src_addr_cols(pinfo, src, "TA");
	    set_dst_addr_cols(pinfo, dst, "RA");

	    if (tree)
	    {
		  guint16 ba_control;
		  guint8 block_ack_type;
		  gint offset;
		  proto_item *ba_parent_item;
		  proto_tree *ba_sub_tree;

	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, dst);
		  offset = 16;

		  ba_control = tvb_get_letohs(tvb, offset);
		  block_ack_type = (ba_control & 0x0006) >> 1;
		  proto_tree_add_uint(hdr_tree, hf_block_ack_type, tvb, offset, 1, block_ack_type);
		  ba_parent_item = proto_tree_add_uint_format(hdr_tree, hf_block_ack_request_control, tvb,
		                    offset, 2, ba_control, "Block Ack Control: 0x%04X", ba_control);
		  ba_sub_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);
		  proto_tree_add_boolean(ba_sub_tree, hf_block_ack_control_ack_policy, tvb, offset, 1, ba_control);
		  proto_tree_add_boolean(ba_sub_tree, hf_block_ack_control_multi_tid, tvb, offset, 1, ba_control);
		  proto_tree_add_boolean(ba_sub_tree, hf_block_ack_control_compressed_bitmap, tvb, offset, 1, ba_control);
		  proto_tree_add_uint(ba_sub_tree, hf_block_ack_control_reserved, tvb, offset, 2, ba_control);

		  switch(block_ack_type){
		  case 0: /*Basic BlockAck */
		    proto_tree_add_uint(ba_sub_tree, hf_block_ack_control_basic_tid_info, tvb, offset+1, 1, ba_control);
			offset += 2;

			ba_control = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_fragment, tvb, offset, 1, ba_control);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_sequence, tvb, offset, 2, ba_control);
			offset += 2;

			proto_tree_add_text(hdr_tree, tvb, offset, 128, "Block Ack Bitmap");
			offset += 128;
		    break;
		  case 2: /* Compressed BlockAck */
		    proto_tree_add_uint(ba_sub_tree, hf_block_ack_control_basic_tid_info, tvb, offset+1, 1, ba_control);
			offset += 2;

			ba_control = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_fragment, tvb, offset, 1, ba_control);
			proto_tree_add_uint(hdr_tree, hf_block_ack_control_basic_sequence, tvb, offset, 2, ba_control);
			offset += 2;

			proto_tree_add_text(hdr_tree, tvb, offset, 8, "Block Ack Bitmap");
			offset += 8;
		    break;
		  case 3: /* Multi-TID BlockAck */
          {
		    guint8 tid_count, i;
		    proto_tree *ba_mtid_tree, *ba_mtid_sub_tree;

			tid_count = ((ba_control & 0xF000) >> 12) + 1;
            proto_tree_add_uint_format(ba_sub_tree, hf_block_ack_control_compressed_tid_info, tvb, offset+1, 1, ba_control,
			    decode_numeric_bitfield(ba_control, 0xF000, 16,"Number of TIDs Present: 0x%%X"), tid_count);
			offset += 2;

			ba_parent_item = proto_tree_add_text (hdr_tree, tvb, offset, tid_count*4, "Per TID Info");
			ba_mtid_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);
			for(i=1; i<=tid_count; i++){
			  ba_parent_item = proto_tree_add_uint(ba_mtid_tree, hf_block_ack_multi_tid_info, tvb, offset, 4, i);
			  ba_mtid_sub_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);

			  ba_control = tvb_get_letohs(tvb, offset);
			  proto_tree_add_uint(ba_mtid_sub_tree, hf_block_ack_multi_tid_reserved, tvb, offset, 2, ba_control);
			  proto_tree_add_uint(ba_mtid_sub_tree, hf_block_ack_multi_tid_value, tvb, offset+1, 1, ba_control);
			  offset += 2;

			  ba_control = tvb_get_letohs(tvb, offset);
			  proto_tree_add_uint(ba_mtid_sub_tree, hf_block_ack_control_basic_fragment, tvb, offset, 1, ba_control);
			  proto_tree_add_uint(ba_mtid_sub_tree, hf_block_ack_control_basic_sequence, tvb, offset, 2, ba_control);
			  offset += 2;

			  proto_tree_add_text(ba_mtid_sub_tree, tvb, offset, 8, "Block Ack Bitmap");
			  offset += 8;
			}
		    break;
		  }
		  }
	    }
	    break;
	  }
	  /*** End: Block Ack - Dustin Johnson ***/
	}
      break;

    case DATA_FRAME:
      addr_type = FCF_ADDR_SELECTOR (fcf);

      /* In order to show src/dst address we must always do the following */
      switch (addr_type)
	{

	case DATA_ADDR_T1:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);
	  bssid = tvb_get_ptr (tvb, 16, 6);
	  break;


	case DATA_ADDR_T2:
	  src = tvb_get_ptr (tvb, 16, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);
	  bssid = tvb_get_ptr (tvb, 10, 6);
	  break;


	case DATA_ADDR_T3:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 16, 6);
	  bssid = tvb_get_ptr (tvb, 4, 6);
	  break;


	case DATA_ADDR_T4:
	  src = tvb_get_ptr (tvb, 24, 6);
	  dst = tvb_get_ptr (tvb, 16, 6);
	  bssid = tvb_get_ptr (tvb, 16, 6);
	  break;
	}

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      /* for tap */

      SET_ADDRESS(&whdr->bssid, AT_ETHER, 6, bssid);
      SET_ADDRESS(&whdr->src, AT_ETHER, 6, src);
      SET_ADDRESS(&whdr->dst, AT_ETHER, 6, dst);
      whdr->type = frame_type_subtype;

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = SEQCTL_FRAGMENT_NUMBER(seq_control);
      seq_number = SEQCTL_SEQUENCE_NUMBER(seq_control);

      if (check_col (pinfo->cinfo, COL_INFO))
      {
	col_append_fstr(pinfo->cinfo, COL_INFO,
          ",SN=%d", seq_number);

  	col_append_fstr(pinfo->cinfo, COL_INFO,
          ",FN=%d",frag_number);
      }

      /* Now if we have a tree we start adding stuff */
      if (tree)
	{


	  switch (addr_type)
	    {

	    case DATA_ADDR_T1:
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 16, 6,
				    tvb_get_ptr (tvb, 16, 6));
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);
	      break;


	    case DATA_ADDR_T2:
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6,
				    tvb_get_ptr (tvb, 10, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 16, 6, src);
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, src);
	      break;


	    case DATA_ADDR_T3:
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 4, 6,
				    tvb_get_ptr (tvb, 4, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 16, 6, dst);

	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, dst);
	      break;


	    case DATA_ADDR_T4:
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6,
				    tvb_get_ptr (tvb, 4, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6,
				    tvb_get_ptr (tvb, 10, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 16, 6, dst);
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 24, 6, src);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 24, 6, src);
	      break;
	    }

	}
      break;
    }

  len = tvb_length_remaining(tvb, hdr_len);
  reported_len = tvb_reported_length_remaining(tvb, hdr_len);

  switch (fcs_len)
    {
      case 0: /* Definitely has no FCS */
        has_fcs = FALSE;
        break;

      case 4: /* Definitely has an FCS */
        has_fcs = TRUE;
        break;

      default: /* Don't know - use "wlan_check_fcs" */
        has_fcs = wlan_check_fcs;
        break;
    }
  if (has_fcs)
    {
      /*
       * Well, this packet should, in theory, have an FCS.
       * Do we have the entire packet, and does it have enough data for
       * the FCS?
       */
      if (reported_len < 4)
	{
	  /*
	   * The packet is claimed not to even have enough data for a 4-byte
	   * FCS.
	   * Pretend it doesn't have an FCS.
	   */
	  ;
        }
      else if (len < reported_len)
	{
	  /*
	   * The packet is claimed to have enough data for a 4-byte FCS, but
	   * we didn't capture all of the packet.
	   * Slice off the 4-byte FCS from the reported length, and trim the
	   * captured length so it's no more than the reported length; that
	   * will slice off what of the FCS, if any, is in the captured
	   * length.
	   */
	  reported_len -= 4;
	  if (len > reported_len)
	    len = reported_len;
	}
      else
	{
	  /*
	   * We have the entire packet, and it includes a 4-byte FCS.
	   * Slice it off, and put it into the tree.
	   */
	  len -= 4;
	  reported_len -= 4;
	  if (tree)
	    {
	      guint32 sent_fcs = tvb_get_ntohl(tvb, hdr_len + len);
	      guint32 fcs;

	      if (datapad)
		fcs = crc32_802_tvb_padded(tvb, ohdr_len, hdr_len, len);
	      else
		fcs = crc32_802_tvb(tvb, hdr_len + len);
	      if (fcs == sent_fcs) {
		      fcs_good = TRUE;
		      fcs_bad = FALSE;
	      } else {
		      fcs_good = FALSE;
		      fcs_bad = TRUE;
	      }

	      if(fcs_good)
		fcs_item = proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x [correct]", sent_fcs);
	      else
		fcs_item = proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x [incorrect, should be 0x%08x]",
			sent_fcs, fcs);

	      fcs_tree = proto_item_add_subtree(fcs_item, ett_fcs);

	      fcs_item = proto_tree_add_boolean(fcs_tree,
						hf_fcs_good, tvb,
						hdr_len + len, 2,
						fcs_good);
	      PROTO_ITEM_SET_GENERATED(fcs_item);

	      fcs_item = proto_tree_add_boolean(fcs_tree,
						hf_fcs_bad, tvb,
						hdr_len + len, 2,
						fcs_bad);
	      PROTO_ITEM_SET_GENERATED(fcs_item);
	    }
	}
    }



  /*
   * Only management and data frames have a body, so we don't have
   * anything more to do for other types of frames.
   */
  switch (FCF_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      break;

    case DATA_FRAME:
      if (tree && DATA_FRAME_IS_QOS(frame_type_subtype))
	{

	  proto_item *qos_fields;
	  proto_tree *qos_tree;

	  guint16 qosoff;
	  guint16 qos_control;
	  guint16 qos_priority;
	  guint16 qos_ack_policy;
	  guint16 qos_amsdu_present;
	  guint16 qos_eosp;
	  guint16 qos_field_content;

	  /*
	   * We calculate the offset to the QoS header data as
	   * an offset relative to the end of the header.  But
	   * when the header has been padded to align the data
	   * this must be done relative to true header size, not
	   * the padded/aligned value.  To simplify this work we
	   * stash the original header size in ohdr_len instead
	   * of recalculating it.
	   */
	  qosoff = ohdr_len - 2;
	  qos_fields = proto_tree_add_text(hdr_tree, tvb, qosoff, 2,
	      "QoS parameters");
	  qos_tree = proto_item_add_subtree (qos_fields, ett_qos_parameters);

	  qos_control = tvb_get_letohs(tvb, qosoff + 0);
	  qos_priority = QOS_PRIORITY(qos_control);
	  qos_ack_policy = QOS_ACK_POLICY(qos_control);
	  qos_amsdu_present = QOS_AMSDU_PRESENT(qos_control);
	  qos_eosp = QOS_EOSP(qos_control);
	  qos_field_content = QOS_FIELD_CONTENT( qos_control);

	  proto_tree_add_uint_format (qos_tree, hf_qos_priority, tvb,
	      qosoff, 1, qos_priority,
	      "Priority: %d (%s) (%s)",
	      qos_priority, qos_tags[qos_priority], qos_acs[qos_priority]);

	  if (flags & FLAG_FROM_DS) {
	    proto_tree_add_boolean (qos_tree, hf_qos_eosp, tvb,
	      qosoff, 1, qos_eosp);
	  }

	  proto_tree_add_uint (qos_tree, hf_qos_ack_policy, tvb, qosoff, 1,
	      qos_ack_policy);

	  if (flags & FLAG_FROM_DS) {
	    if (!DATA_FRAME_IS_NULL(frame_type_subtype)) {
		  proto_tree_add_boolean(qos_tree, hf_qos_amsdu_present, tvb,
      	  	  qosoff, 1, qos_amsdu_present);
		  is_amsdu = qos_amsdu_present;
		}
	    if (DATA_FRAME_IS_CF_POLL(frame_type_subtype)) {
	      /* txop limit */
	      proto_tree_add_uint_format (qos_tree, hf_qos_field_content, tvb,
      		  qosoff + 1, 1, qos_field_content, "TXOP Limit: %d ", qos_field_content);

	    } else {
	      /* qap ps buffer state */
	      proto_item *qos_ps_buf_state_fields;
    	      proto_tree *qos_ps_buf_state_tree;
	      guint16 buf_state;
	      guint16 buf_ac;
	      guint16 buf_load;

	      buf_state = QOS_PS_BUF_STATE(qos_field_content);
	      buf_ac = QOS_PS_BUF_AC(qos_field_content);  /*access category */
	      buf_load = QOS_PS_BUF_LOAD(qos_field_content);

	      qos_ps_buf_state_fields = proto_tree_add_text(qos_tree, tvb, qosoff + 1, 1,
		"QAP PS Buffer State: 0x%x", qos_field_content);
	      qos_ps_buf_state_tree = proto_item_add_subtree (qos_ps_buf_state_fields, ett_qos_ps_buf_state);

/*	FIXME: hf_ values not defined
	      proto_tree_add_boolean (qos_ps_buf_state_tree, hf_qos_buf_state, tvb,
    		  1, 1, buf_state);

	      proto_tree_add_uint_format (qos_ps_buf_state_tree, hf_qos_buf_ac, tvb,
		  qosoff + 1, 1, buf_ac, "Priority: %d (%s)",
		  buf_ac, wme_acs[buf_ac]);

	      proto_tree_add_uint_format (qos_ps_buf_state_tree, hf_qos_buf_load, tvb,
      		  qosoff + 1, 1, buf_load, "Buffered load: %d ", (buf_load * 4096));
*/

	    }
	  } else {
	    if (!DATA_FRAME_IS_NULL(frame_type_subtype)) {
		  proto_tree_add_boolean(qos_tree, hf_qos_amsdu_present, tvb,
      	  	  qosoff, 1, qos_amsdu_present);
		  is_amsdu = qos_amsdu_present;
		}
		if (qos_eosp) {
	      /* txop limit requested */
	      proto_tree_add_uint_format (qos_tree, hf_qos_field_content, tvb,
      	  	qosoff + 1, 1, qos_field_content, "Queue Size: %d ", (qos_field_content * 254));
	    } else {
	      /* queue size */
	      proto_tree_add_uint_format (qos_tree, hf_qos_field_content, tvb,
		    qosoff + 1, 1, qos_field_content, "TXOP Limit Requested: %d ", qos_field_content);
	    }
	  }

	} /* end of qos control field */

#ifdef	HAVE_AIRPDCAP
        /*	Davide Schiera (2006-11-21): process handshake packet with AirPDcap		*/
        /*		the processing will take care of 4-way handshake sessions for WPA		*/
        /*		and WPA2 decryption																	*/
        if (enable_decryption && !pinfo->fd->flags.visited) {
          const guint8 *enc_data = tvb_get_ptr(tvb, 0, hdr_len+reported_len);
          AirPDcapPacketProcess(&airpdcap_ctx, enc_data, hdr_len+reported_len, NULL, 0, NULL, FALSE, FALSE, TRUE, FALSE);
        }
        /* Davide Schiera --------------------------------------------------------	*/
#endif

      /*
       * No-data frames don't have a body.
       */
      if (DATA_FRAME_IS_NULL(frame_type_subtype))
	return;

      break;

    case CONTROL_FRAME:
      return;

    default:
      return;
    }

  if (IS_PROTECTED(FCF_FLAGS(fcf)) && wlan_ignore_wep != WLAN_IGNORE_WEP_WO_IV) {
    /*
     * It's a WEP or WPA encrypted frame; dissect the protections parameters
     * and decrypt the data, if we have a matching key. Otherwise display it as data.
     */

    gboolean can_decrypt = FALSE;
    proto_tree *wep_tree = NULL;
    guint32 iv;
    guint8 key, keybyte;

    /* Davide Schiera (2006-11-27): define algorithms constants and macros	*/
#ifdef	HAVE_AIRPDCAP
#define	PROTECTION_ALG_TKIP	AIRPDCAP_KEY_TYPE_TKIP
#define	PROTECTION_ALG_CCMP	AIRPDCAP_KEY_TYPE_CCMP
#define	PROTECTION_ALG_WEP	AIRPDCAP_KEY_TYPE_WEP
#define	PROTECTION_ALG_RSNA	PROTECTION_ALG_CCMP | PROTECTION_ALG_TKIP
#else
#define	PROTECTION_ALG_WEP	0
#define	PROTECTION_ALG_TKIP	1
#define	PROTECTION_ALG_CCMP	2
#define	PROTECTION_ALG_RSNA	PROTECTION_ALG_CCMP | PROTECTION_ALG_TKIP
#endif
    guint8 algorithm=-1;
    /* Davide Schiera (2006-11-27): added macros to check the algorithm		*/
    /*		used could be TKIP or CCMP														*/
#define	IS_TKIP(tvb, hdr_len)	(tvb_get_guint8(tvb, hdr_len + 1) & 0x20)
#define	IS_CCMP(tvb, hdr_len)	(tvb_get_guint8(tvb, hdr_len + 2) == 0)
    /* Davide Schiera -----------------------------------------------------	*/

#ifdef	HAVE_AIRPDCAP
    /* Davide Schiera (2006-11-21): recorded original lengths to pass them	*/
    /*		to the packets process function												*/
    guint32 sec_header=0;
    guint32 sec_trailer=0;

    next_tvb = try_decrypt(tvb, hdr_len, reported_len, &algorithm, &sec_header, &sec_trailer);
#endif
    /* Davide Schiera -----------------------------------------------------	*/

    keybyte = tvb_get_guint8(tvb, hdr_len + 3);
    key = KEY_OCTET_WEP_KEY(keybyte);
    if ((keybyte & KEY_EXTIV) && (len >= EXTIV_LEN)) {
      /* Extended IV; this frame is likely encrypted with TKIP or CCMP */


      if (tree) {
	proto_item *extiv_fields;

#ifdef	HAVE_AIRPDCAP
        /* Davide Schiera (2006-11-27): differentiated CCMP and TKIP if	*/
        /*		it's possible																*/
        if (algorithm==PROTECTION_ALG_TKIP)
                extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                "TKIP parameters");
        else if (algorithm==PROTECTION_ALG_CCMP)
                extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                "CCMP parameters");
        else {
                /* Davide Schiera --------------------------------------------	*/
#endif
          /* Davide Schiera (2006-11-27): differentiated CCMP and TKIP if*/
          /*		it's possible															*/
          if (IS_TKIP(tvb, hdr_len)) {
                  algorithm=PROTECTION_ALG_TKIP;
                  extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                          "TKIP parameters");
          } else if (IS_CCMP(tvb, hdr_len)) {
                  algorithm=PROTECTION_ALG_CCMP;
                  extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                          "CCMP parameters");
          } else
            extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
					   "TKIP/CCMP parameters");
#ifdef	HAVE_AIRPDCAP
        }
#endif

	wep_tree = proto_item_add_subtree (extiv_fields, ett_wep_parameters);

        if (algorithm==PROTECTION_ALG_TKIP) {
	  g_snprintf(out_buff, SHORT_STR, "0x%08X%02X%02X",
		   tvb_get_letohl(tvb, hdr_len + 4),
		   tvb_get_guint8(tvb, hdr_len),
		   tvb_get_guint8(tvb, hdr_len + 2));
	  proto_tree_add_string(wep_tree, hf_tkip_extiv, tvb, hdr_len,
				EXTIV_LEN, out_buff);
				} else if (algorithm==PROTECTION_ALG_CCMP) {
	  g_snprintf(out_buff, SHORT_STR, "0x%08X%02X%02X",
		   tvb_get_letohl(tvb, hdr_len + 4),
		   tvb_get_guint8(tvb, hdr_len + 1),
		   tvb_get_guint8(tvb, hdr_len));
	  proto_tree_add_string(wep_tree, hf_ccmp_extiv, tvb, hdr_len,
				EXTIV_LEN, out_buff);
	}

        proto_tree_add_uint(wep_tree, hf_wep_key, tvb, hdr_len + 3, 1, key);
      }

      /* Subtract out the length of the IV. */
      len -= EXTIV_LEN;
      reported_len -= EXTIV_LEN;
      ivlen = EXTIV_LEN;
      /* It is unknown whether this is TKIP or CCMP, so let's not even try to
       * parse TKIP Michael MIC+ICV or CCMP MIC. */

#ifdef	HAVE_AIRPDCAP
      /*	Davide Schiera (2006-11-21): enable TKIP and CCMP decryption			*/
      /*		checking for the trailer														*/
      if (next_tvb!=NULL) {
        if (reported_len < (gint) sec_trailer) {
          /* There is no space for a trailer, ignore it and don't decrypt	*/
          ;
        } else if (len < reported_len) {
          /* There is space for a trailer, but we haven't capture all the	*/
          /* packet. Slice off the trailer, but don't try to decrypt			*/
          reported_len -= sec_trailer;
          if (len > reported_len)
                  len = reported_len;
        } else {
          /* Ok, we have a trailer and the whole packet. Decrypt it!			*/
          /* TODO: At the moment we won't add the trailer to the tree,		*/
          /* so don't remove the trailer from the packet							*/
          len -= sec_trailer;
          reported_len -= sec_trailer;
          can_decrypt = TRUE;
        }
      }
      /* Davide Schiera --------------------------------------------------	*/
#endif
    } else {
      /* No Ext. IV - WEP packet */
      /*
       * XXX - pass the IV and key to "try_decrypt_wep()", and have it pass
       * them to "wep_decrypt()", rather than having "wep_decrypt()" extract
       * them itself.
       *
       * Also, just pass the data *following* the WEP parameters as the
       * buffer to decrypt.
       */
      iv = tvb_get_ntoh24(tvb, hdr_len);
      if (tree) {
	proto_item *wep_fields;

	wep_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 4,
					 "WEP parameters");

	wep_tree = proto_item_add_subtree (wep_fields, ett_wep_parameters);
	proto_tree_add_uint (wep_tree, hf_wep_iv, tvb, hdr_len, 3, iv);
	tvb_memcpy(tvb, iv_buff, hdr_len, 3);
	is_iv_bad = weak_iv(iv_buff);
	if (is_iv_bad != -1) {
		proto_tree_add_boolean_format (wep_tree, hf_wep_iv_weak,
					       tvb, 0, 0, TRUE,
					       "Weak IV for key byte %d",
					       is_iv_bad);
	}
      }
      if (tree)
        proto_tree_add_uint (wep_tree, hf_wep_key, tvb, hdr_len + 3, 1, key);

      /* Subtract out the length of the IV. */
      len -= 4;
      reported_len -= 4;
      ivlen = 4;

      /* Davide Schiera (2006-11-27): Even if the decryption was not */
      /* successful, set the algorithm                               */
      algorithm=PROTECTION_ALG_WEP;

      /*
       * Well, this packet should, in theory, have an ICV.
       * Do we have the entire packet, and does it have enough data for
       * the ICV?
       */
      if (reported_len < 4) {
        /*
	 * The packet is claimed not to even have enough data for a
	 * 4-byte ICV.
	 * Pretend it doesn't have an ICV.
	 */
        ;
      } else if (len < reported_len) {
        /*
	 * The packet is claimed to have enough data for a 4-byte ICV,
	 * but we didn't capture all of the packet.
	 * Slice off the 4-byte ICV from the reported length, and trim
	 * the captured length so it's no more than the reported length;
	 * that will slice off what of the ICV, if any, is in the
	 * captured length.
	 *
	 */
        reported_len -= 4;
        if (len > reported_len)
	  len = reported_len;
      } else {
        /*
	 * We have the entire packet, and it includes a 4-byte ICV.
	 * Slice it off, and put it into the tree.
	 *
	 * We only support decrypting if we have the the ICV.
	 *
	 * XXX - the ICV is encrypted; we're putting the encrypted
	 * value, not the decrypted value, into the tree.
	 */
        len -= 4;
	reported_len -= 4;
	can_decrypt = TRUE;
      }
    }

#ifndef	HAVE_AIRPDCAP
    if (can_decrypt)
      next_tvb = try_decrypt_wep(tvb, hdr_len, reported_len + 8);
#else
    /* Davide Schiera (2006-11-26): decrypted before parsing header and		*/
    /*		protection header																	*/
#endif
    if (!can_decrypt || next_tvb == NULL) {
      /*
       * WEP decode impossible or failed, treat payload as raw data
       * and don't attempt fragment reassembly or further dissection.
       */
      next_tvb = tvb_new_subset(tvb, hdr_len + ivlen, len, reported_len);

      if (tree) {
        /* Davide Schiera (2006-11-21): added WEP or WPA separation			*/
        if (algorithm==PROTECTION_ALG_WEP) {
          if (can_decrypt)
            proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb,
				    hdr_len + ivlen + len, 4,
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len),
				    "WEP ICV: 0x%08x (not verified)",
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len));
        } else if (algorithm==PROTECTION_ALG_CCMP) {
        } else if (algorithm==PROTECTION_ALG_TKIP) {
        }
      }
      /* Davide Schiera (2006-11-21) ----------------------------------	*/

      if (pinfo->ethertype != ETHERTYPE_CENTRINO_PROMISC && wlan_ignore_wep == WLAN_IGNORE_WEP_NO) {
	/* Some wireless drivers (such as Centrino) WEP payload already decrypted */
	call_dissector(data_handle, next_tvb, pinfo, tree);
	goto end_of_wlan;
      }
    } else {
      /* Davide Schiera (2006-11-21): added WEP or WPA separation				*/
      if (algorithm==PROTECTION_ALG_WEP) {
        if (tree)
          proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb,
				    hdr_len + ivlen + len, 4,
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len),
				    "WEP ICV: 0x%08x (correct)",
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len));

        add_new_data_source(pinfo, next_tvb, "Decrypted WEP data");
      } else if (algorithm==PROTECTION_ALG_CCMP) {
        add_new_data_source(pinfo, next_tvb, "Decrypted CCMP data");
      } else if (algorithm==PROTECTION_ALG_TKIP) {
        add_new_data_source(pinfo, next_tvb, "Decrypted TKIP data");
      }
      /* Davide Schiera (2006-11-21) -------------------------------------	*/
      /* Davide Schiera (2006-11-27): undefine macros and definitions	*/
#undef	IS_TKIP
#undef	IS_CCMP
#undef	PROTECTION_ALG_CCMP
#undef	PROTECTION_ALG_TKIP
#undef	PROTECTION_ALG_WEP
      /* Davide Schiera --------------------------------------------------	*/
    }

    /*
     * WEP decryption successful!
     *
     * Use the tvbuff we got back from the decryption; the data starts at
     * the beginning.  The lengths are already correct for the decoded WEP
     * payload.
     */
    hdr_len = 0;

  } else {
    /*
     * Not a WEP-encrypted frame; just use the data from the tvbuff
     * handed to us.
     *
     * The payload starts at "hdr_len" (i.e., just past the 802.11
     * MAC header), the length of data in the tvbuff following the
     * 802.11 header is "len", and the length of data in the packet
     * following the 802.11 header is "reported_len".
     */
    next_tvb = tvb;
  }

  /*
   * Do defragmentation if "wlan_defragment" is true, and we have more
   * fragments or this isn't the first fragment.
   *
   * We have to do some special handling to catch frames that
   * have the "More Fragments" indicator not set but that
   * don't show up as reassembled and don't have any other
   * fragments present.  Some networking interfaces appear
   * to do reassembly even when you're capturing raw packets
   * *and* show the reassembled packet without the "More
   * Fragments" indicator set *but* with a non-zero fragment
   * number.
   *
   * "fragment_add_seq_802_11()" handles that; we want to call it
   * even if we have a short frame, so that it does those checks - if
   * the frame is short, it doesn't do reassembly on it.
   *
   * (This could get some false positives if we really *did* only
   * capture the last fragment of a fragmented packet, but that's
   * life.)
   */
  save_fragmented = pinfo->fragmented;
  if (wlan_defragment && (more_frags || frag_number != 0)) {
    fragment_data *fd_head;

    /*
     * If we've already seen this frame, look it up in the
     * table of reassembled packets, otherwise add it to
     * whatever reassembly is in progress, if any, and see
     * if it's done.
     */
    fd_head = fragment_add_seq_802_11(next_tvb, hdr_len, pinfo, seq_number,
				     wlan_fragment_table,
				     wlan_reassembled_table,
				     frag_number,
				     reported_len,
				     more_frags);
    next_tvb = process_reassembled_data(tvb, hdr_len, pinfo,
					"Reassembled 802.11", fd_head,
					&frag_items, NULL, hdr_tree);
  } else {
    /*
     * If this is the first fragment, dissect its contents, otherwise
     * just show it as a fragment.
     */
    if (frag_number != 0) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset (next_tvb, hdr_len, len, reported_len);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (more_frags)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as an incomplete fragment. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "Fragmented IEEE 802.11 frame");
    next_tvb = tvb_new_subset (tvb, hdr_len, len, reported_len);
    call_dissector(data_handle, next_tvb, pinfo, tree);
    pinfo->fragmented = save_fragmented;
    goto end_of_wlan;
  }

  switch (FCF_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      dissect_ieee80211_mgt (fcf, next_tvb, pinfo, tree);
      break;

    case DATA_FRAME:
	  if (is_amsdu && tvb_reported_length_remaining(next_tvb, 0) > 4){
	    tvbuff_t *volatile msdu_tvb = NULL;
		guint32 msdu_offset = 0;
		guint16 i = 1;
		const guint8 *src = NULL;
		const guint8 *dst = NULL;
		guint16 msdu_length;
		proto_item *parent_item;
		proto_tree *mpdu_tree;
		proto_tree *msdu_tree;

        parent_item = proto_tree_add_protocol_format(tree, proto_aggregate, next_tvb, 0,
		                    tvb_reported_length_remaining(next_tvb, 0), "IEEE 802.11 Agregate MSDU");
		mpdu_tree = proto_item_add_subtree(parent_item, ett_ht_info_delimiter1_tree);

		do{
		  dst = tvb_get_ptr (next_tvb, msdu_offset, 6);
		  src = tvb_get_ptr (next_tvb, msdu_offset+6, 6);
		  msdu_length = tvb_get_letohs (next_tvb, msdu_offset+12);

		  parent_item = proto_tree_add_uint_format(mpdu_tree, amsdu_msdu_header_text, next_tvb,
		                    msdu_offset, roundup2(msdu_offset+14+msdu_length, 4),
							i, "MAC Service Data Unit (MSDU) %X", i);
		  i++;
		  msdu_tree = proto_item_add_subtree(parent_item, ett_ht_info_delimiter1_tree);

		  proto_tree_add_ether(msdu_tree, hf_addr_da, next_tvb, msdu_offset, 6, dst);
		  proto_tree_add_ether(msdu_tree, hf_addr_sa, next_tvb, msdu_offset+6, 6, src);
		  proto_tree_add_uint_format(msdu_tree, mcsset_highest_data_rate, next_tvb, msdu_offset+12, 2,
              msdu_length, "MSDU length: 0x%04X", msdu_length);

		  msdu_offset += 14;
		  msdu_tvb = tvb_new_subset(next_tvb, msdu_offset, msdu_length, -1);
		  call_dissector(llc_handle, msdu_tvb, pinfo, msdu_tree);
		  msdu_offset = roundup2(msdu_offset+msdu_length, 4);
		}while (tvb_reported_length_remaining(next_tvb, msdu_offset) > 14);

		break;
	  }
      /* I guess some bridges take Netware Ethernet_802_3 frames,
         which are 802.3 frames (with a length field rather than
         a type field, but with no 802.2 header in the payload),
         and just stick the payload into an 802.11 frame.  I've seen
         captures that show frames of that sort.

         We also handle some odd form of encapsulation in which a
         complete Ethernet frame is encapsulated within an 802.11
         data frame, with no 802.2 header.  This has been seen
         from some hardware.

         So, if the packet doesn't start with 0xaa 0xaa:

           we first use the same scheme that linux-wlan-ng does to detect
           those encapsulated Ethernet frames, namely looking to see whether
           the frame either starts with 6 octets that match the destination
           address from the 802.11 header or has 6 octets that match the
           source address from the 802.11 header following the first 6 octets,
           and, if so, treat it as an encapsulated Ethernet frame;

           otherwise, we use the same scheme that we use in the Ethernet
           dissector to recognize Netware 802.3 frames, namely checking
           whether the packet starts with 0xff 0xff and, if so, treat it
           as an encapsulated IPX frame. */
      encap_type = ENCAP_802_2;
      TRY {
      	octet1 = tvb_get_guint8(next_tvb, 0);
      	octet2 = tvb_get_guint8(next_tvb, 1);
        if (octet1 != 0xaa || octet2 != 0xaa) {
          src = tvb_get_ptr (next_tvb, 6, 6);
          dst = tvb_get_ptr (next_tvb, 0, 6);
          if (memcmp(src, pinfo->dl_src.data, 6) == 0 ||
              memcmp(dst, pinfo->dl_dst.data, 6) == 0)
            encap_type = ENCAP_ETHERNET;
          else if (octet1 == 0xff && octet2 == 0xff)
            encap_type = ENCAP_IPX;
        }
      }
      CATCH2(BoundsError, ReportedBoundsError) {
	    ; /* do nothing */

      }
      ENDTRY;

      switch (encap_type) {

      case ENCAP_802_2:
        call_dissector(llc_handle, next_tvb, pinfo, tree);
        break;

      case ENCAP_ETHERNET:
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
        break;

      case ENCAP_IPX:
        call_dissector(ipx_handle, next_tvb, pinfo, tree);
        break;
      }
      break;
    }
  pinfo->fragmented = save_fragmented;

  end_of_wlan:
  tap_queue_packet(wlan_tap, pinfo, whdr);
}

/*
 * Dissect 802.11 with a variable-length link-layer header.
 */
static void
dissect_ieee80211 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, FALSE,
      pinfo->pseudo_header->ieee_802_11.fcs_len, FALSE, FALSE);
}

/*
 * Dissect 802.11 with a variable-length link-layer header and data padding.
 */
static void
dissect_ieee80211_datapad (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, FALSE,
      pinfo->pseudo_header->ieee_802_11.fcs_len, FALSE, TRUE);
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static void
dissect_ieee80211_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, TRUE,
     pinfo->pseudo_header->ieee_802_11.fcs_len, FALSE, FALSE);
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a byte-swapped
 * control field (some hardware sends out LWAPP-encapsulated 802.11
 * packets with the control field byte swapped).
 */
static void
dissect_ieee80211_bsfc (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, FALSE, 0, TRUE, FALSE);
}

/*
 * Dissect 802.11 with a fixed-length link-layer header (padded to the
 * maximum length).
 */
static void
dissect_ieee80211_fixed (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, TRUE, FALSE, 0, FALSE, FALSE);
}

static void
wlan_defragment_init(void)
{
  fragment_table_init(&wlan_fragment_table);
  reassembled_table_init(&wlan_reassembled_table);
}

void
proto_register_ieee80211 (void)
{
  int i;
  GString *key_name, *key_title, *key_desc;

  static const value_string frame_type[] = {
    {MGT_FRAME,     "Management frame"},
    {CONTROL_FRAME, "Control frame"},
    {DATA_FRAME,    "Data frame"},
    {0,             NULL}
  };

  static const value_string tofrom_ds[] = {
    {0,                       "Not leaving DS or network is operating "
      "in AD-HOC mode (To DS: 0 From DS: 0)"},
    {FLAG_TO_DS,              "Frame from STA to DS via an AP (To DS: 1 "
      "From DS: 0)"},
    {FLAG_FROM_DS,            "Frame from DS to a STA via AP(To DS: 0 "
      "From DS: 1)"},
    {FLAG_TO_DS|FLAG_FROM_DS, "Frame part of WDS from one AP to another "
      "AP (To DS: 1 From DS: 1)"},
    {0, NULL}
  };

  static const true_false_string tods_flag = {
    "Frame is entering DS",
    "Frame is not entering DS"
  };

  static const true_false_string fromds_flag = {
    "Frame is exiting DS",
    "Frame is not exiting DS"
  };

  static const true_false_string more_frags = {
    "More fragments follow",
    "This is the last fragment"
  };

  static const true_false_string retry_flags = {
    "Frame is being retransmitted",
    "Frame is not being retransmitted"
  };

  static const true_false_string pm_flags = {
    "STA will go to sleep",
    "STA will stay up"
  };

  static const true_false_string md_flags = {
    "Data is buffered for STA at AP",
    "No data buffered"
  };

  static const true_false_string protected_flags = {
    "Data is protected",
    "Data is not protected"
  };

  static const true_false_string order_flags = {
    "Strictly ordered",
    "Not strictly ordered"
  };

  static const true_false_string cf_ess_flags = {
    "Transmitter is an AP",
    "Transmitter is a STA"
  };


  static const true_false_string cf_privacy_flags = {
    "AP/STA can support WEP",
    "AP/STA cannot support WEP"
  };

  static const true_false_string cf_preamble_flags = {
    "Short preamble allowed",
    "Short preamble not allowed"
  };

  static const true_false_string cf_pbcc_flags = {
    "PBCC modulation allowed",
    "PBCC modulation not allowed"
  };

  static const true_false_string cf_agility_flags = {
    "Channel agility in use",
    "Channel agility not in use"
  };

  static const true_false_string short_slot_time_flags = {
    "Short slot time in use",
    "Short slot time not in use"
  };

  static const true_false_string dsss_ofdm_flags = {
    "DSSS-OFDM modulation allowed",
    "DSSS-OFDM modulation not allowed"
  };

  static const true_false_string cf_spec_man_flags = {
    "dot11SpectrumManagementRequired TRUE",
    "dot11SpectrumManagementRequired FALSE",
  };

  static const true_false_string cf_apsd_flags = {
    "apsd implemented",
    "apsd not implemented",
  };

  static const true_false_string cf_del_blk_ack_flags = {
    "delayed block ack implemented",
    "delayed block ack not implented",
  };

  static const true_false_string cf_imm_blk_ack_flags = {
    "immediate block ack implemented",
    "immediate block ack not implented",
  };
  static const true_false_string cf_ibss_flags = {
    "Transmitter belongs to an IBSS",
    "Transmitter belongs to a BSS"
  };

  static const true_false_string eosp_flag = {
    "End of service period",
    "Service period"
  };

  static const true_false_string hf_qos_amsdu_present_flag = {
    "A-MSDU",
    "MSDU"
  };

  static const value_string sta_cf_pollable[] = {
    {0x00, "Station is not CF-Pollable"},
    {0x02, "Station is CF-Pollable, "
     "not requesting to be placed on the  CF-polling list"},
    {0x01, "Station is CF-Pollable, "
     "requesting to be placed on the CF-polling list"},
    {0x03, "Station is CF-Pollable, requesting never to be polled"},
    {0x0200, "QSTA requesting association in QBSS"},
    {0, NULL}
  };

  static const value_string ap_cf_pollable[] = {
    {0x00, "No point coordinator at AP"},
    {0x02, "Point coordinator at AP for delivery only (no polling)"},
    {0x01, "Point coordinator at AP for delivery and polling"},
    {0x03, "Reserved"},
    {0x0200, "QAP (HC) does not use CFP for delivery of unicast data type frames"},
    {0x0202, "QAP (HC) uses CFP for delivery, but does not send CF-Polls to non-QoS STAs"},
    {0x0201, "QAP (HC) uses CFP for delivery, and sends CF-Polls to non-QoS STAs"},
    {0x0203, "Reserved"},
    {0, NULL}
  };


  static const value_string auth_alg[] = {
    {0x00, "Open System"},
    {0x01, "Shared key"},
    {0x80, "Network EAP"},	/* Cisco proprietary? */
    {0, NULL}
  };

  static const value_string reason_codes[] = {
    {0x00, "Reserved"},
    {0x01, "Unspecified reason"},
    {0x02, "Previous authentication no longer valid"},
    {0x03, "Deauthenticated because sending STA is leaving (has left) "
     "IBSS or ESS"},
    {0x04, "Disassociated due to inactivity"},
    {0x05, "Disassociated because AP is unable to handle all currently "
     "associated stations"},
    {0x06, "Class 2 frame received from nonauthenticated station"},
    {0x07, "Class 3 frame received from nonassociated station"},
    {0x08, "Disassociated because sending STA is leaving (has left) BSS"},
    {0x09, "Station requesting (re)association is not authenticated with "
      "responding station"},
    {0x0A, "Disassociated because the information in the Power Capability "
      "element is unacceptable"},
    {0x0B, "Disassociated because the information in the Supported"
      "Channels element is unacceptable"},
    {0x0D, "Invalid Information Element"},
    {0x0E, "Michael MIC failure"},
    {0x0F, "4-Way Handshake timeout"},
    {0x10, "Group key update timeout"},
    {0x11, "Information element in 4-Way Handshake different from "
     "(Re)Association Request/Probe Response/Beacon"},
    {0x12, "Group Cipher is not valid"},
    {0x13, "Pairwise Cipher is not valid"},
    {0x14, "AKMP is not valid"},
    {0x15, "Unsupported RSN IE version"},
    {0x16, "Invalid RSN IE Capabilities"},
    {0x17, "IEEE 802.1X Authentication failed"},
    {0x18, "Cipher suite is rejected per security policy"},
    {0x20, "Disassociated for unspecified, QoS-related reason"},
    {0x21, "Disassociated because QAP lacks sufficient bandwidth for this QSTA"},
    {0x22, "Disassociated because of excessive number of frames that need to be "
      "acknowledged, but are not acknowledged for AP transmissions and/or poor "
	"channel conditions"},
    {0x23, "Disassociated because QSTA is transmitting outside the limits of its TXOPs"},
    {0x24, "Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)"},
    {0x25, "Requested from peer QSTA as it does not want to use the mechanism"},
    {0x26, "Requested from peer QSTA as the QSTA received frames using the mechanism "
      "for which a set up is required"},
    {0x27, "Requested from peer QSTA due to time out"},
    {0x2D, "Peer QSTA does not support the requested cipher suite"},
    {0x00, NULL}
  };


  static const value_string status_codes[] = {
    {0x00, "Successful"},
    {0x01, "Unspecified failure"},
    {0x0A, "Cannot support all requested capabilities in the "
     "Capability information field"},
    {0x0B, "Reassociation denied due to inability to confirm that "
     "association exists"},
    {0x0C, "Association denied due to reason outside the scope of this "
     "standard"},

    {0x0D, "Responding station does not support the specified authentication "
     "algorithm"},
    {0x0E, "Received an Authentication frame with authentication sequence "
     "transaction sequence number out of expected sequence"},
    {0x0F, "Authentication rejected because of challenge failure"},
    {0x10, "Authentication rejected due to timeout waiting for next "
     "frame in sequence"},
    {0x11, "Association denied because AP is unable to handle additional "
     "associated stations"},
    {0x12, "Association denied due to requesting station not supporting all "
     "of the datarates in the BSSBasicServiceSet Parameter"},
    {0x13, "Association denied due to requesting station not supporting "
     "short preamble operation"},
    {0x14, "Association denied due to requesting station not supporting "
     "PBCC encoding"},
    {0x15, "Association denied due to requesting station not supporting "
     "channel agility"},
    {0x16, "Association request rejected because Spectrum Management"
      "capability is required"},
    {0x17, "Association request rejected because the information in the"
      "Power Capability element is unacceptable"},
    {0x18, "Association request rejected because the information in the"
      "Supported Channels element is unacceptable"},
    {0x19, "Association denied due to requesting station not supporting "
     "short slot operation"},
    {0x1A, "Association denied due to requesting station not supporting "
     "DSSS-OFDM operation"},
    {0x20, "Unspecified, QoS-related failure"},
    {0x21, "Association denied due to QAP having insufficient bandwidth "
      "to handle another QSTA"},
    {0x22, "Association denied due to excessive frame loss rates and/or "
      "poor conditions on current operating channel"},
    {0x23, "Association (with QBSS) denied due to requesting station not "
      "supporting the QoS facility"},
    {0x24, "Association denied due to requesting station not supporting "
      "Block Ack"},
    {0x25, "The request has been declined."},
    {0x26, "The request has not been successful as one or more parameters "
      "have invalid values."},
    {0x27, "The TS has not been created because the request cannot be honored. "
      "However, a suggested TSPEC is provided so that the initiating QSTA may "
	"attempt to set another TS with the suggested changes to the TSPEC."},
    {0x28, "Invalid Information Element"},
    {0x29, "Group Cipher is not valid"},
    {0x2A, "Pairwise Cipher is not valid"},
    {0x2B, "AKMP is not valid"},
    {0x2C, "Unsupported RSN IE version"},
    {0x2D, "Invalid RSN IE Capabilities"},
    {0x2E, "Cipher suite is rejected per security policy"},
    {0x2F, "The TS has not been created. However, the HC may be capable of "
      "creating a TS, in response to a request, after the time indicated in the TS Delay element."},
    {0x30, "Direct Link is not allowed in the BSS by policy"},
    {0x31, "Destination STA is not present within this QBSS."},
    {0x32, "The Destination STA is not a QSTA."},
    {0x00, NULL}
  };

  static const value_string category_codes[] = {
    {CAT_SPECTRUM_MGMT, "Spectrum Management"},
    {CAT_QOS, "QoS"},
    {CAT_DLS, "DLS"},
    {CAT_BLOCK_ACK, "Block Ack"},
    {CAT_MGMT_NOTIFICATION, "Management notification frame"},
    {0, NULL}
  };

  static const value_string action_codes[] ={
    {SM_ACTION_MEASUREMENT_REQUEST, "Measurement Request"},
    {SM_ACTION_MEASUREMENT_REPORT, "Measurement Report"},
    {SM_ACTION_TPC_REQUEST, "TPC Request"},
    {SM_ACTION_TPC_REPORT, "TPC Report"},
    {SM_ACTION_CHAN_SWITCH_ANNC, "Channel Switch Announcement"},
    {0, NULL}
  };

  static const value_string wme_action_codes[] = {
    {0x00, "Setup request"},
    {0x01, "Setup response"},
    {0x02, "Teardown"},
    {0x00, NULL}
  };

  static const value_string wme_status_codes[] = {
    {0x00, "Admission accepted"},
    {0x01, "Invalid parameters"},
    {0x03, "Refused"},
    {0x00, NULL}
  };

  static const value_string ack_policy[] = {
    {0x00, "Normal Ack"},
    {0x01, "No Ack"},
    {0x02, "No explicit acknowledgment"},
    {0x03, "Block Ack"},
    {0x00, NULL}
  };

  static const value_string qos_action_codes[] = {
    {SM_ACTION_ADDTS_REQUEST, "ADDTS Request"},
    {SM_ACTION_ADDTS_RESPONSE, "ADDTS Response"},
    {SM_ACTION_DELTS, "DELTS"},
    {SM_ACTION_QOS_SCHEDULE, "Schedule"},
    {0, NULL}
  };

  static const value_string dls_action_codes[] = {
    {SM_ACTION_DLS_REQUEST, "DLS Request"},
    {SM_ACTION_DLS_RESPONSE, "DLS Response"},
    {SM_ACTION_DLS_TEARDOWN, "DLS Teardown"},
    {0, NULL}
  };

  static const value_string tsinfo_type[] = {
    {0x0, "Aperiodic or unspecified Traffic"},
    {0x1, "Periodic Traffic"},
    {0, NULL}
  };

  static const value_string tsinfo_direction[] = {
    {0x00, "Uplink"},
    {0x01, "Downlink"},
    {0x02, "Direct link"},
    {0x03, "Bidirectional link"},
    {0, NULL}
  };

  static const value_string tsinfo_access[] = {
    {0x00, "Reserved"},
    {0x01, "EDCA"},
    {0x02, "HCCA"},
    {0x03, "HEMM"},
    {0, NULL}
  };

  static const value_string qos_up[] = {
    {0x00, "Best Effort"},
    {0x01, "Background"},
    {0x02, "Spare"},
    {0x03, "Excellent Effort"},
    {0x04, "Controlled Load"},
    {0x05, "Video"},
    {0x06, "Voice"},
    {0x07, "Network Control"},
    {0, NULL}
  };

  static const value_string classifier_type[] = {
    {0x00, "Ethernet parameters"},
    {0x01, "TCP/UDP IP parameters"},
    {0x02, "IEEE 802.1D/Q parameters"},
    {0, NULL}
  };

  static const value_string tclas_process[] = {
    {0x00, "Incoming MSDU's higher layer parameters have to match to the parameters in all associated TCLAS elements."},
    {0x01, "Incoming MSDU's higher layer parameters have to match to at least one of the associated TCLAS elements."},
    {0x02, "Incoming MSDU's that do not belong to any other TS are classified to the TS for which this TCLAS Processing element is used. In this case, there will not be any associated TCLAS elements."},
    {0, NULL}
  };

  /*** Begin: Block Ack Request  - Dustin Johnson***/
  static const value_string hf_block_ack_request_type_flags[] = {
    {0x00, "Basic Block Ack Request"},
    {0x01, "Reserved"},
    {0x02, "Compressed Block Ack Request"},
    {0x03, "Multi-TID Block Ack Request"},
    {0x00, NULL}
  };
  /*** End: Block Ack Request  - Dustin Johnson***/

  /*** Begin: Block Ack Request  - Dustin Johnson***/
  static const value_string hf_block_ack_type_flags[] = {
    {0x00, "Basic Block Ack"},
    {0x01, "Reserved"},
    {0x02, "Compressed Block"},
    {0x03, "Multi-TID Block"},
    {0x00, NULL}
  };
  /*** End: Block Ack - Dustin Johnson***/

  static hf_register_info hf[] = {
    {&hf_data_rate,
     {"Data Rate", "wlan.data_rate", FT_UINT8, BASE_DEC, NULL, 0,
      "Data rate (.5 Mb/s units)", HFILL }},

    {&hf_channel,
     {"Channel", "wlan.channel", FT_UINT8, BASE_DEC, NULL, 0,
      "Radio channel", HFILL }},

    {&hf_signal_strength,
     {"Signal Strength", "wlan.signal_strength", FT_UINT8, BASE_DEC, NULL, 0,
      "Signal strength (percentage)", HFILL }},

    {&hf_fc_field,
     {"Frame Control Field", "wlan.fc", FT_UINT16, BASE_HEX, NULL, 0,
      "MAC Frame control", HFILL }},

    {&hf_fc_proto_version,
     {"Version", "wlan.fc.version", FT_UINT8, BASE_DEC, NULL, 0,
      "MAC Protocol version", HFILL }},	/* 0 */

    {&hf_fc_frame_type,
     {"Type", "wlan.fc.type", FT_UINT8, BASE_DEC, VALS(frame_type), 0,
      "Frame type", HFILL }},

    {&hf_fc_frame_subtype,
     {"Subtype", "wlan.fc.subtype", FT_UINT8, BASE_DEC, NULL, 0,
      "Frame subtype", HFILL }},	/* 2 */

    {&hf_fc_frame_type_subtype,
     {"Type/Subtype", "wlan.fc.type_subtype", FT_UINT8, BASE_HEX, VALS(frame_type_subtype_vals), 0,
      "Type and subtype combined", HFILL }},

    {&hf_fc_flags,
     {"Protocol Flags", "wlan.flags", FT_UINT8, BASE_HEX, NULL, 0,
      "Protocol flags", HFILL }},

    {&hf_fc_data_ds,
     {"DS status", "wlan.fc.ds", FT_UINT8, BASE_HEX, VALS (&tofrom_ds), 0,
      "Data-frame DS-traversal status", HFILL }},	/* 3 */

    {&hf_fc_to_ds,
     {"To DS", "wlan.fc.tods", FT_BOOLEAN, 8, TFS (&tods_flag), FLAG_TO_DS,
      "To DS flag", HFILL }},		/* 4 */

    {&hf_fc_from_ds,
     {"From DS", "wlan.fc.fromds", FT_BOOLEAN, 8, TFS (&fromds_flag), FLAG_FROM_DS,
      "From DS flag", HFILL }},		/* 5 */

    {&hf_fc_more_frag,
     {"More Fragments", "wlan.fc.frag", FT_BOOLEAN, 8, TFS (&more_frags), FLAG_MORE_FRAGMENTS,
      "More Fragments flag", HFILL }},	/* 6 */

    {&hf_fc_retry,
     {"Retry", "wlan.fc.retry", FT_BOOLEAN, 8, TFS (&retry_flags), FLAG_RETRY,
      "Retransmission flag", HFILL }},

    {&hf_fc_pwr_mgt,
     {"PWR MGT", "wlan.fc.pwrmgt", FT_BOOLEAN, 8, TFS (&pm_flags), FLAG_POWER_MGT,
      "Power management status", HFILL }},

    {&hf_fc_more_data,
     {"More Data", "wlan.fc.moredata", FT_BOOLEAN, 8, TFS (&md_flags), FLAG_MORE_DATA,
      "More data flag", HFILL }},

    {&hf_fc_protected,
     {"Protected flag", "wlan.fc.protected", FT_BOOLEAN, 8, TFS (&protected_flags), FLAG_PROTECTED,
      "Protected flag", HFILL }},

    {&hf_fc_order,
     {"Order flag", "wlan.fc.order", FT_BOOLEAN, 8, TFS (&order_flags), FLAG_ORDER,
      "Strictly ordered flag", HFILL }},

    {&hf_assoc_id,
     {"Association ID","wlan.aid",FT_UINT16, BASE_DEC,NULL,0,
      "Association-ID field", HFILL }},

    {&hf_did_duration,
     {"Duration", "wlan.duration", FT_UINT16, BASE_DEC, NULL, 0,
      "Duration field", HFILL }},

    {&hf_addr_da,
     {"Destination address", "wlan.da", FT_ETHER, BASE_NONE, NULL, 0,
      "Destination Hardware Address", HFILL }},

    {&hf_addr_sa,
     {"Source address", "wlan.sa", FT_ETHER, BASE_NONE, NULL, 0,
      "Source Hardware Address", HFILL }},

    { &hf_addr,
      {"Source or Destination address", "wlan.addr", FT_ETHER, BASE_NONE, NULL, 0,
       "Source or Destination Hardware Address", HFILL }},

    {&hf_addr_ra,
     {"Receiver address", "wlan.ra", FT_ETHER, BASE_NONE, NULL, 0,
      "Receiving Station Hardware Address", HFILL }},

    {&hf_addr_ta,
     {"Transmitter address", "wlan.ta", FT_ETHER, BASE_NONE, NULL, 0,
      "Transmitting Station Hardware Address", HFILL }},

    {&hf_addr_addr1,
     {"First Address of Contained Frame", "wlan.controlwrap.addr1", FT_ETHER, BASE_NONE, NULL, 0,
      "First Address of Contained Frame", HFILL }},

    {&hf_addr_bssid,
     {"BSS Id", "wlan.bssid", FT_ETHER, BASE_NONE, NULL, 0,
      "Basic Service Set ID", HFILL }},

    {&hf_frag_number,
     {"Fragment number", "wlan.frag", FT_UINT16, BASE_DEC, NULL, 0,
      "Fragment number", HFILL }},

    {&hf_seq_number,
     {"Sequence number", "wlan.seq", FT_UINT16, BASE_DEC, NULL, 0,
      "Sequence number", HFILL }},

    {&hf_qos_priority,
     {"Priority", "wlan.qos.priority", FT_UINT16, BASE_DEC, NULL, 0,
      "802.1D Tag", HFILL }},

    {&hf_qos_eosp,
     {"EOSP", "wlan.qos.eosp", FT_BOOLEAN, 8, TFS (&eosp_flag), QOS_FLAG_EOSP,
      "EOSP Field", HFILL }},

    {&hf_qos_ack_policy,
     {"Ack Policy", "wlan.qos.ack", FT_UINT8, BASE_HEX,  VALS (&ack_policy), 0,
      "Ack Policy", HFILL }},

	{&hf_qos_amsdu_present,
     {"Payload Type", "wlan.qos.ampdupresent", FT_BOOLEAN, BASE_NONE,
      TFS (&hf_qos_amsdu_present_flag), 0, "Payload Type", HFILL }},

    {&hf_qos_field_content,
     {"Content", "wlan.qos.fc_content", FT_UINT16, BASE_DEC, NULL, 0,
      "Content1", HFILL }},

/*    {&hf_qos_buffer_state,
     {"QAP PS buffer State", "wlan.qos.ps_buf_state", FT_UINT16, BASE_DEC, NULL, 0,
      "QAP PS buffer State", HFILL }},

    {&hf_qos_txop_dur_req,
     {"TXOP Duration Requested", "wlan.qos.txop_dur_req", FT_UINT16, BASE_DEC, NULL, 0,
      "TXOP Duration Requested", HFILL }},

    {&hf_qos_queue_size,
     {"Queue Size", "wlan.qos.queue_size", FT_UINT16, BASE_DEC, NULL, 0,
      "Queue Size", HFILL }},*/

    {&hf_fcs,
     {"Frame check sequence", "wlan.fcs", FT_UINT32, BASE_HEX,
      NULL, 0, "FCS", HFILL }},

    {&hf_fcs_good,
     {"Good", "wlan.fcs_good", FT_BOOLEAN, BASE_NONE,
      NULL, 0, "True if the FCS is correct", HFILL }},

    {&hf_fcs_bad,
     {"Bad", "wlan.fcs_bad", FT_BOOLEAN, BASE_NONE,
      NULL, 0, "True if the FCS is incorrect", HFILL }},

    {&hf_fragment_overlap,
      {"Fragment overlap", "wlan.fragment.overlap", FT_BOOLEAN, BASE_NONE,
       NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    {&hf_fragment_overlap_conflict,
      {"Conflicting data in fragment overlap", "wlan.fragment.overlap.conflict",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Overlapping fragments contained conflicting data", HFILL }},

    {&hf_fragment_multiple_tails,
      {"Multiple tail fragments found", "wlan.fragment.multipletails",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Several tails were found when defragmenting the packet", HFILL }},

    {&hf_fragment_too_long_fragment,
      {"Fragment too long", "wlan.fragment.toolongfragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment contained data past end of packet", HFILL }},

    {&hf_fragment_error,
      {"Defragmentation error", "wlan.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "Defragmentation error due to illegal fragments", HFILL }},

    {&hf_fragment,
      {"802.11 Fragment", "wlan.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "802.11 Fragment", HFILL }},

    {&hf_fragments,
      {"802.11 Fragments", "wlan.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
       "802.11 Fragments", HFILL }},

    {&hf_reassembled_in,
      {"Reassembled 802.11 in frame", "wlan.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "This 802.11 packet is reassembled in this frame", HFILL }},

    {&hf_wep_iv,
     {"Initialization Vector", "wlan.wep.iv", FT_UINT24, BASE_HEX, NULL, 0,
      "Initialization Vector", HFILL }},

    {&hf_wep_iv_weak,
     {"Weak IV", "wlan.wep.weakiv", FT_BOOLEAN,BASE_NONE, NULL,0x0,
       "Weak IV",HFILL}},

    {&hf_tkip_extiv,
     {"TKIP Ext. Initialization Vector", "wlan.tkip.extiv", FT_STRING,
      BASE_HEX, NULL, 0, "TKIP Extended Initialization Vector", HFILL }},

    {&hf_ccmp_extiv,
     {"CCMP Ext. Initialization Vector", "wlan.ccmp.extiv", FT_STRING,
      BASE_HEX, NULL, 0, "CCMP Extended Initialization Vector", HFILL }},

    {&hf_wep_key,
     {"Key Index", "wlan.wep.key", FT_UINT8, BASE_DEC, NULL, 0,
      "Key Index", HFILL }},

    {&hf_wep_icv,
     {"WEP ICV", "wlan.wep.icv", FT_UINT32, BASE_HEX, NULL, 0,
      "WEP ICV", HFILL }},

	/*** Begin: Block Ack Request/Block Ack  - Dustin Johnson***/
	{&hf_block_ack_request_control,
     {"Block Ack Request Control", "wlan.bar.control",
	  FT_UINT16, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_block_ack_control_ack_policy,
     {"BAR Ack Policy", "wlan.ba.control.ackpolicy",
      FT_BOOLEAN, 16, 0, 0x01, "", HFILL }},

	{&hf_block_ack_control_multi_tid,
     {"Multi-TID", "wlan.ba.control.multitid",
      FT_BOOLEAN, 16, 0, 0x02, "", HFILL }},

	{&hf_block_ack_control_compressed_bitmap,
     {"Compressed Bitmap", "wlan.ba.control.cbitmap",
      FT_BOOLEAN, 16, 0, 0x04, "", HFILL }},

	{&hf_block_ack_control_reserved,
     {"Reserved", "wlan.ba.control.cbitmap",
      FT_UINT16, BASE_HEX, NULL, 0x0ff8, "", HFILL }},

	{&hf_block_ack_control_basic_tid_info,
     {"TID for which a Basic BlockAck frame is requested", "wlan.ba.basic.tidinfo",
      FT_UINT16, BASE_HEX, NULL, 0xf000, "", HFILL }},

	{&hf_block_ack_control_compressed_tid_info,
     {"TID for which a BlockAck frame is requested", "wlan.bar.compressed.tidinfo",
      FT_UINT16, BASE_HEX, NULL, 0xf000, "", HFILL }},

	{&hf_block_ack_control_multi_tid_info,
     {"Number of TIDs Present", "wlan.ba.mtid.tidinfo",
      FT_UINT16, BASE_HEX, NULL, 0xf000, "", HFILL }},

	{&hf_block_ack_control_basic_fragment,
     {"Fragment", "wlan.bar.basic.fragment",
      FT_UINT16, BASE_HEX, 0, 0x0f, "", HFILL }},

	{&hf_block_ack_control_basic_sequence,
     {"Starting Sequence Number", "wlan.bar.basic.sequence",
      FT_UINT16, BASE_HEX, 0, 0xfff0, "", HFILL }},

	{&hf_block_ack_multi_tid_info,
     {"TID Info", "",
      FT_UINT8, BASE_DEC, 0, 0, "", HFILL }},

	{&hf_block_ack_multi_tid_reserved,
     {"Reserved", "wlan.bar.mtid.tidinfo.reserved",
      FT_UINT16, BASE_HEX, 0, 0x0fff, "", HFILL }},

	{&hf_block_ack_multi_tid_value,
     {"Starting Sequence Number", "wlan.bar.mtid.tidinfo.value",
      FT_UINT16, BASE_HEX, 0, 0xf000, "", HFILL }},

	{&hf_block_ack_request_multi_tid_ssc,
     {"Starting Sequence Control", "wlan.bar.mtid.ssc",
      FT_UINT16, BASE_HEX, 0, 0, "", HFILL }},

	{&hf_block_ack_request_type,
     {"Block Ack Request Type", "wlan.bar.type",
      FT_UINT8, BASE_HEX, VALS(&hf_block_ack_request_type_flags), 0, "", HFILL }},

	{&hf_block_ack_ssc,
     {"Starting Sequence Control", "wlan.ba.ssc",
      FT_UINT16, BASE_HEX, 0, 0, "", HFILL }},

	{&hf_block_ack_type,
     {"Block Ack Request Type", "wlan.ba.type",
      FT_UINT8, BASE_HEX, VALS(&hf_block_ack_type_flags), 0, "", HFILL }},
	/*** End: Block Ack Request/Block Ack  - Dustin Johnson***/
  };

  static const true_false_string rsn_preauth_flags = {
    "Transmitter supports pre-authentication",
    "Transmitter does not support pre-authentication"
  };

  static const true_false_string rsn_no_pairwise_flags = {
    "Transmitter cannot support WEP default key 0 simultaneously with "
    "Pairwise key",
    "Transmitter can support WEP default key 0 simultaneously with "
    "Pairwise key"
  };

  static const value_string rsn_cap_replay_counter[] = {
    {0x00, "1 replay counter per PTKSA/GTKSA/STAKeySA"},
    {0x01, "2 replay counters per PTKSA/GTKSA/STAKeySA"},
    {0x02, "4 replay counters per PTKSA/GTKSA/STAKeySA"},
    {0x03, "16 replay counters per PTKSA/GTKSA/STAKeySA"},
    {0, NULL}
  };

  static const true_false_string ht_ldpc_coding_flag = {
      "Transmitter supports receiving LDPC coded packets",
      "Transmitter does not support receiving LDPC coded packets"
  };

  static const true_false_string ht_chan_width_flag = {
      "Transmitter supports 20MHz and 40MHz operation",
      "Transmitter only supports 20MHz operation"
  };

  static const value_string ht_sm_pwsave_flag[] = {
    {0x00, "Static SM Power Save mode"},
    {0x01, "Dynamic SM Power Save mode"},
    {0x02, "Reserved"},
    {0x03, "SM enabled"},
    {0x00, NULL}
  };

  static const true_false_string ht_green_flag = {
      "Transmitter is able to receive PPDUs with Green Field (GF) preamble",
      "Transmitter is not able to receive PPDUs with Green Field (GF) preamble"
  };

  static const true_false_string ht_tf_flag = {
      "Supported",
      "Not Supported "
  };

  static const value_string ht_rx_stbc_flag[] = {
    {0x00, "No Rx STBC support"},
    {0x01, "Rx support of one spatial stream"},
    {0x02, "Rx support of one and two spatial streams"},
    {0x03, "Rx support of one, two, and three spatial streams"},
    {0x00, NULL}
  };

  static const true_false_string ht_delayed_block_ack_flag = {
      "Transmitter supports HT-Delayed BlockAck",
      "Transmitter does not support HT-Delayed BlockAck"
  };

  static const true_false_string ht_max_amsdu_flag = {
      "7935 bytes",
      "3839 bytes"
  };

  static const true_false_string ht_dss_cck_40_flag = {
      "Will/Can use DSSS/CCK in 40 MHz",
      "Won't/Can't use of DSSS/CCK in 40 MHz"
  };

  static const true_false_string ht_psmp_flag = {
      "Will/Can support PSMP operation",
      "Won't/Can't support PSMP operation"
  };

  static const true_false_string ht_40_mhz_intolerant_flag = {
      "Use of 40 Mhz transmissions restricted/disallowed",
      "Use of 40 Mhz transmissions unrestricted/allowed"
  };

  static const value_string ampduparam_mpdu_start_spacing_flags[] = {
    {0x00, "no restriction"},
    {0x01, "1/4 usec"},
    {0x02, "1/2 usec"},
    {0x03, "1 usec"},
    {0x04, "2 usec"},
    {0x05, "4 usec"},
    {0x06, "8 usec"},
    {0x07, "16 usec"},
    {0x00, NULL}
  };

  static const true_false_string mcsset_tx_mcs_set_defined_flag = {
    "Defined",
    "Not Defined",
  };

  static const true_false_string mcsset_tx_rx_mcs_set_not_equal_flag = {
    "Not Equal",
    "Equal",
  };

  static const value_string mcsset_tx_max_spatial_streams_flags[] = {
    {0x00, "1 spatial stream"},
    {0x01, "2 spatial streams"},
    {0x02, "3 spatial streams"},
    {0x03, "4 spatial streams"},
    {0x00, NULL}
  };

  static const value_string htex_transtime_flags[] = {
    {0x00, "No Transition"},
    {0x01, "400 usec"},
    {0x02, "1.5 msec"},
    {0x03, "5 msec"},
    {0x00, NULL}
  };

  static const value_string htex_mcs_flags[] = {
    {0x00, "STA does not provide MCS feedback"},
    {0x01, "Reserved"},
    {0x02, "STA provides only unsolicited MCS feedback"},
    {0x03, "STA can provide MCS feedback in response to MRQ as well as unsolicited MCS feedback"},
    {0x00, NULL}
  };

  static const value_string txbf_calib_flag[] = {
    {0x00, "incapable"},
    {0x01, "Limited involvement, cannot initiate"},
    {0x02, "Limited involvement, can initiate"},
    {0x03, "Fully capable"},
    {0x00, NULL}
  };

  static const value_string txbf_feedback_flags[] = {
    {0x00, "not supported"},
    {0x01, "delayed feedback capable"},
    {0x02, "immediate feedback capable"},
    {0x03, "delayed and immediate feedback capable"},
    {0x00, NULL}
  };

  static const value_string txbf_antenna_flags[] = {
    {0x00, "1 TX antenna sounding"},
    {0x01, "2 TX antenna sounding"},
    {0x02, "3 TX antenna sounding"},
    {0x03, "4 TX antenna sounding"},
    {0x00, NULL}
  };

  static const value_string txbf_csi_max_rows_bf_flags[] = {
    {0x00, "1 row of CSI"},
    {0x01, "2 rows of CSI"},
    {0x02, "3 rows of CSI"},
    {0x03, "4 rows of CSI"},
    {0x00, NULL}
  };

  static const value_string txbf_chan_est_flags[] = {
    {0x00, "1 space time stream"},
    {0x01, "2 space time streams"},
    {0x02, "3 space time streams"},
    {0x03, "4 space time streams"},
    {0x00, NULL}
  };

  static const value_string txbf_min_group_flags[] = {
    {0x00, "No grouping supported"},
    {0x01, "Groups of 1,2 supported"},
    {0x02, "Groups of 1,4 supported"},
    {0x03, "Groups of 1,2,4 supported"},
    {0x00, NULL}
  };

  static const value_string hta_ext_chan_offset_flag[] = {
    {0x00, "No Extension Channel"},
    {0x01, "Extension Channel above control channel"},
    {0x02, "Undefined"},
    {0x03, "Extension Channel below control channel"},
    {0x00, NULL}
  };

  static const true_false_string hta_rec_tx_width_flag = {
      "Any channel width enabled",
      "Use 20MHz channel (control)"
  };

  static const true_false_string hta_rifs_mode_flag = {
      "Use of RIFS permitted",
      "Use of RIFS prohibited"
  };

  static const true_false_string hta_controlled_access_flag = {
      "Not only PSMP",
      "PSMP only"
  };

  static const value_string hta_service_interval_flag[] = {
    {0x00, "5ms"},
    {0x01, "10ms"},
    {0x02, "15ms"},
    {0x03, "20ms"},
    {0x04, "25ms"},
    {0x05, "30ms"},
    {0x06, "35ms"},
    {0x07, "40ms"},
    {0x00, NULL}
  };

  static const value_string hta_operating_mode_flag[] = {
    {0x00, "Pure HT, no protection"},
    {0x01, "There may be non-HT devices (control & ext channel)"},
    {0x02, "No non-HT is associated, but at least 1 20MHz is. protect on"},
    {0x03, "Mixed: no non-HT is associated, protect on"},
    {0x00, NULL}
  };

  static const true_false_string hta_non_gf_devices_flag = {
      "All HT devices associated are GF capable",
      "One or More HT devices are not GF capable"
  };

  static const true_false_string hta_dual_stbc_protection_flag = {
      "Dual CTS protections is used",
      "Regular use of RTS/CTS"
  };

  static const true_false_string hta_secondary_beacon_flag = {
      "Secondary Beacon",
      "Primary Beacon"
  };

  static const true_false_string hta_lsig_txop_protection_flag = {
      "Full Support",
      "Not full support"
  };

  static const true_false_string hta_pco_active_flag = {
      "PCO is activated in the BSS",
      "PCO is not activated in the BSS"
  };

  static const true_false_string hta_pco_phase_flag = {
      "Switch to 20MHz phase/keep 20MHz",
      "Switch to 40MHz phase/keep 40MHz"
  };

  static const value_string ht_info_secondary_channel_offset_flags[] = {
    {0x00, "No secondary channel"},
    {0x01, "Secondary channel is above the primary channel"},
    {0x02, "Reserved"},
    {0x03, "Secondary channel is below the primary channel"},
    {0x00, NULL}
  };

  static const true_false_string ht_info_channel_width_flag = {
      "Channel of any width supported",
      "20 MHz channel width only"
  };

  static const true_false_string ht_info_rifs_mode_flag = {
      "Permitted",
      "Prohibited"
  };

  static const true_false_string ht_info_psmp_stas_only_flag = {
      "Association requests are accepted from only PSMP capable STA",
      "Association requests are accepted regardless of PSMP capability"
  };

  static const value_string ht_info_service_interval_granularity_flags[] = {
    {0x00, "5 ms"},
	{0x01, "10 ms"},
	{0x02, "15 ms"},
	{0x03, "20 ms"},
	{0x04, "25 ms"},
	{0x05, "30 ms"},
	{0x06, "35 ms"},
	{0x07, "40 ms"},
    {0x00, NULL}
  };

  static const value_string ht_info_operating_mode_flags[] = {
    {0x00, "All STAs are - 20/40 MHz HT or in a 20/40 MHz BSS or are 20 MHz HT in a 20 Mhz BSS"},
	{0x01, "HT non-member protection mode"},
	{0x02, "Only HT STAs in the BSS, however, there exists at least one 20 MHz STA"},
	{0x03, "HT mixed mode"},
    {0x00, NULL}
  };

  static const true_false_string ht_info_non_greenfield_sta_present_flag = {
      "One or more associated STAs are not greenfield capable",
      "All associated STAs are greenfield capable"
  };

  static const true_false_string ht_info_transmit_burst_limit_flag = {
      "2.4 GHz - 6.16 ms | All other bands - 3.08 ms",
      "No limit"
  };

  static const true_false_string ht_info_obss_non_ht_stas_present_flag = {
      "Use of protection for non-HT STAs by overlapping BSSs is needed",
      "Use of protection for non-HT STAs by overlapping BSSs is not needed"
  };

  static const true_false_string ht_info_dual_beacon_flag = {
      "AP transmits a secondary beacon",
      "No second beacon is transmitted"
  };

  static const true_false_string ht_info_dual_cts_protection_flag = {
      "Required",
      "Not required"
  };

  static const true_false_string ht_info_secondary_beacon_flag = {
      "Secondary beacon",
      "Primary beacon"
  };

  static const true_false_string ht_info_lsig_txop_protection_full_support_flag = {
      "All HT STAs in the BSS support L-SIG TXOP protection",
      "One or more HT STAs in the BSS do not support L-SIG TXOP protection"
  };

  /* XXX - We might want to use tfs_active_inactive here */
  static const true_false_string ht_info_pco_active_flag = {
      "Active",
      "Not active"
  };

  static const true_false_string ht_info_pco_phase_flag = {
      "Switch to or continue 40 MHz phase",
      "Switch to or continue 20 MHz phase"
  };

  static const true_false_string htc_lac_trq_flag = {
      "Want sounding PPDU",
      "Don't want sounding PPDU"
  };

  static const true_false_string htc_lac_mai_mrq_flag = {
      "MCS feedback requested",
      "No MCS feedback requested"
  };

  static const value_string hf_tag_secondary_channel_offset_flags[] = {
    {0x00, "No Secondary Channel"},
	{0x01, "Above Primary Channel"},
	{0x02, "Reserved"},
	{0x03, "Below Primary Channel"},
    {0x00, NULL}
  };

  static const true_false_string hf_tag_measure_enable_flag = {
      "Enabled",
      "Disabled"
  };

  static const true_false_string hf_tag_measure_acc_not_acc = {
      "Accepted",
      "Not Accepted"
  };

  static const value_string hf_tag_measure_request_type_flags[] = {
    {0x00, "Basic Request"},
	{0x01, "Clear Channel Assessment (CCA) Request"},
	{0x02, "Receive Power Indication (RPI) Histogram Request"},
	{0x03, "Channel Load Request"},
	{0x04, "Noise Histogram Request"},
	{0x05, "Beacon Request"},
	{0x06, "Frame Request"},
	{0x07, "STA Statistics Request"},
	{0x08, "Location Configuration Indication (LCI) Request"},
	{0x09, "Transmit Stream Measurement Request"},
	{0x0A, "Measurement Pause Request"},
    {0x00, NULL}
  };

  static const value_string hf_tag_measure_report_type_flags[] = {
    {0x00, "Basic Report"},
	{0x01, "Clear Channel Assessment (CCA) Report"},
	{0x02, "Receive Power Indication (RPI) Histogram Report"},
	{0x03, "Channel Load Report"},
	{0x04, "Noise Histogram Report"},
	{0x05, "Beacon Report"},
	{0x06, "Frame Report"},
	{0x07, "STA Statistics Report"},
	{0x08, "Location Configuration Information (LCI) Report"},
	{0x09, "Transmit Stream Measurement Report"},
    {0x00, NULL}
  };

  static const true_false_string hf_tag_measure_report_frame_info_frame_type_flag = {
      "Measurement Pilot Frame",
	  "Beacon/Probe Response Frame"
  };

  static const true_false_string hf_tag_measure_map_field_bss_flag = {
      "At least one MPDU was recieved by another BSS or IBSS in the measurement period.",
      "No MPDUs were recieved from another BSS or IBSS in the measurement period."
  };

  static const true_false_string hf_tag_measure_detected_not_detected = {
      "Detected",
      "Not Detected"
  };

  static const true_false_string hf_tag_measure_true_false = {
      "True",
      "False"
  };

  static const value_string hf_tag_measure_request_measurement_mode_flags[] = {
    {0x00, "Passive"},
	{0x01, "Active"},
	{0x02, "Beacon Table"},
    {0x00, NULL}
  };

  static const value_string hf_tag_measure_request_reporting_condition_flags[] = {
    {0x00, "Report to be issued after each measurement."},
	{0x01, "The measured RCPI level is greater than an absolute threshold."},
	{0x02, "The measured RCPI level is less than an absolute threshold."},
	{0x03, "The measured RSNI level is greater than an absolute threshold."},
	{0x04, "The measured RSNI level is less than an absolute threshold."},
	{0x05, "The measured RCPI level is greater than a threshold defined by an offset from the serving AP's reference RCPI."},
	{0x06, "The measured RCPI level is less than a threshold defined by an offset from the serving AP's reference RCPI."},
	{0x07, "The measured RSNI level is greater than a threshold defined by an offset from the serving AP's reference RSNI."},
	{0x08, "The measured RSNI level is less than a threshold defined by an offset from the serving AP's reference RSNI."},
	{0x09, "The measured RCPI level is in a range bound by the serving AP's reference RCPI and an offset from the serving AP's reference RCPI."},
	{0x0a, "The measured RSNI level is in a range bound by the serving AP's reference RSNI and an offset from the serving AP's reference RSNI."},
	{0xfe, "Report not required to be issued"},
    {0x00, NULL}
  };

  static const value_string hf_tag_measure_request_group_id_flags[] = {
    {0x00, "STA Counters from dot11CountersTable"},
	{0x01, "STA Counters from dot11MacStatistics group"},
	{0x02, "QoS STA Counters for UP0 from dot11QosCountersTable"},
	{0x03, "QoS STA Counters for UP1 from dot11QosCountersTable"},
	{0x04, "QoS STA Counters for UP2 from dot11QosCountersTable"},
	{0x05, "QoS STA Counters for UP3 from dot11QosCountersTable"},
	{0x06, "QoS STA Counters for UP4 from dot11QosCountersTable"},
	{0x07, "QoS STA Counters for UP5 from dot11QosCountersTable"},
	{0x08, "QoS STA Counters for UP6 from dot11QosCountersTable"},
	{0x09, "QoS STA Counters for UP7 from dot11QosCountersTable"},
	{0x0a, "BSS Average Access Delays"},
	{0x0b, "STA Counters from dot11A-MSDU Group"},
	{0x0c, "STA Counters from dot11A-MPDU Group"},
	{0x0d, "STA Counters from dot11 BAR, Channel Width, PSMP Group"},
	{0x0e, "STA Counters from dot11Protection Group"},
	{0x0f, "STBC Group"},
    {0x00, NULL}
  };

  static const true_false_string hf_tag_extended_capabilities_flag = {
      "True - HT Information Exchange management frame type supported",
      "False -  HT Information Exchange management frame type not supported"
  };

  /*** Begin: Extended Channel Switch Announcement Tag - Dustin Johnson ***/
  static const value_string hf_tag_ext_channel_switch_announcement_switch_mode_flags[] = {
    {0x00, "Frames may be transmitted before the channel switch has been completed"},
	{0x01, "No more frames are to be transmitted until the channel switch has been completed"},
    {0x00, NULL}
  };
  /*** End: Extended Channel Switch Announcement Tag - Dustin Johnson ***/

  static hf_register_info ff[] = {
    {&ff_timestamp,
     {"Timestamp", "wlan_mgt.fixed.timestamp", FT_STRING, BASE_NONE,
      NULL, 0, "", HFILL }},

    {&ff_auth_alg,
     {"Authentication Algorithm", "wlan_mgt.fixed.auth.alg",
      FT_UINT16, BASE_DEC, VALS (&auth_alg), 0, "", HFILL }},

    {&ff_beacon_interval,
     {"Beacon Interval", "wlan_mgt.fixed.beacon", FT_DOUBLE, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&hf_fixed_parameters,
     {"Fixed parameters", "wlan_mgt.fixed.all", FT_UINT16, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&hf_tagged_parameters,
     {"Tagged parameters", "wlan_mgt.tagged.all", FT_UINT16, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&ff_capture,
     {"Capabilities", "wlan_mgt.fixed.capabilities", FT_UINT16, BASE_HEX, NULL, 0,
      "Capability information", HFILL }},

    {&ff_cf_ess,
     {"ESS capabilities", "wlan_mgt.fixed.capabilities.ess",
      FT_BOOLEAN, 16, TFS (&cf_ess_flags), 0x0001, "ESS capabilities", HFILL }},

    {&ff_cf_ibss,
     {"IBSS status", "wlan_mgt.fixed.capabilities.ibss",
      FT_BOOLEAN, 16, TFS (&cf_ibss_flags), 0x0002, "IBSS participation", HFILL }},

    {&ff_cf_sta_poll,
     {"CFP participation capabilities", "wlan_mgt.fixed.capabilities.cfpoll.sta",
      FT_UINT16, BASE_HEX, VALS (&sta_cf_pollable), 0x020C,
      "CF-Poll capabilities for a STA", HFILL }},

    {&ff_cf_ap_poll,
     {"CFP participation capabilities", "wlan_mgt.fixed.capabilities.cfpoll.ap",
      FT_UINT16, BASE_HEX, VALS (&ap_cf_pollable), 0x020C,
      "CF-Poll capabilities for an AP", HFILL }},

    {&ff_cf_privacy,
     {"Privacy", "wlan_mgt.fixed.capabilities.privacy",
      FT_BOOLEAN, 16, TFS (&cf_privacy_flags), 0x0010, "WEP support", HFILL }},

    {&ff_cf_preamble,
     {"Short Preamble", "wlan_mgt.fixed.capabilities.preamble",
      FT_BOOLEAN, 16, TFS (&cf_preamble_flags), 0x0020, "Short Preamble", HFILL }},

    {&ff_cf_pbcc,
     {"PBCC", "wlan_mgt.fixed.capabilities.pbcc",
      FT_BOOLEAN, 16, TFS (&cf_pbcc_flags), 0x0040, "PBCC Modulation", HFILL }},

    {&ff_cf_agility,
     {"Channel Agility", "wlan_mgt.fixed.capabilities.agility",
      FT_BOOLEAN, 16, TFS (&cf_agility_flags), 0x0080, "Channel Agility", HFILL }},

    {&ff_cf_spec_man,
     {"Spectrum Management", "wlan_mgt.fixed.capabilities.spec_man",
      FT_BOOLEAN, 16, TFS (&cf_spec_man_flags), 0x0100, "Spectrum Management", HFILL }},

    {&ff_short_slot_time,
     {"Short Slot Time", "wlan_mgt.fixed.capabilities.short_slot_time",
      FT_BOOLEAN, 16, TFS (&short_slot_time_flags), 0x0400, "Short Slot Time",
      HFILL }},

    {&ff_cf_apsd,
     {"Automatic Power Save Delivery", "wlan_mgt.fixed.capabilities.apsd",
      FT_BOOLEAN, 16, TFS (&cf_apsd_flags), 0x0800, "Automatic Power Save "
	"Delivery", HFILL }},

    {&ff_dsss_ofdm,
     {"DSSS-OFDM", "wlan_mgt.fixed.capabilities.dsss_ofdm",
      FT_BOOLEAN, 16, TFS (&dsss_ofdm_flags), 0x2000, "DSSS-OFDM Modulation",
      HFILL }},

    {&ff_cf_del_blk_ack,
     {"Delayed Block Ack", "wlan_mgt.fixed.capabilities.del_blk_ack",
      FT_BOOLEAN, 16, TFS (&cf_del_blk_ack_flags), 0x4000, "Delayed Block "
	"Ack", HFILL }},

    {&ff_cf_imm_blk_ack,
     {"Immediate Block Ack", "wlan_mgt.fixed.capabilities.imm_blk_ack",
      FT_BOOLEAN, 16, TFS (&cf_imm_blk_ack_flags), 0x8000, "Immediate Block "
	"Ack", HFILL }},

    {&ff_auth_seq,
     {"Authentication SEQ", "wlan_mgt.fixed.auth_seq",
      FT_UINT16, BASE_HEX, NULL, 0, "Authentication sequence number", HFILL }},

    {&ff_assoc_id,
     {"Association ID", "wlan_mgt.fixed.aid",
      FT_UINT16, BASE_HEX, NULL, 0, "Association ID", HFILL }},

    {&ff_listen_ival,
     {"Listen Interval", "wlan_mgt.fixed.listen_ival",
      FT_UINT16, BASE_HEX, NULL, 0, "Listen Interval", HFILL }},

    {&ff_current_ap,
     {"Current AP", "wlan_mgt.fixed.current_ap",
      FT_ETHER, BASE_NONE, NULL, 0, "MAC address of current AP", HFILL }},

    {&ff_reason,
     {"Reason code", "wlan_mgt.fixed.reason_code",
      FT_UINT16, BASE_HEX, VALS (&reason_codes), 0,
      "Reason for unsolicited notification", HFILL }},

    {&ff_status_code,
     {"Status code", "wlan_mgt.fixed.status_code",
      FT_UINT16, BASE_HEX, VALS (&status_codes), 0,
      "Status of requested event", HFILL }},

    {&ff_category_code,
     {"Category code", "wlan_mgt.fixed.category_code",
      FT_UINT16, BASE_DEC, VALS (&category_codes), 0,
      "Management action category", HFILL }},

    {&ff_action_code,
     {"Action code", "wlan_mgt.fixed.action_code",
      FT_UINT16, BASE_DEC, VALS (&action_codes), 0,
      "Management action code", HFILL }},

    {&ff_dialog_token,
     {"Dialog token", "wlan_mgt.fixed.dialog_token",
      FT_UINT16, BASE_HEX, NULL, 0, "Management action dialog token", HFILL }},

    {&ff_wme_action_code,
     {"Action code", "wlan_mgt.fixed.action_code",
      FT_UINT16, BASE_HEX, VALS (&wme_action_codes), 0,
      "Management notification action code", HFILL }},

    {&ff_wme_status_code,
     {"Status code", "wlan_mgt.fixed.status_code",
      FT_UINT16, BASE_HEX, VALS (&wme_status_codes), 0,
      "Management notification setup response status code", HFILL }},

    {&ff_qos_action_code,
     {"Action code", "wlan_mgt.fixed.action_code",
      FT_UINT16, BASE_HEX, VALS (&qos_action_codes), 0,
      "QoS management action code", HFILL }},

    {&ff_dls_action_code,
     {"Action code", "wlan_mgt.fixed.action_code",
      FT_UINT16, BASE_HEX, VALS (&dls_action_codes), 0,
      "DLS management action code", HFILL }},

    {&ff_dst_mac_addr,
     {"Destination address", "wlan_mgt.fixed.dst_mac_addr",
      FT_ETHER, BASE_NONE, NULL, 0, "Destination MAC address", HFILL }},

    {&ff_src_mac_addr,
     {"Source address", "wlan_mgt.fixed.src_mac_addr",
      FT_ETHER, BASE_NONE, NULL, 0, "Source MAC address", HFILL }},

    {&ff_dls_timeout,
     {"DLS timeout", "wlan_mgt.fixed.dls_timeout",
      FT_UINT16, BASE_HEX, NULL, 0, "DLS timeout value", HFILL }},

    {&tag_number,
     {"Tag", "wlan_mgt.tag.number",
      FT_UINT8, BASE_DEC, VALS(tag_num_vals), 0,
      "Element ID", HFILL }},

    {&tag_length,
     {"Tag length", "wlan_mgt.tag.length",
      FT_UINT8, BASE_DEC, NULL, 0, "Length of tag", HFILL }},

    {&tag_interpretation,
     {"Tag interpretation", "wlan_mgt.tag.interpretation",
      FT_STRING, BASE_NONE, NULL, 0, "Interpretation of tag", HFILL }},

    {&tag_oui,
     {"OUI", "wlan_mgt.tag.oui",
      FT_BYTES, BASE_NONE, NULL, 0, "OUI of vendor specific IE", HFILL }},

    {&tim_length,
     {"TIM length", "wlan_mgt.tim.length",
      FT_UINT8, BASE_DEC, NULL, 0,
      "Traffic Indication Map length", HFILL }},

    {&tim_dtim_count,
     {"DTIM count", "wlan_mgt.tim.dtim_count",
      FT_UINT8, BASE_DEC, NULL, 0,
      "DTIM count", HFILL }},

    {&tim_dtim_period,
     {"DTIM period", "wlan_mgt.tim.dtim_period",
      FT_UINT8, BASE_DEC, NULL, 0,
      "DTIM period", HFILL }},

    {&tim_bmapctl,
     {"Bitmap control", "wlan_mgt.tim.bmapctl",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Bitmap control", HFILL }},

    {&rsn_cap,
     {"RSN Capabilities", "wlan_mgt.rsn.capabilities", FT_UINT16, BASE_HEX,
      NULL, 0, "RSN Capability information", HFILL }},

    {&rsn_cap_preauth,
     {"RSN Pre-Auth capabilities", "wlan_mgt.rsn.capabilities.preauth",
      FT_BOOLEAN, 16, TFS (&rsn_preauth_flags), 0x0001,
      "RSN Pre-Auth capabilities", HFILL }},

    {&rsn_cap_no_pairwise,
     {"RSN No Pairwise capabilities", "wlan_mgt.rsn.capabilities.no_pairwise",
      FT_BOOLEAN, 16, TFS (&rsn_no_pairwise_flags), 0x0002,
      "RSN No Pairwise capabilities", HFILL }},

    {&rsn_cap_ptksa_replay_counter,
     {"RSN PTKSA Replay Counter capabilities",
      "wlan_mgt.rsn.capabilities.ptksa_replay_counter",
      FT_UINT16, BASE_HEX, VALS (&rsn_cap_replay_counter), 0x000C,
      "RSN PTKSA Replay Counter capabilities", HFILL }},

    {&rsn_cap_gtksa_replay_counter,
     {"RSN GTKSA Replay Counter capabilities",
      "wlan_mgt.rsn.capabilities.gtksa_replay_counter",
      FT_UINT16, BASE_HEX, VALS (&rsn_cap_replay_counter), 0x0030,
      "RSN GTKSA Replay Counter capabilities", HFILL }},

    {&ht_cap,
     {"HT Capabilities", "wlan_mgt.ht.capabilities", FT_UINT16, BASE_HEX,
      NULL, 0, "HT Capability information", HFILL }},

    {&ht_ldpc_coding,
     {"HT LDPC coding capability", "wlan_mgt.ht.capabilities.ldpccoding",
      FT_BOOLEAN, 16, TFS (&ht_ldpc_coding_flag), 0x0001,
      "HT LDPC coding capability", HFILL }},

    {&ht_chan_width,
     {"HT Support channel width", "wlan_mgt.ht.capabilities.width",
      FT_BOOLEAN, 16, TFS (&ht_chan_width_flag), 0x0002,
      "HT Support channel width", HFILL }},

    {&ht_sm_pwsave,
     {"HT SM Power Save", "wlan_mgt.ht.capabilities.sm",
      FT_UINT16, BASE_HEX, VALS (&ht_sm_pwsave_flag), 0x000c,
      "HT SM Power Save", HFILL }},

    {&ht_green,
     {"HT Green Field", "wlan_mgt.ht.capabilities.green",
      FT_BOOLEAN, 16, TFS (&ht_green_flag), 0x0010,
      "HT Green Field", HFILL }},

    {&ht_short20,
     {"HT Short GI for 20MHz", "wlan_mgt.ht.capabilities.short20",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0020,
      "HT Short GI for 20MHz", HFILL }},

    {&ht_short40,
     {"HT Short GI for 40MHz", "wlan_mgt.ht.capabilities.short40",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0040,
      "HT Short GI for 40MHz", HFILL }},

    {&ht_tx_stbc,
     {"HT Tx STBC", "wlan_mgt.ht.capabilities.txstbc",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0080,
      "HT Tx STBC", HFILL }},

    {&ht_rx_stbc,
     {"HT Rx STBC", "wlan_mgt.ht.capabilities.rxstbc",
      FT_UINT16, BASE_HEX, VALS (&ht_rx_stbc_flag), 0x0300,
      "HT Tx STBC", HFILL }},

    {&ht_delayed_block_ack,
     {"HT Delayed Block ACK", "wlan_mgt.ht.capabilities.delayedblockack",
      FT_BOOLEAN, 16, TFS (&ht_delayed_block_ack_flag), 0x0400,
      "HT Delayed Block ACK", HFILL }},

    {&ht_max_amsdu,
     {"HT Max A-MSDU length", "wlan_mgt.ht.capabilities.amsdu",
      FT_BOOLEAN, 16, TFS (&ht_max_amsdu_flag), 0x0800,
      "HT Max A-MSDU length", HFILL }},

    {&ht_dss_cck_40,
     {"HT DSSS/CCK mode in 40MHz", "wlan_mgt.ht.capabilities.dsscck",
      FT_BOOLEAN, 16, TFS (&ht_dss_cck_40_flag), 0x1000,
      "HT DSS/CCK mode in 40MHz", HFILL }},

    {&ht_psmp,
     {"HT PSMP Support", "wlan_mgt.ht.capabilities.psmp",
      FT_BOOLEAN, 16, TFS (&ht_psmp_flag), 0x2000,
      "HT PSMP Support", HFILL }},

    {&ht_40_mhz_intolerant,
     {"HT Forty MHz Intolerant", "wlan_mgt.ht.capabilities.40mhzintolerant",
      FT_BOOLEAN, 16, TFS (&ht_40_mhz_intolerant_flag), 0x4000,
      "HT Forty MHz Intolerant", HFILL }},

    {&ht_l_sig,
     {"HT L-SIG TXOP Protection support", "wlan_mgt.ht.capabilities.lsig",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x8000,
      "HT L-SIG TXOP Protection support", HFILL }},

    {&ampduparam,
     {"MAC Parameters", "wlan_mgt.ht.ampduparam", FT_UINT16, BASE_HEX,
      NULL, 0, "MAC Parameters", HFILL }},

    {&ampduparam_mpdu,
     {"Maximum Rx A-MPDU Length 2^(13+maxLen)-1 Bytes", "wlan_mgt.ht.ampduparam.maxlength",
      FT_UINT8, BASE_HEX, 0 , 0x03,
      "Maximum Rx A-MPDU Length 2^(13+maxLen)-1 Bytes", HFILL }},

    {&ampduparam_mpdu_start_spacing,
     {"MPDU Density", "wlan_mgt.ht.ampduparam.mpdudensity",
      FT_UINT8, BASE_HEX, VALS (&ampduparam_mpdu_start_spacing_flags) , 0x1c,
      "MPDU Density", HFILL }},

	{&mcsset,
     {"Supported MCS Set", "wlan_mgt.ht.mcsset",
      FT_STRING, BASE_NONE, NULL, 0, "Supported MCS Set", HFILL }},

	{&mcsset_highest_data_rate,
     {"Highest Supported Data Rate", "wlan_mgt.ht.mcsset.highestdatarate",
      FT_UINT16, BASE_HEX, 0, 0x03ff, "Highest Supported Data Rate", HFILL }},

	{&mcsset_tx_mcs_set_defined,
     {"Tx Suported MCS Set", "wlan_mgt.ht.mcsset.txsetdefined",
      FT_BOOLEAN, 16, TFS (&mcsset_tx_mcs_set_defined_flag), 0x0001,
      "Tx Suported MCS Set", HFILL }},

	{&mcsset_tx_rx_mcs_set_not_equal,
     {"Tx and Rx MCS Set", "wlan_mgt.ht.mcsset.txrxmcsnotequal",
      FT_BOOLEAN, 16, TFS (&mcsset_tx_rx_mcs_set_not_equal_flag), 0x0002,
      "Tx and Rx MCS Set", HFILL }},

    {&mcsset_tx_max_spatial_streams,
     {"Tx Maximum Number of Spatial Streams Supported", "wlan_mgt.ht.mcsset.txmaxss",
      FT_UINT16, BASE_HEX, VALS (&mcsset_tx_max_spatial_streams_flags) , 0x001c,
      "Tx Maximum Number of Spatial Streams Supported", HFILL }},

	{&mcsset_tx_unequal_modulation,
     {"Unequal Modulation", "wlan_mgt.ht.mcsset.txunequalmod",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0020,
      "Unequal Modulation", HFILL }},

    {&htex_cap,
     {"HT Extended Capabilities", "wlan_mgt.htex.capabilities", FT_UINT16, BASE_HEX,
      NULL, 0, "HT Extended Capability information", HFILL }},

    {&htex_pco,
     {"Transmitter supports PCO", "wlan_mgt.htex.capabilities.pco",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0001,
      "Transmitter supports PCO", HFILL }},

    {&htex_transtime,
     {"Transition Time between 20MHz and 40MHz", "wlan_mgt.htex.capabilities.transtime",
      FT_UINT16, BASE_HEX, VALS (&htex_transtime_flags), 0x0006,
      "Transition Time between 20MHz and 40MHz", HFILL }},

    {&htex_mcs,
     {"MCS Feedback capability", "wlan_mgt.htex.capabilities.mcs",
      FT_UINT16, BASE_HEX, VALS (&htex_mcs_flags), 0x0300,
      "MCS Feedback capability", HFILL }},

	{&htex_htc_support,
     {"High Throughput", "wlan_mgt.htex.capabilities.htc",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0400,
      "High Throughput", HFILL }},

	{&htex_rd_responder,
     {"Reverse Direction Responder", "wlan_mgt.htex.capabilities.rdresponder",
      FT_BOOLEAN, 16, TFS (&ht_tf_flag), 0x0800,
      "Reverse Direction Responder", HFILL }},

    {&txbf,
     {"TxBF Transmit Beam Forming Capability", "wlan_mgt.txbf", FT_UINT16, BASE_HEX,
      NULL, 0, "TxBF Transmit Beam Forming Capability", HFILL }},

    {&txbf_cap,
     {"TxBF", "wlan_mgt.txbf.txbf",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000001,
      "", HFILL }},

    {&txbf_rcv_ssc,
     {"Receive Staggered Sounding", "wlan_mgt.txbf.rxss",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000002,
      "", HFILL }},

    {&txbf_tx_ssc,
     {"Transmit staggered sounding", "wlan_mgt.txbf.txss",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000004,
      "", HFILL }},

    {&txbf_rcv_ndp,
     {"Receive NDP", "wlan_mgt.txbf.rxndp",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000008,
      "", HFILL }},

    {&txbf_tx_ndp,
     {"Transmit NDP", "wlan_mgt.txbf.txndp",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000010,
      "", HFILL }},

    {&txbf_impl_txbf,
     {"Implicit TxBF capable", "wlan_mgt.txbf.impltxbf",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000020,
      "", HFILL }},

    {&txbf_calib,
     {"Calibration", "wlan_mgt.txbf.calibration",
      FT_UINT32, BASE_HEX, VALS (&txbf_calib_flag), 0x000000c0,
      "", HFILL }},

    {&txbf_expl_csi,
     {"STA can apply TxBF using CSI explicit feedback", "wlan_mgt.txbf.csi",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000100,
      "", HFILL }},

    {&txbf_expl_uncomp_fm,
     {"STA can apply TxBF using uncompressed beamforming feedback matrix", "wlan_mgt.txbf.fm.uncompressed.tbf",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000200,
      "", HFILL }},

	{&txbf_expl_comp_fm,
     {"STA can apply TxBF using compressed beamforming feedback matrix", "wlan_mgt.txbf.fm.compressed.tbf",
      FT_BOOLEAN, 32, TFS (&ht_tf_flag), 0x00000400,
      "", HFILL }},

    {&txbf_expl_bf_csi,
     {"Receiver can return explicit CSI feedback", "wlan_mgt.txbf.rcsi",
      FT_UINT32, BASE_HEX, VALS (&txbf_feedback_flags), 0x00001800,
      "", HFILL }},

    {&txbf_expl_uncomp_fm_feed,
     {"Receiver can return explicit uncompressed Beamforming Feedback Matrix", "wlan_mgt.txbf.fm.uncompressed.rbf",
      FT_UINT32, BASE_HEX, VALS (&txbf_feedback_flags), 0x00006000,
      "", HFILL }},

    {&txbf_expl_comp_fm_feed,
     {"STA can compress and use compressed Beamforming Feedback Matrix", "wlan_mgt.txbf.fm.compressed.bf",
      FT_UINT32, BASE_HEX, VALS (&txbf_feedback_flags), 0x00018000,
      "", HFILL }},

	{&txbf_min_group,
     {"Minimal grouping used for explicit feedback reports", "wlan_mgt.txbf.mingroup",
      FT_UINT32, BASE_HEX, VALS (&txbf_min_group_flags), 0x00060000,
      "", HFILL }},

    {&txbf_csi_num_bf_ant,
     {"Max antennae STA can support when CSI feedback required", "wlan_mgt.txbf.csinumant",
      FT_UINT32, BASE_HEX, VALS (&txbf_antenna_flags), 0x00180000,
      "", HFILL }},

    {&txbf_uncomp_sm_bf_ant,
     {"Max antennae STA can support when uncompressed Beamforming feedback required", "wlan_mgt.txbf.fm.uncompressed.maxant",
      FT_UINT32, BASE_HEX, VALS (&txbf_antenna_flags), 0x00600000,
      "", HFILL }},

    {&txbf_comp_sm_bf_ant,
     {"Max antennae STA can support when compressed Beamforming feedback required", "wlan_mgt.txbf.fm.compressed.maxant",
      FT_UINT32, BASE_HEX, VALS (&txbf_antenna_flags), 0x01800000,
      "", HFILL }},

	{&txbf_csi_max_rows_bf,
     {"Maximum number of rows of CSI explicit feeback", "wlan_mgt.txbf.csi.maxrows",
      FT_UINT32, BASE_HEX, VALS (&txbf_csi_max_rows_bf_flags), 0x06000000,
      "", HFILL }},

    {&txbf_chan_est,
     {"Maximum number of space time streams for which channel dimensions can be simultaneously estimated", "wlan_mgt.txbf.channelest",
      FT_UINT32, BASE_HEX, VALS (&txbf_chan_est_flags), 0x18000000,
      "", HFILL }},

	{&txbf_resrv,
     {"Reserved", "wlan_mgt.txbf.reserved",
      FT_UINT32, BASE_HEX, NULL, 0xe0000000,
      "", HFILL }},

    {&hta_cap,
     {"HT Additional Capabilities", "wlan_mgt.hta.capabilities", FT_UINT16, BASE_HEX,
      NULL, 0, "HT Additional Capability information", HFILL }},

    {&hta_ext_chan_offset,
     {"Extension Channel Offset", "wlan_mgt.hta.capabilities.extchan",
      FT_UINT16, BASE_HEX, VALS (&hta_ext_chan_offset_flag), 0x0003,
      "", HFILL }},

    {&hta_rec_tx_width,
     {"Reccomended Tx Channel Width", "wlan_mgt.hta.capabilities.rectxwidth",
      FT_BOOLEAN, 16, TFS (&hta_rec_tx_width_flag), 0x0004,
      "", HFILL }},

    {&hta_rifs_mode,
     {"RIFS Mode", "wlan_mgt.hta.capabilities.rifsmode",
      FT_BOOLEAN, 16, TFS (&hta_rifs_mode_flag), 0x0008,
      "", HFILL }},

    {&hta_controlled_access,
     {"Controlled Access Only", "wlan_mgt.hta.capabilities.controlledaccess",
      FT_BOOLEAN, 16, TFS (&hta_controlled_access_flag), 0x0010,
      "", HFILL }},

    {&hta_service_interval,
     {"Service Interval Granularity", "wlan_mgt.hta.capabilities.serviceinterval",
      FT_UINT16, BASE_HEX, VALS (&hta_service_interval_flag), 0x00E0,
      "", HFILL }},

    {&hta_operating_mode,
     {"Operating Mode", "wlan_mgt.hta.capabilities.operatingmode",
      FT_UINT16, BASE_HEX, VALS (&hta_operating_mode_flag), 0x0003,
      "", HFILL }},

    {&hta_non_gf_devices,
     {"Non GF devices Present", "wlan_mgt.hta.capabilities.nongfdevices",
      FT_BOOLEAN, 16, TFS (&hta_non_gf_devices_flag), 0x0004,
      "", HFILL }},

    {&hta_basic_stbc_mcs,
     {"Basic STB MCS", "wlan_mgt.hta.capabilities.",
      FT_UINT16, BASE_HEX, NULL , 0x007f,
      "", HFILL }},

    {&hta_dual_stbc_protection,
     {"Dual CTS Protection", "wlan_mgt.hta.capabilities.",
      FT_BOOLEAN, 16, TFS (&hta_dual_stbc_protection_flag), 0x0080,
      "", HFILL }},

    {&hta_secondary_beacon,
     {"Secondary Beacon", "wlan_mgt.hta.capabilities.",
      FT_BOOLEAN, 16, TFS (&hta_secondary_beacon_flag), 0x0100,
      "", HFILL }},

    {&hta_lsig_txop_protection,
     {"L-SIG TXOP Protection Support", "wlan_mgt.hta.capabilities.",
      FT_BOOLEAN, 16, TFS (&hta_lsig_txop_protection_flag), 0x0200,
      "", HFILL }},

    {&hta_pco_active,
     {"PCO Active", "wlan_mgt.hta.capabilities.",
      FT_BOOLEAN, 16, TFS (&hta_pco_active_flag), 0x0400,
      "", HFILL }},

    {&hta_pco_phase,
     {"PCO Phase", "wlan_mgt.hta.capabilities.",
      FT_BOOLEAN, 16, TFS (&hta_pco_phase_flag), 0x0800,
      "", HFILL }},

    {&antsel,
     {"Antenna Selection Capability", "wlan_mgt.txbf",
	  FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

    {&antsel_b0,
     {"Antenna Selection Capable", "wlan_mgt.asel.capable",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x01, "", HFILL }},

    {&antsel_b1,
     {"Explicit CSI Feedback Based Tx ASEL", "wlan_mgt.asel.txcsi",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x02, "", HFILL }},

    {&antsel_b2,
     {"Antenna Indices Feedback Based Tx ASEL", "wlan_mgt.asel.txif",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x04, "", HFILL }},

    {&antsel_b3,
     {"Explicit CSI Feedback", "wlan_mgt.asel.csi",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x08, "", HFILL }},

    {&antsel_b4,
     {"Antenna Indices Feedback", "wlan_mgt.asel.if",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x10, "", HFILL }},

    {&antsel_b5,
     {"Rx ASEL", "wlan_mgt.asel.rx",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x20, "", HFILL }},

    {&antsel_b6,
     {"Tx Sounding PPDUs", "wlan_mgt.asel.sppdu",
      FT_BOOLEAN, 8, TFS (&ht_tf_flag), 0x40, "", HFILL }},

	{&antsel_b7,
     {"Reserved", "wlan_mgt.asel.reserved",
      FT_UINT8, BASE_HEX, NULL, 0x80, "", HFILL }},

	{&ht_info_delimiter1,
     {"HT Information Delimiter 1", "wlan_mgt.ht.info.delim1",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&ht_info_primary_channel,
     {"Primary channel", "wlan_mgt.ht.info.primarychannel",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&ht_info_secondary_channel_offset,
     {"Secondary channel offset", "wlan_mgt.ht.info.secchanoffset",
      FT_UINT8, BASE_HEX, VALS (&ht_info_secondary_channel_offset_flags), 0x03, "", HFILL }},

	{&ht_info_channel_width,
     {"Supported channel width", "wlan_mgt.ht.info.chanwidth",
      FT_BOOLEAN, 8, TFS (&ht_info_channel_width_flag), 0x04, "", HFILL }},

	{&ht_info_rifs_mode,
     {"Reduced interframe spacing (RIFS)", "wlan_mgt.ht.info.rifs",
      FT_BOOLEAN, 8, TFS (&ht_info_rifs_mode_flag), 0x08, "", HFILL }},

	{&ht_info_psmp_stas_only,
     {"PSMP stations only", "wlan_mgt.ht.info.psmponly",
      FT_BOOLEAN, 8, TFS (&ht_info_psmp_stas_only_flag), 0x10, "", HFILL }},

	{&ht_info_service_interval_granularity,
     {"Shortest service interval", "wlan_mgt.ht.info.",
      FT_UINT8, BASE_HEX, VALS (&ht_info_service_interval_granularity_flags), 0xe0, "", HFILL }},

	{&ht_info_delimiter2,
     {"HT Information Delimiter #2", "wlan_mgt.ht.info.delim2",
      FT_UINT16, BASE_HEX, NULL, 0xffff, "", HFILL }},

	{&ht_info_operating_mode,
     {"Operating mode of BSS", "wlan_mgt.ht.info.operatingmode",
      FT_UINT16, BASE_HEX, VALS (&ht_info_operating_mode_flags), 0x0003, "", HFILL }},

	{&ht_info_non_greenfield_sta_present,
     {"Non-greenfield STAs present", "wlan_mgt.ht.info.greenfield",
      FT_BOOLEAN, 16, TFS (&ht_info_non_greenfield_sta_present_flag), 0x0004, "", HFILL }},

	{&ht_info_transmit_burst_limit,
     {"Transmit burst limit", "wlan_mgt.ht.info.burstlim",
      FT_BOOLEAN, 16, TFS (&ht_info_transmit_burst_limit_flag), 0x0008, "", HFILL }},

	{&ht_info_obss_non_ht_stas_present,
     {"OBSS non-HT STAs present", "wlan_mgt.ht.info.obssnonht",
      FT_BOOLEAN, 16, TFS (&ht_info_obss_non_ht_stas_present_flag), 0x0010, "", HFILL }},

	{&ht_info_reserved_1,
     {"Reserved", "wlan_mgt.ht.info.reserved1",
      FT_UINT16, BASE_HEX, NULL, 0xffe0, "", HFILL }},

	{&ht_info_delimiter3,
     {"HT Information Delimiter #3", "wlan_mgt.ht.info.delim3",
      FT_UINT16, BASE_HEX, NULL, 0xffff, "", HFILL }},

	{&ht_info_reserved_2,
     {"Reserved", "wlan_mgt.ht.info.reserved2",
      FT_UINT16, BASE_HEX, NULL, 0x003f, "", HFILL }},

	{&ht_info_dual_beacon,
     {"Dual beacon", "wlan_mgt.ht.info.dualbeacon",
      FT_BOOLEAN, 16, TFS (&ht_info_dual_beacon_flag), 0x0040, "", HFILL }},

	{&ht_info_dual_cts_protection,
     {"Dual CTS protection", "wlan_mgt.ht.info.dualcts",
      FT_BOOLEAN, 16, TFS (&ht_info_dual_cts_protection_flag), 0x0080, "", HFILL }},

	{&ht_info_secondary_beacon,
     {"Beacon ID", "wlan_mgt.ht.info.secondarybeacon",
      FT_BOOLEAN, 16, TFS (&ht_info_secondary_beacon_flag), 0x0100, "", HFILL }},

	{&ht_info_lsig_txop_protection_full_support,
     {"L-SIG TXOP Protection Full Support", "wlan_mgt.ht.info.lsigprotsupport",
      FT_BOOLEAN, 16, TFS (&ht_info_lsig_txop_protection_full_support_flag), 0x0200, "", HFILL }},

	{&ht_info_pco_active,
     {"PCO", "wlan_mgt.ht.info.pco.active",
      FT_BOOLEAN, 16, TFS (&ht_info_pco_active_flag), 0x0400, "", HFILL }},

	{&ht_info_pco_phase,
     {"PCO phase", "wlan_mgt.ht.info.pco.phase",
      FT_BOOLEAN, 16, TFS (&ht_info_pco_phase_flag), 0x0800, "", HFILL }},

	{&ht_info_reserved_3,
     {"Reserved", "wlan_mgt.ht.info.reserved3",
      FT_UINT16, BASE_HEX, NULL, 0xf000, "", HFILL }},

	{&ht_basic_mcs_set,
     {"Bitfield", "wlan_mgt.ht.info.basicmcsset",
      FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_secondary_channel_offset,
     {"Secondary Channel Offset", "wlan_mgt.secchanoffset",
      FT_UINT8, BASE_HEX, VALS (&hf_tag_secondary_channel_offset_flags), 0,
      "", HFILL }},


	/*** Start: Measurement Request Tag  - Dustin Johnson***/
	{&hf_tag_measure_request_measurement_token,
     {"Measurement Token", "wlan_mgt.measure.req.measuretoken",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_request_mode,
     {"Measurement Request Mode", "wlan_mgt.measure.req.reqmode",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_request_mode_reserved1,
     {"Reserved", "wlan_mgt.measure.req.reqmode.reserved1",
      FT_UINT8, BASE_HEX, NULL, 0x01, "", HFILL }},

	{&hf_tag_measure_request_mode_enable,
     {"Measurement Request Mode Field", "wlan_mgt.measure.req.reqmode.enable",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_enable_flag), 0x02, "", HFILL }},

	{&hf_tag_measure_request_mode_request,
     {"Measurement Reports", "wlan_mgt.measure.req.reqmode.request",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_acc_not_acc), 0x04, "", HFILL }},

	{&hf_tag_measure_request_mode_report,
     {"Autonomous Measurement Reports", "wlan_mgt.measure.req.reqmode.report",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_acc_not_acc), 0x08, "", HFILL }},

	{&hf_tag_measure_request_mode_reserved2,
     {"Reserved", "wlan_mgt.measure.req.reqmode.reserved2",
      FT_UINT8, BASE_HEX, NULL, 0xf0, "", HFILL }},

	{&hf_tag_measure_request_type,
     {"Measurement Request Type", "wlan_mgt.measure.req.reqtype",
      FT_UINT8, BASE_HEX, VALS (&hf_tag_measure_request_type_flags), 0x00, "", HFILL }},

	{&hf_tag_measure_request_channel_number,
     {"Measurement Channel Number", "wlan_mgt.measure.req.channelnumber",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_request_start_time,
     {"Measurement Start Time", "wlan_mgt.measure.req.starttime",
      FT_UINT64, BASE_HEX, NULL, 0xffffffff, "", HFILL }},

	{&hf_tag_measure_request_duration,
     {"Measurement Duration", "wlan_mgt.measure.req.channelnumber",
      FT_UINT16, BASE_HEX, NULL, 0xffff, "", HFILL }},

	{&hf_tag_measure_request_regulatory_class,
     {"Measurement Channel Number", "wlan_mgt.measure.req.regclass",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_request_randomization_interval,
     {"Randomization Interval", "wlan_mgt.measure.req.randint",
      FT_UINT16, BASE_HEX, NULL, 0xffff, "", HFILL }},



	{&hf_tag_measure_request_measurement_mode,
     {"Measurement Mode", "wlan_mgt.measure.req.measurementmode",
      FT_UINT8, BASE_HEX, VALS(&hf_tag_measure_request_measurement_mode_flags), 0xff, "", HFILL }},

	{&hf_tag_measure_request_bssid,
     {"BSSID", "wlan_mgt.measure.req.bssid",
      FT_ETHER, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_measure_request_reporting_condition,
     {"Reporting Condition", "wlan_mgt.measure.req.repcond",
      FT_UINT8, BASE_HEX, VALS(&hf_tag_measure_request_reporting_condition_flags), 0xff, "", HFILL }},

	{&hf_tag_measure_request_threshold_offset_unsigned,
     {"Threshold/Offset", "wlan_mgt.measure.req.threshold",
      FT_UINT8, BASE_HEX, 0, 0xff, "", HFILL }},

	{&hf_tag_measure_request_threshold_offset_signed,
     {"Threshold/Offset", "wlan_mgt.measure.req.threshold",
      FT_INT8, BASE_HEX, 0, 0xff, "", HFILL }},

	{&hf_tag_measure_request_report_mac,
     {"MAC on wich to gather data", "wlan_mgt.measure.req.reportmac",
      FT_ETHER, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_measure_request_group_id,
     {"Group ID", "wlan_mgt.measure.req.groupid",
      FT_INT8, BASE_HEX, VALS(&hf_tag_measure_request_group_id_flags), 0xff, "", HFILL }},

    /*** End: Measurement Request Tag  - Dustin Johnson***/

    /*** Start: Measurement Report Tag  - Dustin Johnson***/
	{&hf_tag_measure_report_measurement_token,
     {"Measurement Token", "wlan_mgt.measure.req.clr",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_report_mode,
     {"Measurement Report Mode", "wlan_mgt.measure.req.clr",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_report_mode_late,
     {"Measurement Report Mode Field", "wlan_mgt.measure.rep.repmode.late",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_enable_flag), 0x01, "", HFILL }},

	{&hf_tag_measure_report_mode_incapable,
     {"Measurement Reports", "wlan_mgt.measure.rep.repmode.incapable",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_acc_not_acc), 0x02, "", HFILL }},

	{&hf_tag_measure_report_mode_refused,
     {"Autonomous Measurement Reports", "wlan_mgt.measure.rep.repmode.refused",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_acc_not_acc), 0x04, "", HFILL }},

	{&hf_tag_measure_report_mode_reserved,
     {"Reserved", "wlan_mgt.measure.rep.repmode.reserved",
      FT_UINT8, BASE_HEX, NULL, 0xf8, "", HFILL }},

	{&hf_tag_measure_report_type,
     {"Measurement Report Type", "wlan_mgt.measure.rep.reptype",
      FT_UINT8, BASE_HEX, VALS (&hf_tag_measure_report_type_flags), 0x00, "", HFILL }},

	{&hf_tag_measure_report_channel_number,
     {"Measurement Channel Number", "wlan_mgt.measure.rep.channelnumber",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_report_start_time,
     {"Measurement Start Time", "wlan_mgt.measure.rep.starttime",
      FT_UINT64, BASE_HEX, NULL, 0xffffffff, "", HFILL }},

	{&hf_tag_measure_report_duration,
     {"Measurement Duration", "wlan_mgt.measure.rep.channelnumber",
      FT_UINT16, BASE_HEX, NULL, 0xffff, "", HFILL }},

	{&hf_tag_measure_basic_map_field,
     {"Map Field", "wlan_mgt.measure.rep.mapfield",
      FT_UINT8, BASE_HEX, NULL, 0xff, "", HFILL }},

	{&hf_tag_measure_map_field_bss,
     {"BSS", "wlan_mgt.measure.rep.repmode.mapfield.bss",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_map_field_bss_flag), 0x01, "", HFILL }},

	{&hf_tag_measure_map_field_odfm,
     {"Orthogonal Frequencey Division Multiplexing (ODFM) Preamble", "wlan_mgt.measure.rep.repmode.mapfield.bss",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_detected_not_detected), 0x02, "", HFILL }},

	{&hf_tag_measure_map_field_unident_signal,
     {"Unidentified Signal", "wlan_mgt.measure.rep.repmode.mapfield.unidentsig",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_detected_not_detected), 0x04, "", HFILL }},

	{&hf_tag_measure_map_field_radar,
     {"Radar", "wlan_mgt.measure.rep.repmode.mapfield.radar",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_detected_not_detected), 0x08, "", HFILL }},

	{&hf_tag_measure_map_field_unmeasured,
     {"Unmeasured", "wlan_mgt.measure.rep.repmode.mapfield.unmeasured",
      FT_BOOLEAN, 8, TFS (&hf_tag_measure_true_false), 0x10, "", HFILL }},

	{&hf_tag_measure_map_field_reserved,
     {"Reserved", "wlan_mgt.measure.rep.repmode.mapfield.reserved",
      FT_UINT8, BASE_HEX, NULL, 0xe0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report,
     {"RPI Histogram Report", "",
      FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_0,
     {"RPI 0 Density", "wlan_mgt.measure.rep.rpi.rpi0density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_1,
     {"RPI 1 Density", "wlan_mgt.measure.rep.rpi.rpi1density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_2,
     {"RPI 2 Density", "wlan_mgt.measure.rep.rpi.rpi2density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_3,
     {"RPI 3 Density", "wlan_mgt.measure.rep.rpi.rpi3density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_4,
     {"RPI 4 Density", "wlan_mgt.measure.rep.rpi.rpi4density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_5,
     {"RPI 5 Density", "wlan_mgt.measure.rep.rpi.rpi5density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_6,
     {"RPI 6 Density", "wlan_mgt.measure.rep.rpi.rpi6density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_rpi_histogram_report_7,
     {"RPI 7 Density", "wlan_mgt.measure.rep.rpi.rpi7density",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_regulatory_class,
     {"Regulatory Class", "wlan_mgt.measure.rep.regclass",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_channel_load,
     {"Channel Load", "wlan_mgt.measure.rep.chanload",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_frame_info,
     {"Reported Frame Information", "wlan_mgt.measure.rep.frameinfo",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_frame_info_phy_type,
     {"Condensed PHY", "wlan_mgt.measure.rep.frameinfo.phytype",
      FT_UINT8, BASE_HEX, NULL, 0x7F, "", HFILL }},

	{&hf_tag_measure_report_frame_info_frame_type,
     {"Reported Frame Type", "wlan_mgt.measure.rep.frameinfo.frametype",
      FT_UINT8, BASE_HEX, TFS(&hf_tag_measure_report_frame_info_frame_type_flag), 0x80, "", HFILL }},

	{&hf_tag_measure_report_rcpi,
     {"Received Channel Power Indicator (RCPI)", "wlan_mgt.measure.rep.rcpi",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_rsni,
     {"Received Signal to Noise Indicator (RSNI)", "wlan_mgt.measure.rep.rsni",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_bssid,
     {"BSSID Being Reported", "wlan_mgt.measure.rep.bssid",
      FT_ETHER, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_ant_id,
     {"Antenna ID", "wlan_mgt.measure.rep.antid",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_measure_report_parent_tsf,
     {"Parent TSF", "wlan_mgt.measure.rep.parenttsf",
      FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	/*** End: Measurement Report Tag  - Dustin Johnson***/

	/*** Begin: Extended Capabilities Tag - Dustin Johnson ***/
	{&hf_tag_extended_capabilities,
     {"HT Information Exchange Support", "wlan_mgt.extcap.infoexchange",
      FT_UINT8, BASE_HEX, TFS(&hf_tag_extended_capabilities_flag), 0xff, "", HFILL }},
	/*** End: Extended Capabilities Tag - Dustin Johnson ***/

	/*** Begin: Neighbor Report Tag - Dustin Johnson ***/
	{&hf_tag_neighbor_report_bssid,
     {"BSSID", "wlan_mgt.nreport.bssid",
      FT_ETHER, BASE_NONE, NULL, 0, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info,
     {"BSSID Information", "wlan_mgt.nreport.bssid.info",
      FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_reachability,
     {"Reachability", "wlan_mgt.nreport.bssid.info.reachability",
      FT_UINT16, BASE_HEX, NULL, 0x0003, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_security,
     {"Security", "wlan_mgt.nreport.bssid.info.security",
      FT_UINT16, BASE_HEX, NULL, 0x0004, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_key_scope,
     {"Key Scope", "wlan_mgt.nreport.bssid.info.keyscope",
      FT_UINT16, BASE_HEX, NULL, 0x0008, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_spec_mng,
     {"Capability: Spectrum Management", "wlan_mgt.nreport.bssid.info.capability.specmngt",
      FT_UINT16, BASE_HEX, NULL, 0x0010, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_qos,
     {"Capability: QoS", "wlan_mgt.nreport.bssid.info.capability.qos",
      FT_UINT16, BASE_HEX, NULL, 0x0020, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_apsd,
     {"Capability: APSD", "wlan_mgt.nreport.bssid.info.capability.apsd",
      FT_UINT16, BASE_HEX, NULL, 0x0040, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_radio_msnt,
     {"Capability: Radio Measurement", "wlan_mgt.nreport.bssid.info.capability.radiomsnt",
      FT_UINT16, BASE_HEX, NULL, 0x0080, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_dback,
     {"Capability: Delayed Block Ack", "wlan_mgt.nreport.bssid.info.capability.dback",
      FT_UINT16, BASE_HEX, NULL, 0x0100, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_capability_iback,
     {"Capability: Immediate Block Ack", "wlan_mgt.nreport.bssid.info.capability.iback",
      FT_UINT16, BASE_HEX, NULL, 0x0200, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_mobility_domain,
     {"Mobility Domain", "wlan_mgt.nreport.bssid.info.mobilitydomain",
      FT_UINT16, BASE_HEX, NULL, 0x0400, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_high_throughput,
     {"High Throughput", "wlan_mgt.nreport.bssid.info.hthoughput",
      FT_UINT16, BASE_HEX, NULL, 0x0800, "", HFILL }},

	{&hf_tag_neighbor_report_bssid_info_reserved,
     {"Reserved", "wlan_mgt.nreport.bssid.info.reserved",
      FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_neighbor_report_reg_class,
     {"Regulatory Class", "wlan_mgt.nreport.regclass",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_neighbor_report_channel_number,
     {"Channel Number", "wlan_mgt.nreport.channumber",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_neighbor_report_phy_type,
     {"PHY Type", "wlan_mgt.nreport.phytype",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},
	/*** End: Neighbor Report Tag - Dustin Johnson ***/

	/*** Begin: Extended Channel Switch Announcement Tag - Dustin Johnson ***/
	{&hf_tag_ext_channel_switch_announcement_switch_mode,
     {"Channel Switch Mode", "wlan_mgt.extchanswitch.switchmode",
      FT_UINT8, BASE_HEX, VALS (&hf_tag_ext_channel_switch_announcement_switch_mode_flags), 0, "", HFILL }},

	{&hf_tag_ext_channel_switch_announcement_new_reg_class,
     {"New Regulatory Class", "wlan_mgt.extchanswitch.new.regclass",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_ext_channel_switch_announcement_new_chan_number,
     {"New Channel Number", "wlan_mgt.extchanswitch.new.channumber",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_ext_channel_switch_announcement_switch_count,
     {"Channel Switch Count", "wlan_mgt.extchanswitch.switchcount",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},
	/*** End: Extended Channel Switch Announcement Tag - Dustin Johnson ***/

	/*** Begin: Supported Regulatory Classes Tag - Dustin Johnson ***/
	{&hf_tag_supported_reg_classes_current,
     {"Current Regulatory Class", "wlan_mgt.supregclass.current",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

	{&hf_tag_supported_reg_classes_alternate,
     {"Alternate Regulatory Classes", "",
      FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
	/*** End: Supported Regulatory Classes Tag - Dustin Johnson ***/

    {&hf_aironet_ie_type,
     {"Aironet IE type", "wlan_mgt.aironet.type",
      FT_UINT8, BASE_DEC, VALS(aironet_ie_type_vals), 0, "", HFILL }},

    {&hf_aironet_ie_version,
     {"Aironet IE CCX version?", "wlan_mgt.aironet.version",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_aironet_ie_data,
      { "Aironet IE data", "wlan_mgt.aironet.data",
        FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},

    {&hf_qbss_version,
     {"QBSS Version", "wlan_mgt.qbss.version",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss_scount,
     {"Station Count", "wlan_mgt.qbss.scount",
      FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss_cu,
     {"Channel Utilization", "wlan_mgt.qbss.cu",
       FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss_adc,
     {"Available Admission Capabilities", "wlan_mgt.qbss.adc",
     FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss2_cu,
     {"Channel Utilization", "wlan_mgt.qbss2.cu",
       FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss2_gl,
     {"G.711 CU Quantum", "wlan_mgt.qbss2.glimit",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss2_cal,
     {"Call Admission Limit", "wlan_mgt.qbss2.cal",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_qbss2_scount,
     {"Station Count", "wlan_mgt.qbss2.scount",
      FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_aironet_ie_qos_unk1,
     {"Aironet IE QoS unknown1", "wlan_mgt.aironet.qos.unk1",
      FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }},

    {&hf_aironet_ie_qos_paramset,
     {"Aironet IE QoS paramset", "wlan_mgt.aironet.qos.paramset",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    {&hf_aironet_ie_qos_val,
     {"Aironet IE QoS valueset", "wlan_mgt.aironet.qos.val",
      FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }},

    {&hf_ts_info,
     {"TS Info", "wlan_mgt.ts_info",
      FT_UINT24, BASE_HEX, NULL, 0, "TS Info field", HFILL }},

    {&hf_tsinfo_type,
     {"Traffic Type", "wlan_mgt.ts_info.type", FT_UINT8, BASE_DEC,
      VALS (&tsinfo_type), 0, "TS Info Traffic Type", HFILL }},

    {&hf_tsinfo_tsid,
     {"TSID", "wlan_mgt.ts_info.tsid",
      FT_UINT8, BASE_DEC, NULL, 0, "TS Info TSID", HFILL }},

    {&hf_tsinfo_dir,
     {"Direction", "wlan_mgt.ts_info.dir", FT_UINT8, BASE_DEC,
      VALS (&tsinfo_direction), 0, "TS Info Direction", HFILL }},

    {&hf_tsinfo_access,
     {"Access Policy", "wlan_mgt.ts_info.dir", FT_UINT8, BASE_DEC,
      VALS (&tsinfo_access), 0, "TS Info Access Policy", HFILL }},

    {&hf_tsinfo_agg,
     {"Aggregation", "wlan_mgt.ts_info.agg", FT_UINT8, BASE_DEC,
      NULL, 0, "TS Info Access Policy", HFILL }},

    {&hf_tsinfo_apsd,
     {"APSD", "wlan_mgt.ts_info.apsd", FT_UINT8, BASE_DEC,
      NULL, 0, "TS Info APSD", HFILL }},

    {&hf_tsinfo_up,
     {"UP", "wlan_mgt.ts_info.up", FT_UINT8, BASE_DEC,
      VALS (&qos_up), 0, "TS Info User Priority", HFILL }},

    {&hf_tsinfo_ack,
     {"Ack Policy", "wlan_mgt.ts_info.ack", FT_UINT8, BASE_DEC,
      VALS (&ack_policy), 0, "TS Info Ack Policy", HFILL }},

    {&hf_tsinfo_sched,
     {"Schedule", "wlan_mgt.ts_info.sched", FT_UINT8, BASE_DEC,
      NULL, 0, "TS Info Schedule", HFILL }},

    {&tspec_nor_msdu,
     {"Normal MSDU Size", "wlan_mgt.tspec.nor_msdu",
      FT_UINT16, BASE_DEC, NULL, 0, "Normal MSDU Size", HFILL }},

    {&tspec_max_msdu,
     {"Maximum MSDU Size", "wlan_mgt.tspec.max_msdu",
      FT_UINT16, BASE_DEC, NULL, 0, "Maximum MSDU Size", HFILL }},

    {&tspec_min_srv,
     {"Minimum Service Interval", "wlan_mgt.tspec.min_srv",
      FT_UINT32, BASE_DEC, NULL, 0, "Minimum Service Interval", HFILL }},

    {&tspec_max_srv,
     {"Maximum Service Interval", "wlan_mgt.tspec.max_srv",
      FT_UINT32, BASE_DEC, NULL, 0, "Maximum Service Interval", HFILL }},

    {&tspec_inact_int,
     {"Inactivity Interval", "wlan_mgt.tspec.inact_int",
      FT_UINT32, BASE_DEC, NULL, 0, "Inactivity Interval", HFILL }},

    {&tspec_susp_int,
     {"Suspension Interval", "wlan_mgt.tspec.susp_int",
      FT_UINT32, BASE_DEC, NULL, 0, "Suspension Interval", HFILL }},

    {&tspec_srv_start,
     {"Service Start Time", "wlan_mgt.tspec.srv_start",
      FT_UINT32, BASE_DEC, NULL, 0, "Service Start Time", HFILL }},

    {&tspec_min_data,
     {"Minimum Data Rate", "wlan_mgt.tspec.min_data",
      FT_UINT32, BASE_DEC, NULL, 0, "Minimum Data Rate", HFILL }},

    {&tspec_mean_data,
     {"Mean Data Rate", "wlan_mgt.tspec.mean_data",
      FT_UINT32, BASE_DEC, NULL, 0, "Mean Data Rate", HFILL }},

    {&tspec_peak_data,
     {"Peak Data Rate", "wlan_mgt.tspec.peak_data",
      FT_UINT32, BASE_DEC, NULL, 0, "Peak Data Rate", HFILL }},

    {&tspec_burst_size,
     {"Burst Size", "wlan_mgt.tspec.burst_size",
      FT_UINT32, BASE_DEC, NULL, 0, "Burst Size", HFILL }},

    {&tspec_delay_bound,
     {"Delay Bound", "wlan_mgt.tspec.delay_bound",
      FT_UINT32, BASE_DEC, NULL, 0, "Delay Bound", HFILL }},

    {&tspec_min_phy,
     {"Minimum PHY Rate", "wlan_mgt.tspec.min_phy",
      FT_UINT32, BASE_DEC, NULL, 0, "Minimum PHY Rate", HFILL }},

    {&tspec_surplus,
     {"Surplus Bandwidth Allowance", "wlan_mgt.tspec.surplus",
      FT_UINT16, BASE_DEC, NULL, 0, "Surplus Bandwidth Allowance", HFILL }},

    {&tspec_medium,
     {"Medium Time", "wlan_mgt.tspec.medium",
      FT_UINT16, BASE_DEC, NULL, 0, "Medium Time", HFILL }},

    {&ts_delay,
     {"TS Delay", "wlan_mgt.ts_delay",
      FT_UINT32, BASE_DEC, NULL, 0, "TS Delay", HFILL }},

    {&hf_class_type,
     {"Classifier Type", "wlan_mgt.tclas.class_type", FT_UINT8, BASE_DEC,
      VALS (classifier_type), 0, "Classifier Type", HFILL }},

    {&hf_class_mask,
     {"Classifier Mask", "wlan_mgt.tclas.class_mask", FT_UINT8, BASE_HEX,
      NULL, 0, "Classifier Mask", HFILL }},

    {&hf_ether_type,
     {"Type", "wlan_mgt.tclas.params.type", FT_UINT8, BASE_DEC,
      NULL, 0, "Classifier Parameters Ethernet Type", HFILL }},

    {&hf_tclas_process,
     {"Processing", "wlan_mgt.tclas_proc.processing", FT_UINT8, BASE_DEC,
      VALS (tclas_process), 0, "TCLAS Porcessing", HFILL }},

    {&hf_sched_info,
     {"Schedule Info", "wlan_mgt.sched.sched_info",
      FT_UINT16, BASE_HEX, NULL, 0, "Schedule Info field", HFILL }},

    {&hf_sched_srv_start,
     {"Service Start Time", "wlan_mgt.sched.srv_start",
      FT_UINT32, BASE_HEX, NULL, 0, "Service Start Time", HFILL }},

    {&hf_sched_srv_int,
     {"Service Interval", "wlan_mgt.sched.srv_int",
      FT_UINT32, BASE_HEX, NULL, 0, "Service Interval", HFILL }},

    {&hf_sched_spec_int,
     {"Specification Interval", "wlan_mgt.sched.spec_int",
      FT_UINT16, BASE_HEX, NULL, 0, "Specification Interval", HFILL }},

    {&hf_action,
     {"Action", "wlan_mgt.fixed.action",
      FT_UINT16, BASE_HEX, NULL, 0, "Action", HFILL }},

    {&cf_version,
     {"IP Version", "wlan_mgt.tclas.params.version",
      FT_UINT8, BASE_DEC, NULL, 0, "IP Version", HFILL }},

    {&cf_ipv4_src,
     {"IPv4 Src Addr", "wlan_mgt.tclas.params.ipv4_src",
      FT_IPv4, BASE_NONE, NULL, 0, "IPv4 Src Addr", HFILL }},

    {&cf_ipv4_dst,
     {"IPv4 Dst Addr", "wlan_mgt.tclas.params.ipv4_dst",
      FT_IPv4, BASE_NONE, NULL, 0, "IPv4 Dst Addr", HFILL }},

    {&cf_src_port,
     {"Source Port", "wlan_mgt.tclas.params.src_port",
      FT_UINT16, BASE_DEC, NULL, 0, "Source Port", HFILL }},

    {&cf_dst_port,
     {"Destination Port", "wlan_mgt.tclas.params.dst_port",
      FT_UINT16, BASE_DEC, NULL, 0, "Destination Port", HFILL }},

    {&cf_dscp,
     {"DSCP", "wlan_mgt.tclas.params.dscp",
      FT_UINT8, BASE_HEX, NULL, 0, "IPv4 DSCP Field", HFILL }},

    {&cf_protocol,
     {"Protocol", "wlan_mgt.tclas.params.protocol",
      FT_UINT8, BASE_HEX, NULL, 0, "IPv4 Protocol", HFILL }},

    {&cf_ipv6_src,
     {"IPv6 Src Addr", "wlan_mgt.tclas.params.ipv6_src",
      FT_IPv6, BASE_NONE, NULL, 0, "IPv6 Src Addr", HFILL }},

    {&cf_ipv6_dst,
     {"IPv6 Dst Addr", "wlan_mgt.tclas.params.ipv6_dst",
      FT_IPv6, BASE_NONE, NULL, 0, "IPv6 Dst Addr", HFILL }},

    {&cf_flow,
     {"Flow Label", "wlan_mgt.tclas.params.flow",
      FT_UINT24, BASE_HEX, NULL, 0, "IPv6 Flow Label", HFILL }},

    {&cf_tag_type,
     {"802.1Q Tag Type", "wlan_mgt.tclas.params.tag_type",
      FT_UINT16, BASE_HEX, NULL, 0, "802.1Q Tag Type", HFILL }},

    /* HT Control (+HTC) */
    {&hf_htc,
     {"HT Control (+HTC)", "wlan_mgt.htc",
      FT_UINT32, BASE_HEX, NULL, 0x0, "High Throughput Control (+HTC)", HFILL }},
    {&hf_htc_lac,
     {"+HTC LAC", "wlan_mgt.htc.lac",
      FT_UINT16, BASE_HEX, NULL, 0x0, "High Throughput Control Link Adaptation Control", HFILL }},
    {&hf_htc_lac_trq,
     {"+HTC LAC TRQ", "wlan_mgt.htc.lac.trq",
      FT_BOOLEAN, 16, TFS(&htc_lac_trq_flag), 0x0001, "High Throughput Control Link Adaptation Control Sounding Request", HFILL }},
    {&hf_htc_lac_mai_aseli,
     {"+HTC LAC MAI ASELI", "wlan_mgt.htc.lac.mai.aseli",
      FT_BOOLEAN, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control MAI Antenna Selection Indication", HFILL }},
    {&hf_htc_lac_mai_mrq,
     {"+HTC LAC MAI MRQ", "wlan_mgt.htc.lac.mai.mrq",
      FT_BOOLEAN, 4, TFS(&htc_lac_mai_mrq_flag), 0x04, "High Throughput Control Link Adaptation Control MAI MCS Request", HFILL }},
    {&hf_htc_lac_mai_msi,
     {"+HTC LAC MAI MSI", "wlan_mgt.htc.lac.mai.msi",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control MAI MCS Request Sequence Identifier", HFILL }},
    {&hf_htc_lac_mfsi,
     {"+HTC LAC MFSI", "wlan_mgt.htc.lac.mfsi",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control MFB Sequence Identifier", HFILL }},
    {&hf_htc_lac_asel_command,
     {"+HTC LAC ASEL Command", "wlan_mgt.htc.lac.asel.command",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control Antenna Selection Command", HFILL }},
    {&hf_htc_lac_asel_data,
     {"+HTC LAC ASEL Command", "wlan_mgt.htc.lac.asel.data",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control Antenna Selection Data", HFILL }},
    {&hf_htc_lac_mfb,
     {"+HTC LAC MFG", "wlan_mgt.htc.lac.mfb",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Link Adaptation Control MCS Feedback", HFILL }},
    {&hf_htc_cal_pos,
     {"+HTC Calibration Position", "wlan_mgt.htc.cal.pos",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Calibration Position", HFILL }},
    {&hf_htc_cal_seq,
     {"+HTC Calibration Sequence", "wlan_mgt.htc.cal.seq",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control Calibration Sequence", HFILL }},
    {&hf_htc_csi_steering,
     {"+HTC CSI/Steering", "wlan_mgt.htc.csi_steering",
      FT_UINT8, BASE_DEC, NULL, 0, "High Throughput Control CSI/Steering", HFILL }},
    {&hf_htc_ndp_announcement,
     {"+HTC NDP Announcement", "wlan_mgt.htc.ndp_announcement",
      FT_BOOLEAN, BASE_DEC, NULL, 0, "High Throughput Control NDP Announcement", HFILL }},
    {&hf_htc_ac_constraint,
     {"+HTC AC Constraint", "wlan_mgt.htc.ac_constraint",
      FT_BOOLEAN, BASE_DEC, NULL, 0, "High Throughput Control AC Constraint", HFILL }},
    {&hf_htc_rdg_more_ppdu,
     {"+HTC RDG/More PPDU", "wlan_mgt.htc.rdg_more_ppdu",
      FT_BOOLEAN, BASE_DEC, NULL, 0, "High Throughput Control RDG/More PPDU", HFILL }},

  };

  static hf_register_info agregate_fields[] = {

		{ &amsdu_msdu_header_text,
		{ "MAC Service Data Unit (MSDU)",	"wlan_agregate.msduheader", FT_UINT16, BASE_DEC, 0,
			0x0000, "MAC Service Data Unit (MSDU)", HFILL }},
	};

  static gint *tree_array[] = {
    &ett_80211,
    &ett_fc_tree,
    &ett_proto_flags,
    &ett_fragments,
    &ett_fragment,
    &ett_block_ack,
    &ett_80211_mgt,
    &ett_fixed_parameters,
    &ett_tagged_parameters,
    &ett_qos_parameters,
    &ett_qos_ps_buf_state,
    &ett_wep_parameters,
    &ett_cap_tree,
    &ett_rsn_cap_tree,
    &ett_ht_cap_tree,
    &ett_cntrl_wrapper_fc,
    &ett_ht_info_delimiter1_tree,
    &ett_ht_info_delimiter2_tree,
    &ett_ht_info_delimiter3_tree,
    &ett_tag_measure_request_tree,
    &ett_tag_neighbor_report_bssid_info_tree,
    &ett_tag_neighbor_report_bssid_info_capability_tree,
    &ett_tag_neighbor_report_sub_tag_tree,
    &ett_ampduparam_tree,
    &ett_mcsset_tree,
    &ett_htex_cap_tree,
    &ett_txbf_tree,
    &ett_hta_cap_tree,
    &ett_hta_cap1_tree,
    &ett_hta_cap2_tree,
    &ett_htc_tree,
    &ett_antsel_tree,
    &ett_80211_mgt_ie,
    &ett_tsinfo_tree,
    &ett_sched_tree,
    &ett_fcs
  };
  module_t *wlan_module;


  proto_aggregate = proto_register_protocol("IEEE 802.11 wireless LAN agregate frame",
	    "IEEE 802.11 Agregate Data", "wlan_agregate");
  proto_register_field_array(proto_aggregate, agregate_fields, array_length(agregate_fields));
  proto_wlan = proto_register_protocol ("IEEE 802.11 wireless LAN",
					"IEEE 802.11", "wlan");
  proto_register_field_array (proto_wlan, hf, array_length (hf));
  proto_wlan_mgt = proto_register_protocol ("IEEE 802.11 wireless LAN management frame",
					"802.11 MGT", "wlan_mgt");
  proto_register_field_array (proto_wlan_mgt, ff, array_length (ff));
  proto_register_subtree_array (tree_array, array_length (tree_array));

  register_dissector("wlan", dissect_ieee80211, proto_wlan);
  register_dissector("wlan_fixed", dissect_ieee80211_fixed, proto_wlan);
  register_dissector("wlan_bsfc", dissect_ieee80211_bsfc, proto_wlan);
  register_dissector("wlan_datapad", dissect_ieee80211_datapad, proto_wlan);
  register_dissector("wlan_radio", dissect_ieee80211_radio, proto_wlan);
  register_init_routine(wlan_defragment_init);

  wlan_tap = register_tap("wlan");

  /* Register configuration options */
  wlan_module = prefs_register_protocol(proto_wlan, init_wepkeys);
  prefs_register_bool_preference(wlan_module, "defragment",
	"Reassemble fragmented 802.11 datagrams",
	"Whether fragmented 802.11 datagrams should be reassembled",
	&wlan_defragment);

  prefs_register_bool_preference(wlan_module, "check_fcs",
				 "Assume packets have FCS",
				 "Some 802.11 cards include the FCS at the end of a packet, others do not.",
				 &wlan_check_fcs);

  /* Davide Schiera (2006-11-26): changed "WEP bit" in "Protection bit"		*/
  /*		(according to the document IEEE Std 802.11i-2004)							*/
  prefs_register_enum_preference(wlan_module, "ignore_wep",
		"Ignore the Protection bit",
		"Some 802.11 cards leave the Protection bit set even though the packet is decrypted, "
		"and some also leave the IV (initialization vector).",
				 &wlan_ignore_wep, wlan_ignore_wep_options, TRUE);

#ifndef USE_ENV

  prefs_register_obsolete_preference(wlan_module, "wep_keys");

#ifdef HAVE_AIRPDCAP
  /* Davide Schiera (2006-11-26): added reference to WPA/WPA2 decryption		*/
  prefs_register_bool_preference(wlan_module, "enable_decryption",
	"Enable decryption", "Enable WEP and WPA/WPA2 decryption",
	&enable_decryption);
#else
  prefs_register_bool_preference(wlan_module, "enable_decryption",
	"Enable decryption", "Enable WEP decryption",
	&enable_decryption);
#endif

#ifdef HAVE_AIRPDCAP
  prefs_register_static_text_preference(wlan_module, "info_decryption_key",
	  "Key examples: 01:02:03:04:05 (40/64-bit WEP),\n"
	  "010203040506070809101111213 (104/128-bit WEP),\n"
	  "wpa-pwd:MyPassword[:MyAP] (WPA + plaintext password [+ SSID]),\n"
	  "wpa-psk:0102030405...6061626364 (WPA + 256-bit key).  "
	  "Invalid keys will be ignored.",
	  "This is just a static text");
#else
  prefs_register_static_text_preference(wlan_module, "info_decryption_key",
	  "Key examples: 01:02:03:04:05 (40/64-bit WEP),\n"
	  "010203040506070809101111213 (104/128-bit WEP)",
	  "This is just a static text");
#endif

  for (i = 0; i < MAX_ENCRYPTION_KEYS; i++) {
    key_name = g_string_new("");
    key_title = g_string_new("");
    key_desc = g_string_new("");
    wep_keystr[i] = NULL;
    /* prefs_register_*_preference() expects unique strings, so
     * we build them using g_string_sprintf and just leave them
     * allocated. */
#ifdef HAVE_AIRPDCAP
  g_string_sprintf(key_name, "wep_key%d", i + 1);
  g_string_sprintf(key_title, "Key #%d", i + 1);
  /* Davide Schiera (2006-11-26): modified keys input tooltip					*/
  g_string_sprintf(key_desc,
	"Key #%d string can be:"
	"   <wep hexadecimal key>;"
	"   wep:<wep hexadecimal key>;"
	"   wpa-pwd:<passphrase>[:<ssid>];"
	"   wpa-psk:<wpa hexadecimal key>", i + 1);
#else
    g_string_sprintf(key_name, "wep_key%d", i + 1);
    g_string_sprintf(key_title, "WEP key #%d", i + 1);
    g_string_sprintf(key_desc, "WEP key #%d bytes in hexadecimal (A:B:C:D:E) "
	    "[40bit], (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key "
	    "length you're using", i + 1);
#endif

    prefs_register_string_preference(wlan_module, key_name->str,
	    key_title->str, key_desc->str, (const char **) &wep_keystr[i]);

    g_string_free(key_name, FALSE);
    g_string_free(key_title, FALSE);
    g_string_free(key_desc, FALSE);
  }
#endif
}

void
proto_reg_handoff_ieee80211(void)
{
  dissector_handle_t ieee80211_handle;
  dissector_handle_t ieee80211_radio_handle;

  /*
   * Get handles for the LLC, IPX and Ethernet  dissectors.
   */
  llc_handle = find_dissector("llc");
  ipx_handle = find_dissector("ipx");
  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  data_handle = find_dissector("data");

  ieee80211_handle = find_dissector("wlan");
  dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11, ieee80211_handle);
  ieee80211_radio_handle = create_dissector_handle(dissect_ieee80211_radio,
						   proto_wlan);
  dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
		ieee80211_radio_handle);
  dissector_add("ethertype", ETHERTYPE_CENTRINO_PROMISC, ieee80211_handle);
}

#ifdef	HAVE_AIRPDCAP
/*	Davide Schiera (2006-11-26): this function will try to decrypt with WEP or	*/
/*		WPA and return a tvb to the caller to add a new tab. It returns the		*/
/*		algorithm used for decryption (WEP, TKIP, CCMP) and the header and		*/
/*		trailer lengths.																			*/
static tvbuff_t *
try_decrypt(tvbuff_t *tvb, guint32 offset, guint32 len, guint8 *algorithm, guint32 *sec_header, guint32 *sec_trailer) {
	const guint8 *enc_data;
	guint8 *tmp = NULL;
	tvbuff_t *decr_tvb = NULL;
	size_t dec_caplen;
	guchar dec_data[AIRPDCAP_MAX_CAPLEN];
	AIRPDCAP_KEY_ITEM used_key;

	if (!enable_decryption)
		return NULL;

	/* get the entire packet																	*/
	enc_data = tvb_get_ptr(tvb, 0, len+offset);

	/*	process packet with AirPDcap															*/
	if (AirPDcapPacketProcess(&airpdcap_ctx, enc_data, len+offset, dec_data, &dec_caplen, &used_key, FALSE, FALSE, FALSE, TRUE)==AIRPDCAP_RET_SUCCESS)
	{
		*algorithm=used_key.KeyType;
		switch (*algorithm) {
			case AIRPDCAP_KEY_TYPE_WEP:
				*sec_header=AIRPDCAP_WEP_HEADER;
				*sec_trailer=AIRPDCAP_WEP_TRAILER;
				break;
			case AIRPDCAP_KEY_TYPE_CCMP:
				*sec_header=AIRPDCAP_RSNA_HEADER;
				*sec_trailer=AIRPDCAP_CCMP_TRAILER;
				break;
			case AIRPDCAP_KEY_TYPE_TKIP:
				*sec_header=AIRPDCAP_RSNA_HEADER;
				*sec_trailer=AIRPDCAP_TKIP_TRAILER;
				break;
			default:
				return NULL;
		}

		/* allocate buffer for decrypted payload											*/
		if ((tmp = g_malloc(dec_caplen-offset)) == NULL)
			return NULL;  /* krap! */
		memcpy(tmp, dec_data+offset, dec_caplen-offset);

		len=dec_caplen-offset;

		/* decrypt successful, let's set up a new data tvb.							*/
		decr_tvb = tvb_new_real_data(tmp, len, len);
		tvb_set_free_cb(decr_tvb, g_free);
		tvb_set_child_real_data_tvbuff(tvb, decr_tvb);
	} else
		g_free(tmp);

	return decr_tvb;
}
/*	Davide Schiera -----------------------------------------------------------	*/
#else

static tvbuff_t *try_decrypt_wep(tvbuff_t *tvb, guint32 offset, guint32 len) {
  const guint8 *enc_data;
  guint8 *tmp = NULL;
  int i;
  tvbuff_t *decr_tvb = NULL;

  if (! enable_decryption)
    return NULL;

  enc_data = tvb_get_ptr(tvb, offset, len);

  if ((tmp = g_malloc(len)) == NULL)
    return NULL;  /* krap! */

  /* try once with the key index in the packet, then look through our list. */
  for (i = 0; i < num_wepkeys; i++) {
    /* copy the encrypted data over to the tmp buffer */
#if 0
    printf("trying %d\n", i);
#endif
    memcpy(tmp, enc_data, len);
    if (wep_decrypt(tmp, len, i) == 0) {

      /* decrypt successful, let's set up a new data tvb. */
      decr_tvb = tvb_new_real_data(tmp, len-8, len-8);
      tvb_set_free_cb(decr_tvb, g_free);
      tvb_set_child_real_data_tvbuff(tvb, decr_tvb);

      break;
    }
  }

  if ((!decr_tvb) && (tmp))    g_free(tmp);

#if 0
  printf("de-wep %p\n", decr_tvb);
#endif

  return decr_tvb;
}
#endif

#ifdef	HAVE_AIRPDCAP
static
void set_airpdcap_keys(void)
{
	guint i = 0;
	AIRPDCAP_KEY_ITEM key;
	PAIRPDCAP_KEYS_COLLECTION keys;
	decryption_key_t* dk = NULL;
	GByteArray *bytes = NULL;
	gboolean res;
	gchar* tmpk = NULL;

	keys=(PAIRPDCAP_KEYS_COLLECTION)g_malloc(sizeof(AIRPDCAP_KEYS_COLLECTION));
	keys->nKeys = 0;

	for(i = 0; i < MAX_ENCRYPTION_KEYS; i++)
	{
		tmpk = g_strdup(wep_keystr[i]);

		dk = parse_key_string(tmpk);

		if(dk != NULL)
		{
			if(dk->type == AIRPDCAP_KEY_TYPE_WEP)
			{
				key.KeyType = AIRPDCAP_KEY_TYPE_WEP;

				bytes = g_byte_array_new();
				res = hex_str_to_bytes(dk->key->str, bytes, FALSE);

				if (dk->key->str && res && bytes->len > 0 && bytes->len <= AIRPDCAP_WEP_KEY_MAXLEN)
				{
					/*
					 * WEP key is correct (well, the can be even or odd, so it is not
					 * a real check, I think... is a check performed somewhere in the
					 * AirPDcap function??? )
					 */
					memcpy(key.KeyData.Wep.WepKey, bytes->data, bytes->len);
					key.KeyData.Wep.WepKeyLen = bytes->len;
					keys->Keys[keys->nKeys] = key;
					keys->nKeys++;
				}
			}
			else if(dk->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
			{
				key.KeyType = AIRPDCAP_KEY_TYPE_WPA_PWD;

				/* XXX - This just lops the end if the key off if it's too long.
				 *       Should we handle this more gracefully? */
				strncpy(key.UserPwd.Passphrase, dk->key->str, AIRPDCAP_WPA_PASSPHRASE_MAX_LEN);

				key.UserPwd.SsidLen = 0;
				if(dk->ssid != NULL && dk->ssid->len <= AIRPDCAP_WPA_SSID_MAX_LEN)
				{
					memcpy(key.UserPwd.Ssid, dk->ssid->data, dk->ssid->len);
					key.UserPwd.SsidLen = dk->ssid->len;
				}

				keys->Keys[keys->nKeys] = key;
				keys->nKeys++;
			}
			else if(dk->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
			{
				key.KeyType = AIRPDCAP_KEY_TYPE_WPA_PMK;

				bytes = g_byte_array_new();
				res = hex_str_to_bytes(dk->key->str, bytes, FALSE);

				/* XXX - Pass the correct array of bytes... */
				if (bytes-> len <= AIRPDCAP_WPA_PMK_LEN) {
					memcpy(key.KeyData.Wpa.Pmk, bytes->data, bytes->len);

					keys->Keys[keys->nKeys] = key;
					keys->nKeys++;
				}
			}
		}
		if(tmpk != NULL) g_free(tmpk);
	}

	/* Now set the keys */
	AirPDcapSetKeys(&airpdcap_ctx,keys->Keys,keys->nKeys);
	g_free(keys);
	if (bytes)
		g_byte_array_free(bytes, TRUE);

}
#endif

#ifndef HAVE_AIRPDCAP
/* de-weps the block.  if successful, buf* will point to the data start. */
static int wep_decrypt(guint8 *buf, guint32 len, int keyidx) {
  guint32 i, j, k, crc, keylen;
  guint8 s[256], key[128], c_crc[4];
  guint8 *dpos, *cpos;

  /* Needs to be at least 8 bytes of payload */
  if (len < 8)
    return -1;

  /* initialize the first bytes of the key from the IV */
  key[0] = buf[0];
  key[1] = buf[1];
  key[2] = buf[2];

  if (keyidx < 0 || keyidx >= num_wepkeys)
    return -1;

  keylen = wep_keylens[keyidx];

  if (keylen == 0)
    return -1;
  if (wep_keys[keyidx] == NULL)
    return -1;

  keylen+=3;  /* add in ICV bytes */

  /* copy the rest of the key over from the designated key */
  memcpy(key+3, wep_keys[keyidx], wep_keylens[keyidx]);

#if 0
  printf("%d: %02x %02x %02x (%d %d) %02x:%02x:%02x:%02x:%02x\n", len, key[0], key[1], key[2], keyidx, keylen, key[3], key[4], key[5], key[6], key[7]);
#endif

  /* set up the RC4 state */
  for (i = 0; i < 256; i++)
    s[i] = i;
  j = 0;
  for (i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % keylen]) & 0xff;
    SSWAP(i,j);
  }

  /* Apply the RC4 to the data, update the CRC32 */
  cpos = buf+4;
  dpos = buf;
  crc = ~0;
  i = j = 0;
  for (k = 0; k < (len -8); k++) {
    i = (i+1) & 0xff;
    j = (j+s[i]) & 0xff;
    SSWAP(i,j);
#if 0
    printf("%d -- %02x ", k, *dpos);
#endif
    *dpos = *cpos++ ^ s[(s[i] + s[j]) & 0xff];
#if 0
    printf("%02x\n", *dpos);
#endif
    crc = crc32_ccitt_table[(crc ^ *dpos++) & 0xff] ^ (crc >> 8);
  }
  crc = ~crc;

  /* now let's check the crc */
  c_crc[0] = crc;
  c_crc[1] = crc >> 8;
  c_crc[2] = crc >> 16;
  c_crc[3] = crc >> 24;

  for (k = 0; k < 4; k++) {
    i = (i + 1) & 0xff;
    j = (j+s[i]) & 0xff;
    SSWAP(i,j);
#if 0
    printf("-- %02x %02x\n", *dpos, c_crc[k]);
#endif
    if ((*cpos++ ^ s[(s[i] + s[j]) & 0xff]) != c_crc[k])
      return -1; /* ICV mismatch */
  }

  return 0;
}
#endif

static void init_wepkeys(void) {
  const char *tmp;
  int i, keyidx;
  GByteArray *bytes;
  gboolean res;

  if (wep_keys) {
    for (i = 0; i < num_wepkeys; i++)
      g_free(wep_keys[i]);
    g_free(wep_keys);
  }

  if (wep_keylens)
    g_free(wep_keylens);

#ifdef USE_ENV
  guint8 *buf;

  tmp = getenv("WIRESHARK_WEPKEYNUM");
  if (!tmp) {
    num_wepkeys = 0;
    return;
  }
  num_wepkeys = atoi(tmp);

  if (num_wepkeys < 1)
    return;
#endif

  /* Figure out how many valid keys we have */
  bytes = g_byte_array_new();
  num_wepkeys = 0;
  for ( i = 0; i < MAX_ENCRYPTION_KEYS; i++) {
    res = hex_str_to_bytes(wep_keystr[i], bytes, FALSE);
    if (wep_keystr[i] && res && bytes-> len > 0) {
      num_wepkeys++;
    }
  }

#ifdef	HAVE_AIRPDCAP
	/*
	* XXX - AirPDcap - That God sends it to us beautiful (che dio ce la mandi bona)
	* The next lines will add a key to the AirPDcap context. The keystring will be added
	* to the old WEP array too, but we don't care, because the packets will come here
	* already decrypted... One of these days we will fix this too
	*/
	set_airpdcap_keys();

	/* END AirPDcap */
#endif

  wep_keys = g_malloc0(num_wepkeys * sizeof(guint8*));
  wep_keylens = g_malloc(num_wepkeys * sizeof(int));

  for (i = 0, keyidx = 0; i < MAX_ENCRYPTION_KEYS && keyidx < num_wepkeys; i++) {
    wep_keys[keyidx] = NULL;
    wep_keylens[keyidx] = 0;

#ifdef USE_ENV
    buf=ep_alloc(128);
    g_snprintf(buf, 128, "WIRESHARK_WEPKEY%d", i+1);
    tmp = getenv(buf);
#else
    tmp = wep_keystr[i];
#endif

    if (tmp) {
#if 0
#ifdef USE_ENV
      printf("%s -- %s\n", buf, tmp);
#else
      printf("%d -- %s\n", i+1, tmp);
#endif
#endif

      if (wep_keys[keyidx]) {
	g_free(wep_keys[keyidx]);
      }

      res = hex_str_to_bytes(tmp, bytes, FALSE);
      if (tmp && res && bytes->len > 0) {
        if (bytes->len > 32) {
	  bytes->len = 32;
	}
	wep_keys[keyidx] = g_malloc0(32 * sizeof(guint8));
	memcpy(wep_keys[keyidx], bytes->data, bytes->len * sizeof(guint8));
	wep_keylens[keyidx] = bytes->len;
	keyidx++;
#if 0
	printf("%d: %d bytes\n", i, bytes->len);
	printf("%d: %s\n", i, bytes_to_str(bytes->data, bytes->len));
#endif
      } else {
#if 0
	printf("res: %d  bytes->len: %d\n", res, bytes->len);
#endif
        g_warning("Could not parse WEP key %d: %s", i + 1, tmp);
      }
    }
  }
  g_byte_array_free(bytes, TRUE);
}
/*
 * This code had been taken from AirSnort crack.c function classify()
 * Permission granted by snax <at> shmoo dot com
 * weak_iv - determine which key byte an iv is useful in resolving
 * parm     - p, pointer to the first byte of an IV
 * return   -  n - this IV is weak for byte n of a WEP key
 *            -1 - this IV is not weak for any key bytes
 *
 * This function tests for IVs that are known to satisfy the criteria
 * for a weak IV as specified in FMS section 7.1
 *
 */
static int
weak_iv(guchar *iv)
{
        guchar sum, k;

        if (iv[1] == 255 && iv[0] > 2 && iv[0] < 16) {
                return iv[0] -3;
        }

        sum = iv[0] + iv[1];
        if (sum == 1) {
                if (iv[2] <= 0x0a) {
                        return iv[2] +2;
                }
                else if (iv[2] == 0xff){
                        return 0;
                }
        }
        k = 0xfe - iv[2];
        if (sum == k  && (iv[2] >= 0xf2 && iv[2] <= 0xfe && iv[2] != 0xfd)){
                return k;
        }
        return -1;
}
