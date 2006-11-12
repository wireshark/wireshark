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

#include <ctype.h>
#include "isprint.h"

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
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
static gboolean wlan_ignore_wep = FALSE;

/* Tables for reassembly of fragments. */
static GHashTable *wlan_fragment_table = NULL;
static GHashTable *wlan_reassembled_table = NULL;

/* Stuff for the WEP decoder */

static gint num_wepkeys = 0;
static gboolean enable_decryption = FALSE;
static guint8 **wep_keys = NULL;
static int *wep_keylens = NULL;
static void init_wepkeys(void);
static int wep_decrypt(guint8 *buf, guint32 len, int key_override);
static tvbuff_t *try_decrypt_wep(tvbuff_t *tvb, guint32 offset, guint32 len);
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
#define IS_TO_DS(x)            ((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          ((x) & FLAG_FROM_DS)
#define HAVE_FRAGMENTS(x)      ((x) & FLAG_MORE_FRAGMENTS)
#define IS_RETRY(x)            ((x) & FLAG_RETRY)
#define POWER_MGT_STATUS(x)    ((x) & FLAG_POWER_MGT)
#define HAS_MORE_DATA(x)       ((x) & FLAG_MORE_DATA)
#define IS_PROTECTED(x)        (!wlan_ignore_wep && ((x) & FLAG_PROTECTED))
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
#define QOS_FIELD_CONTENT(x)  (((x) & 0xFF00) >> 8)

#define QOS_FLAG_EOSP		0x08

/*
 * Extract subfields from the result of QOS_FIELD_CONTENT().
 */
#define QOS_PS_BUF_STATE(x)	(((x) & 0x02) >> 1)
#define QOS_PS_BUF_AC(x)	(((x) & 0x0C) >> 2)
#define QOS_PS_BUF_LOAD(x)	(((x) & 0xF0) >> 4)

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

/*
 * COMPOSE_FRAME_TYPE() values for control frames.
 */
#define CTRL_BLOCK_ACK_REQ   0x18	/* Block ack Request		    */
#define CTRL_BLOCK_ACK	     0x19	/* Block ack			    */
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
#define DATA_QOS_NULL		    0x2C	/* QoS Null			  */
#define DATA_QOS_CF_POLL_NOD	    0x2E	/* QoS CF-Poll (No Data)		  */
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
#define TAG_QOS_CAPABILITY	 0x2E
#define TAG_ERP_INFO_OLD         0x2F	/* IEEE Std 802.11g/D4.0 */
#define TAG_RSN_IE               0x30
#define TAG_EXT_SUPP_RATES       0x32
#define TAG_AGERE_PROPRIETARY	 0x80
#define TAG_CISCO_UNKNOWN_1	 0x85	/* Cisco Compatible eXtensions? */
#define TAG_CISCO_UNKNOWN_2	 0x88	/* Cisco Compatible eXtensions? */
#define TAG_VENDOR_SPECIFIC_IE	 0xDD
#define TAG_SYMBOL_PROPRIETARY	 0xAD

#define WPA_OUI	"\x00\x50\xF2"
#define RSN_OUI "\x00\x0F\xAC"
#define WME_OUI "\x00\x50\xF2"

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
static int hf_addr_bssid = -1;	/* address is bssid */

static int hf_addr = -1;	/* Source or destination address subfield */


/* ************************************************************************* */
/*                Header values for QoS control field                        */
/* ************************************************************************* */
static int hf_qos_priority = -1;
static int hf_qos_ack_policy = -1;
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
/*                Header values for sequence number field                    */
/* ************************************************************************* */
static int hf_frag_number = -1;
static int hf_seq_number = -1;

/* ************************************************************************* */
/*                   Header values for Frame Check field                     */
/* ************************************************************************* */
static int hf_fcs = -1;

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
static gint ett_fragments = -1;
static gint ett_fragment = -1;

static gint ett_80211_mgt = -1;
static gint ett_fixed_parameters = -1;
static gint ett_tagged_parameters = -1;
static gint ett_qos_parameters = -1;
static gint ett_qos_ps_buf_state = -1;
static gint ett_wep_parameters = -1;

static gint ett_rsn_cap_tree = -1;

static gint ett_80211_mgt_ie = -1;
static gint ett_tsinfo_tree = -1;
static gint ett_sched_tree = -1;

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

static dissector_handle_t llc_handle;
static dissector_handle_t ipx_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t data_handle;

static int wlan_tap = -1;

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
    if (DATA_FRAME_IS_QOS(COMPOSE_FRAME_TYPE(fcf)))
      return len + 2;
    else
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

  if (IS_PROTECTED(FCF_FLAGS(fcf)))
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
static void
add_fixed_field (proto_tree * tree, tvbuff_t * tvb, int offset, int lfcode)
{
  const guint8 *dataptr;
  char out_buff[SHORT_STR];
  guint16 capability;
  proto_item *cap_item;
  static proto_tree *cap_tree;
  double temp_double;

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
      break;

    case FIELD_AUTH_ALG:
      proto_tree_add_item (tree, ff_auth_alg, tvb, offset, 2, TRUE);
      break;

    case FIELD_AUTH_TRANS_SEQ:
      proto_tree_add_item (tree, ff_auth_seq, tvb, offset, 2, TRUE);
      break;

    case FIELD_CURRENT_AP_ADDR:
      proto_tree_add_item (tree, ff_current_ap, tvb, offset, 6, FALSE);
      break;

    case FIELD_LISTEN_IVAL:
      proto_tree_add_item (tree, ff_listen_ival, tvb, offset, 2, TRUE);
      break;

    case FIELD_REASON_CODE:
      proto_tree_add_item (tree, ff_reason, tvb, offset, 2, TRUE);
      break;

    case FIELD_ASSOC_ID:
      proto_tree_add_uint(tree, ff_assoc_id, tvb, offset, 2,
			  ASSOC_ID(tvb_get_letohs(tvb,offset)));
      /* proto_tree_add_item (tree, ff_assoc_id, tvb, offset, 2, TRUE); */
      break;

    case FIELD_STATUS_CODE:
      proto_tree_add_item (tree, ff_status_code, tvb, offset, 2, TRUE);
      break;

    case FIELD_CATEGORY_CODE:
      proto_tree_add_item (tree, ff_category_code, tvb, offset, 1, TRUE);
      break;

    case FIELD_ACTION_CODE:
      proto_tree_add_item (tree, ff_action_code, tvb, offset, 1, TRUE);
      break;

    case FIELD_DIALOG_TOKEN:
      proto_tree_add_item (tree, ff_dialog_token, tvb, offset, 1, TRUE);
      break;

    case FIELD_WME_ACTION_CODE:
      proto_tree_add_item (tree, ff_wme_action_code, tvb, offset, 1, TRUE);
      break;

    case FIELD_WME_STATUS_CODE:
      proto_tree_add_item (tree, ff_wme_status_code, tvb, offset, 1, TRUE);
      break;

    case FIELD_QOS_ACTION_CODE:
      proto_tree_add_item (tree, ff_qos_action_code, tvb, offset, 1, TRUE);
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
      break;

    case FIELD_DLS_ACTION_CODE:
      proto_tree_add_item (tree, ff_dls_action_code, tvb, offset, 1, TRUE);
      break;

    case FIELD_DST_MAC_ADDR:
      proto_tree_add_item (tree, ff_dst_mac_addr, tvb, offset, 6, TRUE);
      break;

    case FIELD_SRC_MAC_ADDR:
      proto_tree_add_item (tree, ff_src_mac_addr, tvb, offset, 6, TRUE);
      break;

    case FIELD_DLS_TIMEOUT:
      proto_tree_add_item (tree, ff_dls_timeout, tvb, offset, 2, TRUE);
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
    break;
    }
}

static const char *wpa_cipher_str[] =
{
  "NONE",
  "WEP (40-bit)",
  "TKIP",
  "AES (OCB)",
  "AES (CCM)",
  "WEP (104-bit)",
};

static const char *
wpa_cipher_idx2str(guint idx)
{
  if (idx < sizeof(wpa_cipher_str)/sizeof(wpa_cipher_str[0]))
    return wpa_cipher_str[idx];
  return "UNKNOWN";
}

static const char *wpa_keymgmt_str[] =
{
  "NONE",
  "WPA",
  "PSK",
};

static const char *
wpa_keymgmt_idx2str(guint idx)
{
  if (idx < sizeof(wpa_keymgmt_str)/sizeof(wpa_keymgmt_str[0]))
    return wpa_keymgmt_str[idx];
  return "UNKNOWN";
}

static void
dissect_vendor_ie_wpawme(proto_tree * ietree, proto_tree * tree, tvbuff_t * tvb,
	int offset, guint32 tag_len, const guint8 *tag_val)
{
      guint32 tag_val_off = 0;
      char out_buff[SHORT_STR];
      guint i;

      /* Wi-Fi Protected Access (WPA) Information Element */
      if (tag_val_off + 6 <= tag_len && !memcmp(tag_val, WPA_OUI"\x01", 4)) {
        g_snprintf(out_buff, SHORT_STR, "WPA IE, type %u, version %u",
                  tag_val[tag_val_off + 3], pletohs(&tag_val[tag_val_off + 4]));
        proto_tree_add_string(tree, tag_interpretation, tvb, offset, 6, out_buff);
        offset += 6;
        tag_val_off += 6;
        if (tag_val_off + 4 <= tag_len) {
          /* multicast cipher suite */
          if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
            g_snprintf(out_buff, SHORT_STR, "Multicast cipher suite: %s",
                      wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
            proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
            offset += 4;
            tag_val_off += 4;
            /* unicast cipher suites */
            if (tag_val_off + 2 <= tag_len) {
              g_snprintf(out_buff, SHORT_STR, "# of unicast cipher suites: %u",
                        pletohs(tag_val + tag_val_off));
              proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
              offset += 2;
              tag_val_off += 2;
              i = 1;
              while (tag_val_off + 4 <= tag_len) {
                if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
                  g_snprintf(out_buff, SHORT_STR, "Unicast cipher suite %u: %s",
                            i, wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
                  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
                  offset += 4;
                  tag_val_off += 4;
                  i ++;
                }
                else
                  break;
              }
	      /* authenticated key management suites */
              if (tag_val_off + 2 <= tag_len) {
                g_snprintf(out_buff, SHORT_STR, "# of auth key management suites: %u",
                          pletohs(tag_val + tag_val_off));
                proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
                offset += 2;
                tag_val_off += 2;
                i = 1;
                while (tag_val_off + 4 <= tag_len) {
                  if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
                    g_snprintf(out_buff, SHORT_STR, "auth key management suite %u: %s",
                              i, wpa_keymgmt_idx2str(tag_val[tag_val_off + 3]));
                    proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
                    offset += 4;
                    tag_val_off += 4;
                    i ++;
                  }
                  else
                    break;
                }
              }
            }
          }
        }
        if (tag_val_off < tag_len)
          proto_tree_add_string(tree, tag_interpretation, tvb,
                                 offset, tag_len - tag_val_off, "Not interpreted");
	proto_item_append_text(ietree, ": WPA");
      } else if (tag_val_off + 7 <= tag_len && !memcmp(tag_val, WME_OUI"\x02\x00", 5)) {
      /* Wireless Multimedia Enhancements (WME) Information Element */
        g_snprintf(out_buff, SHORT_STR, "WME IE: type %u, subtype %u, version %u, parameter set %u",
		 tag_val[tag_val_off + 3], tag_val[tag_val_off + 4], tag_val[tag_val_off + 5],
		 tag_val[tag_val_off + 6]);
        proto_tree_add_string(tree, tag_interpretation, tvb, offset, 7, out_buff);
	proto_item_append_text(ietree, ": WME");
      } else if (tag_val_off + 24 <= tag_len && !memcmp(tag_val, WME_OUI"\x02\x01", 5)) {
      /* Wireless Multimedia Enhancements (WME) Parameter Element */
        g_snprintf(out_buff, SHORT_STR, "WME PE: type %u, subtype %u, version %u, parameter set %u",
		 tag_val[tag_val_off + 3], tag_val[tag_val_off + 4], tag_val[tag_val_off + 5],
		 tag_val[tag_val_off + 6]);
        proto_tree_add_string(tree, tag_interpretation, tvb, offset, 7, out_buff);
	offset += 8;
	tag_val_off += 8;
	for (i = 0; i < 4; i++) {
	  g_snprintf(out_buff, SHORT_STR, "WME AC Parameters: ACI %u (%s), Admission Control %sMandatory, AIFSN %u, ECWmin %u, ECWmax %u, TXOP %u",
		   (tag_val[tag_val_off] & 0x60) >> 5,
		   wme_acs[(tag_val[tag_val_off] & 0x60) >> 5],
		   (tag_val[tag_val_off] & 0x10) ? "" : "not ",
		   tag_val[tag_val_off] & 0x0f,
		   tag_val[tag_val_off + 1] & 0x0f,
		   (tag_val[tag_val_off + 1] & 0xf0) >> 4,
		   tvb_get_letohs(tvb, offset + 2));
	  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
	  offset += 4;
	  tag_val_off += 4;
	}
	proto_item_append_text(ietree, ": WME");
      } else if (tag_val_off + 56 <= tag_len && !memcmp(tag_val, WME_OUI"\x02\x02", 5)) {
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

        g_snprintf(out_buff, SHORT_STR, "WME TSPEC: type %u, subtype %u, version %u",
		 tag_val[tag_val_off + 3], tag_val[tag_val_off + 4], tag_val[tag_val_off + 5]);
        proto_tree_add_string(tree, tag_interpretation, tvb, offset, 6, out_buff);
	offset += 6;
	tag_val_off += 6;

	ts_info = tvb_get_letohs(tvb, offset);
	g_snprintf(out_buff, SHORT_STR, "WME TS Info: Priority %u (%s) (%s), Contention-based access %sset, %s",
		 (ts_info >> 11) & 0x7, qos_tags[(ts_info >> 11) & 0x7], qos_acs[(ts_info >> 11) & 0x7],
		 (ts_info & 0x0080) ? "" : "not ",
		 direction[(ts_info >> 5) & 0x3]);
	proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
	offset += 2;
	tag_val_off += 2;

	msdu_size = tvb_get_letohs(tvb, offset);
	g_snprintf(out_buff, SHORT_STR, "WME TSPEC: %s MSDU Size %u",
		 (msdu_size & 0x8000) ? "Fixed" : "Nominal", msdu_size & 0x7fff);
	proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
	offset += 2;
	tag_val_off += 2;

	g_snprintf(out_buff, SHORT_STR, "WME TSPEC: Maximum MSDU Size %u", tvb_get_letohs(tvb, offset));
	proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
	offset += 2;
	tag_val_off += 2;

	while ((field = val_to_str(tag_val_off, fields, "Unknown"))) {
	  g_snprintf(out_buff, SHORT_STR, "WME TSPEC: %s %u", field, tvb_get_letohl(tvb, offset));
	  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
	  offset += 4;
	  tag_val_off += 4;
	  if (tag_val_off == 52)
	    break;
	}

	surplus_bandwidth = tvb_get_letohs(tvb, offset);
	g_snprintf(out_buff, SHORT_STR, "WME TSPEC: Surplus Bandwidth Allowance Factor %u.%u",
		 (surplus_bandwidth >> 13) & 0x7, (surplus_bandwidth & 0x1fff));
	offset += 2;
	tag_val_off += 2;

	g_snprintf(out_buff, SHORT_STR, "WME TSPEC: Medium Time %u", tvb_get_letohs(tvb, offset));
	proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
	offset += 2;
	tag_val_off += 2;
	proto_item_append_text(ietree, ": WME");
      }
}

static void
dissect_vendor_ie_rsn(proto_tree * ietree, proto_tree * tree, tvbuff_t * tvb,
	int offset, guint32 tag_len, const guint8 *tag_val)
{
	guint32 tag_val_off = 0;
	char out_buff[SHORT_STR], *pos;
	guint i;

	if (tag_val_off + 4 <= tag_len && !memcmp(tag_val, RSN_OUI"\x04", 4)) {
		/* IEEE 802.11i / Key Data Encapsulation / Data Type=4 - PMKID.
		 * This is only used within EAPOL-Key frame Key Data. */
		pos = out_buff;
		pos += g_snprintf(pos, out_buff + SHORT_STR - pos, "RSN PMKID: ");
		if (tag_len - 4 != PMKID_LEN) {
			pos += g_snprintf(pos, out_buff + SHORT_STR - pos,
				"(invalid PMKID len=%d, expected 16) ", tag_len - 4);
		}
		for (i = 0; i < tag_len - 4; i++) {
			pos += g_snprintf(pos, out_buff + SHORT_STR - pos, "%02X",
				tag_val[tag_val_off + 4 + i]);
		}
		proto_tree_add_string(tree, tag_interpretation, tvb, offset,
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
dissect_rsn_ie(proto_tree * tree, tvbuff_t * tvb, int offset,
	       guint32 tag_len, const guint8 *tag_val)
{
  guint32 tag_val_off = 0;
  guint16 rsn_capab;
  char out_buff[SHORT_STR];
  int i, j, count;
  proto_item *cap_item;
  proto_tree *cap_tree;

  if (tag_val_off + 2 > tag_len) {
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, tag_len,
			  "Not interpreted");
    return;
  }

  g_snprintf(out_buff, SHORT_STR, "RSN IE, version %u",
	   pletohs(&tag_val[tag_val_off]));
  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);

  offset += 2;
  tag_val_off += 2;

  if (tag_val_off + 4 > tag_len)
    goto done;

  /* multicast cipher suite */
  if (!memcmp(&tag_val[tag_val_off], RSN_OUI, 3)) {
    g_snprintf(out_buff, SHORT_STR, "Multicast cipher suite: %s",
	     wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
    offset += 4;
    tag_val_off += 4;
  }

  if (tag_val_off + 2 > tag_len)
    goto done;

  /* unicast cipher suites */
  count = pletohs(tag_val + tag_val_off);
  g_snprintf(out_buff, SHORT_STR, "# of unicast cipher suites: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
  offset += 2;
  tag_val_off += 2;
  i = 1;
  while (tag_val_off + 4 <= tag_len && i <= count) {
    if (memcmp(&tag_val[tag_val_off], RSN_OUI, 3) != 0)
      goto done;
    g_snprintf(out_buff, SHORT_STR, "Unicast cipher suite %u: %s",
	     i, wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
    offset += 4;
    tag_val_off += 4;
    i++;
  }

  if (i <= count || tag_val_off + 2 > tag_len)
    goto done;

  /* authenticated key management suites */
  count = pletohs(tag_val + tag_val_off);
  g_snprintf(out_buff, SHORT_STR, "# of auth key management suites: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
  offset += 2;
  tag_val_off += 2;
  i = 1;
  while (tag_val_off + 4 <= tag_len && i <= count) {
    if (memcmp(&tag_val[tag_val_off], RSN_OUI, 3) != 0)
      goto done;
    g_snprintf(out_buff, SHORT_STR, "auth key management suite %u: %s",
	     i, wpa_keymgmt_idx2str(tag_val[tag_val_off + 3]));
    proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
    offset += 4;
    tag_val_off += 4;
    i++;
  }

  if (i <= count || tag_val_off + 2 > tag_len)
    goto done;

  rsn_capab = pletohs(&tag_val[tag_val_off]);
  g_snprintf(out_buff, SHORT_STR, "RSN Capabilities 0x%04x", rsn_capab);
  cap_item = proto_tree_add_uint_format(tree, rsn_cap, tvb,
					offset, 2, rsn_capab,
					"RSN Capabilities: 0x%04X", rsn_capab);
  cap_tree = proto_item_add_subtree(cap_item, ett_rsn_cap_tree);
  proto_tree_add_boolean(cap_tree, rsn_cap_preauth, tvb, offset, 2,
			 rsn_capab);
  proto_tree_add_boolean(cap_tree, rsn_cap_no_pairwise, tvb, offset, 2,
			 rsn_capab);
  proto_tree_add_uint(cap_tree, rsn_cap_ptksa_replay_counter, tvb, offset, 2,
		      rsn_capab);
  proto_tree_add_uint(cap_tree, rsn_cap_gtksa_replay_counter, tvb, offset, 2,
		      rsn_capab);
  offset += 2;
  tag_val_off += 2;

  if (tag_val_off + 2 > tag_len)
    goto done;

  count = pletohs(tag_val + tag_val_off);
  g_snprintf(out_buff, SHORT_STR, "# of PMKIDs: %u", count);
  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
  offset += 2;
  tag_val_off += 2;

  /* PMKID List (16 * n octets) */
  for (i = 0; i < count; i++) {
    char *pos;
    if (tag_val_off + PMKID_LEN > tag_len)
      goto done;
    pos = out_buff;
    pos += g_snprintf(pos, out_buff + SHORT_STR - pos, "PMKID %u: ", i);
    for (j = 0; j < PMKID_LEN; j++) {
      pos += g_snprintf(pos, out_buff + SHORT_STR - pos, "%02X",
		      tag_val[tag_val_off + j]);
    }
    proto_tree_add_string(tree, tag_interpretation, tvb, offset,
			  PMKID_LEN, out_buff);
    offset += PMKID_LEN;
    tag_val_off += PMKID_LEN;
  }

 done:
  if (tag_val_off < tag_len)
    proto_tree_add_string(tree, tag_interpretation, tvb, offset,
			  tag_len - tag_val_off, "Not interpreted");
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
	{ TAG_VENDOR_SPECIFIC_IE,   "Vendor Specific" },
	{ TAG_SYMBOL_PROPRIETARY,   "Symbol Proprietary"},
	{ TAG_AGERE_PROPRIETARY,    "Agere Proprietary"},
	{ TAG_REQUEST,		    "Request"},
	{ TAG_QBSS_LOAD,	    "QBSS Load Element"},
	{ TAG_EDCA_PARAM_SET,	    "EDCA Parameter Set"},
	{ TAG_TSPEC,		    "Traffic Specification"},
	{ TAG_TCLAS,		    "Traffic Classification"},
	{ TAG_SCHEDULE,		    "Schedule"},
	{ TAG_TS_DELAY,		    "TS Delay"},
	{ TAG_TCLAS_PROCESS,	    "TCLAS Processing"},
	{ TAG_QOS_CAPABILITY,	    "QoS Capability"},
	{ TAG_POWER_CONSTRAINT,	    "Power Constraint"},
	{ TAG_POWER_CAPABILITY,	    "Power Capability"},
	{ TAG_TPC_REQUEST,	    "TPC Request"},
	{ TAG_TPC_REPORT,	    "TPC Report"},
	{ TAG_SUPPORTED_CHANNELS,   "Supported Channels"},
	{ TAG_CHANNEL_SWITCH_ANN,   "Channel Switch Announcement"},
	{ TAG_MEASURE_REQ,	    "Measurement Request"},
	{ TAG_MEASURE_REP,	    "Measurement Report"},
	{ TAG_QUIET,		    "Quiet"},
	{ TAG_IBSS_DFS,		    "IBSS DFS"},
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
  const guint8 *tag_val;
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
        proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
                               tag_len, ssid);
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
		"Tag length %u too short, must be > 0", tag_len);
        break;
      }

      tag_data_ptr = tvb_get_ptr (tvb, offset + 2, tag_len);
      for (i = 0, n = 0; i < tag_len && n < SHORT_STR; i++) {
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
      add_fixed_field (tree, tvb, offset + 2, FIELD_QOS_TS_INFO);
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
      add_fixed_field (tree, tvb, offset + 2, FIELD_SCHEDULE_INFO);
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
		tag_val = tvb_get_ptr(tvb, offset + 2, tag_len);

#define WPAWME_OUI	0x0050F2
#define RSNOUI_VAL	0x000FAC

		switch (oui) {
		case WPAWME_OUI:
			dissect_vendor_ie_wpawme(ti, tree, tvb, offset + 2, tag_len, tag_val);
			break;
		case RSNOUI_VAL:
			dissect_vendor_ie_rsn(ti, tree, tvb, offset + 2, tag_len, tag_val);
			break;
		case OUI_CISCOWL:	/* Cisco Wireless (Aironet) */
			dissect_vendor_ie_aironet(ti, tree, tvb, offset + 5, tag_len - 3);
			break;
		default:
			proto_tree_add_bytes_format (tree, tag_oui, tvb, offset + 2, 3,
				"", "Vendor: %s", get_manuf_name(tag_val));
			proto_item_append_text(ti, ": %s", get_manuf_name(tag_val));
			proto_tree_add_string (tree, tag_interpretation, tvb, offset + 5,
				tag_len - 3, "Not interpreted");
			break;
		}

      }
      break;

    case TAG_RSN_IE:
      dissect_rsn_ie(tree, tvb, offset + 2, tag_len,
                     tvb_get_ptr (tvb, offset + 2, tag_len));
      break;

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
      int offset;
      int tagged_parameter_tree_len;

      g_pinfo = pinfo;

      CHECK_DISPLAY_AS_X(data_handle,proto_wlan_mgt, tvb, pinfo, tree);

      ti = proto_tree_add_item (tree, proto_wlan_mgt, tvb, 0, -1, FALSE);
      mgt_tree = proto_item_add_subtree (ti, ett_80211_mgt);

      switch (COMPOSE_FRAME_TYPE(fcf))
	{

	case MGT_ASSOC_REQ:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 4);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_ASSOC_ID);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_CURRENT_AP_ADDR);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_ASSOC_ID);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field (fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field (fixed_tree, tvb, 10, FIELD_CAP_INFO);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field (fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field (fixed_tree, tvb, 10, FIELD_CAP_INFO);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;


	case MGT_AUTHENTICATION:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_AUTH_ALG);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_AUTH_TRANS_SEQ);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_STATUS_CODE);
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
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;


	case MGT_ACTION:
	  switch (tvb_get_guint8(tvb, 0))
	    {

	    case CAT_SPECTRUM_MGMT:
	      switch (tvb_get_guint8(tvb, 1))
		{
		case SM_ACTION_MEASUREMENT_REQUEST:
		case SM_ACTION_MEASUREMENT_REPORT:
		case SM_ACTION_TPC_REQUEST:
		case SM_ACTION_TPC_REPORT:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 3);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  offset = 3;	/* Size of fixed fields */
		  break;

		case SM_ACTION_CHAN_SWITCH_ANNC:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  offset = 2;	/* Size of fixed fields */
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  offset = 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_QOS:
	      switch (tvb_get_guint8(tvb, 1))
	        {
		case SM_ACTION_ADDTS_REQUEST:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 3);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  offset = 3;
		  break;

		case SM_ACTION_ADDTS_RESPONSE:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 5);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
		  add_fixed_field (fixed_tree, tvb, 3, FIELD_STATUS_CODE);
		  offset = 5;
		  break;

		case SM_ACTION_DELTS:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 7);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_QOS_TS_INFO);
		  add_fixed_field (fixed_tree, tvb, 5, FIELD_REASON_CODE);
		  offset = 7;
		  break;

		case SM_ACTION_QOS_SCHEDULE:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_QOS_ACTION_CODE);
		  offset = 2;
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  offset = 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_DLS:
	      switch (tvb_get_guint8(tvb, 1))
	        {
		case SM_ACTION_DLS_REQUEST:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 18);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_DST_MAC_ADDR);
		  add_fixed_field (fixed_tree, tvb, 8, FIELD_SRC_MAC_ADDR);
		  add_fixed_field (fixed_tree, tvb, 14, FIELD_CAP_INFO);
		  add_fixed_field (fixed_tree, tvb, 16, FIELD_DLS_TIMEOUT);
		  offset = 18;
		  break;

		case SM_ACTION_DLS_RESPONSE:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 16);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_STATUS_CODE);
		  add_fixed_field (fixed_tree, tvb, 4, FIELD_DST_MAC_ADDR);
		  add_fixed_field (fixed_tree, tvb, 10, FIELD_SRC_MAC_ADDR);
		  offset = 16;
		  if (!ff_status_code)
		    add_fixed_field (fixed_tree, tvb, 16, FIELD_CAP_INFO);
		  break;

		case SM_ACTION_DLS_TEARDOWN:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 18);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  add_fixed_field (fixed_tree, tvb, 1, FIELD_DLS_ACTION_CODE);
		  add_fixed_field (fixed_tree, tvb, 2, FIELD_DST_MAC_ADDR);
		  add_fixed_field (fixed_tree, tvb, 8, FIELD_SRC_MAC_ADDR);
		  add_fixed_field (fixed_tree, tvb, 14, FIELD_REASON_CODE);
		  offset = 16;
		  break;

		default:
		  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
		  add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
		  offset = 2;	/* Size of fixed fields */
		  break;
		}
	      break;

	    case CAT_MGMT_NOTIFICATION:	/* Management notification frame */
	      fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 4);
	      add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
	      add_fixed_field (fixed_tree, tvb, 1, FIELD_WME_ACTION_CODE);
	      add_fixed_field (fixed_tree, tvb, 2, FIELD_DIALOG_TOKEN);
	      add_fixed_field (fixed_tree, tvb, 3, FIELD_WME_STATUS_CODE);
	      offset = 4;	/* Size of fixed fields */
	      break;

	    default:
	      fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 1);
	      add_fixed_field (fixed_tree, tvb, 0, FIELD_CATEGORY_CODE);
	      offset = 1;	/* Size of fixed fields */
	      break;
	    }

	    tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
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
  proto_item *flag_item;
  proto_item *fc_item;
  proto_tree *hdr_tree = NULL;
  proto_tree *flag_tree;
  proto_tree *fc_tree;
  guint16 hdr_len, ohdr_len;
  gboolean has_fcs;
  gint len, reported_len, ivlen;
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

      proto_tree_add_uint (hdr_tree, hf_fc_frame_type_subtype,
			   tvb,
	  	    	   wlan_broken_fc?1:0, 1,
			   frame_type_subtype);

      fc_item = proto_tree_add_uint_format (hdr_tree, hf_fc_field, tvb,
		      			    0, 2,
					    fcf,
					    "Frame Control: 0x%04X (%s)",
					    fcf, wlan_broken_fc?"Swapped":"Normal");

      fc_tree = proto_item_add_subtree (fc_item, ett_fc_tree);


      proto_tree_add_uint (fc_tree, hf_fc_proto_version, tvb,
		           wlan_broken_fc?1:0, 1,
			   FCF_PROT_VERSION (fcf));

      proto_tree_add_uint (fc_tree, hf_fc_frame_type, tvb,
		           wlan_broken_fc?1:0, 1,
			   FCF_FRAME_TYPE (fcf));

      proto_tree_add_uint (fc_tree, hf_fc_frame_subtype,
			   tvb,
			   wlan_broken_fc?1:0, 1,
			   FCF_FRAME_SUBTYPE (fcf));

      flag_item =
	proto_tree_add_uint_format (fc_tree, hf_fc_flags, tvb,
			            wlan_broken_fc?0:1, 1,
				    flags, "Flags: 0x%X", flags);

      flag_tree = proto_item_add_subtree (flag_item, ett_proto_flags);

      proto_tree_add_uint (flag_tree, hf_fc_data_ds, tvb,
		           wlan_broken_fc?0:1, 1,
			   FLAGS_DS_STATUS (flags));
      proto_tree_add_boolean_hidden (flag_tree, hf_fc_to_ds, tvb, 1, 1,
				     flags);
      proto_tree_add_boolean_hidden (flag_tree, hf_fc_from_ds, tvb, 1, 1,
				     flags);

      proto_tree_add_boolean (flag_tree, hf_fc_more_frag, tvb,
		              wlan_broken_fc?0:1, 1,
			      flags);

      proto_tree_add_boolean (flag_tree, hf_fc_retry, tvb,
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_pwr_mgt, tvb,
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_more_data, tvb,
		              wlan_broken_fc?0:1, 1,
			      flags);

      proto_tree_add_boolean (flag_tree, hf_fc_protected, tvb,
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_order, tvb,
		              wlan_broken_fc?0:1, 1, flags);

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

	case CTRL_BLOCK_ACK_REQ:
	  {
	    src = tvb_get_ptr (tvb, 10, 6);
	    dst = tvb_get_ptr (tvb, 4, 6);

	    set_src_addr_cols(pinfo, src, "TA");
	    set_dst_addr_cols(pinfo, dst, "RA");

	    if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, src);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, dst);
	    }
	  /* TODO BAR */
	  break;
	  }

	case CTRL_BLOCK_ACK:
	  {
	    src = tvb_get_ptr (tvb, 10, 6);
	    dst = tvb_get_ptr (tvb, 4, 6);

	    set_src_addr_cols(pinfo, src, "TA");
	    set_dst_addr_cols(pinfo, dst, "RA");

	    if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, src);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, dst);
	    }
	    /* TODO BAR Format */
	    break;
	  }
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
	      if (fcs == sent_fcs)
		proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x [correct]", sent_fcs);
	      else
		proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x [incorrect, should be 0x%08x]",
			sent_fcs, fcs);
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
	  qos_eosp = QOS_EOSP(qos_control);
	  qos_field_content = QOS_FIELD_CONTENT( qos_control);

	  proto_tree_add_uint_format (qos_tree, hf_qos_priority, tvb,
	      qosoff, 2, qos_priority,
	      "Priority: %d (%s) (%s)",
	      qos_priority, qos_tags[qos_priority], qos_acs[qos_priority]);

	  if (flags & FLAG_FROM_DS) {
	    proto_tree_add_boolean (qos_tree, hf_qos_eosp, tvb,
	      qosoff, 1, qos_eosp);

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
	  } else if (qos_eosp)  {
	    /* txop limit requested */
	    proto_tree_add_uint_format (qos_tree, hf_qos_field_content, tvb,
      		  qosoff + 1, 1, qos_field_content, "Queue Size: %d ", (qos_field_content * 254));
	  } else {
	    /* queue size */
	    proto_tree_add_uint_format (qos_tree, hf_qos_field_content, tvb,
		  qosoff + 1, 1, qos_field_content, "TXOP Limit Requested: %d ", qos_field_content);
	  }

	  proto_tree_add_uint (qos_tree, hf_qos_ack_policy, tvb, qosoff, 1,
	      qos_ack_policy);

	} /* end of qos control field */

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

  if (IS_PROTECTED(FCF_FLAGS(fcf))) {
    /*
     * It's a WEP-encrypted frame; dissect the WEP parameters and decrypt
     * the data, if we have a matching key.  Otherwise display it as data.
     */
    gboolean can_decrypt = FALSE;
    proto_tree *wep_tree = NULL;
    guint32 iv;
    guint8 key, keybyte;

    keybyte = tvb_get_guint8(tvb, hdr_len + 3);
    key = KEY_OCTET_WEP_KEY(keybyte);
    if ((keybyte & KEY_EXTIV) && (len >= EXTIV_LEN)) {
      /* Extended IV; this frame is likely encrypted with TKIP or CCMP */
      if (tree) {
	proto_item *extiv_fields;

	extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
					   "TKIP/CCMP parameters");
	wep_tree = proto_item_add_subtree (extiv_fields, ett_wep_parameters);
	/* It is unknown whether this is a TKIP or CCMP encrypted packet, so
	 * display both packet number alternatives unless the ExtIV can be
	 * determined to be possible only with one of the encryption protocols.
	 */
	if (tvb_get_guint8(tvb, hdr_len + 1) & 0x20) {
	  g_snprintf(out_buff, SHORT_STR, "0x%08X%02X%02X",
		   tvb_get_letohl(tvb, hdr_len + 4),
		   tvb_get_guint8(tvb, hdr_len),
		   tvb_get_guint8(tvb, hdr_len + 2));
	  proto_tree_add_string(wep_tree, hf_tkip_extiv, tvb, hdr_len,
				EXTIV_LEN, out_buff);
	}
	if (tvb_get_guint8(tvb, hdr_len + 2) == 0) {
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

    if (!can_decrypt || (next_tvb = try_decrypt_wep(tvb, hdr_len, reported_len + 8)) == NULL) {
      /*
       * WEP decode impossible or failed, treat payload as raw data
       * and don't attempt fragment reassembly or further dissection.
       */
      next_tvb = tvb_new_subset(tvb, hdr_len + ivlen, len, reported_len);

      if (tree && can_decrypt)
	proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb,
				    hdr_len + ivlen + len, 4,
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len),
				    "WEP ICV: 0x%08x (not verified)",
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len));

      if (pinfo->ethertype != ETHERTYPE_CENTRINO_PROMISC)
      {
        /* Some wireless drivers (such as Centrino) WEP payload already decrypted */
        call_dissector(data_handle, next_tvb, pinfo, tree);
        goto end_of_wlan;
      }
    } else {

      if (tree)
	proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb,
				    hdr_len + ivlen + len, 4,
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len),
				    "WEP ICV: 0x%08x (correct)",
				    tvb_get_ntohl(tvb, hdr_len + ivlen + len));

      add_new_data_source(pinfo, next_tvb, "Decrypted WEP data");
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
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, TRUE,
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
    {0x02, "No explicit Ack"},
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
     {"Type/Subtype", "wlan.fc.type_subtype", FT_UINT16, BASE_DEC, VALS(frame_type_subtype_vals), 0,
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
     {"Ack Policy", "wlan.qos.ack", FT_UINT16, BASE_HEX,  VALS (&ack_policy), 0,
      "Ack Policy", HFILL }},

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

    {&hf_aironet_ie_type,
     {"Aironet IE type", "wlan_mgt.aironet.type",
      FT_UINT8, BASE_DEC, VALS(aironet_ie_type_vals), 0, "", HFILL }},

    {&hf_aironet_ie_version,
     {"Aironet IE CCX version?", "wlan_mgt.aironet.version",
      FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},

    { &hf_aironet_ie_data,
      { "Aironet IE data", "wlan_mgmt.aironet.data",
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

  };

  static gint *tree_array[] = {
    &ett_80211,
    &ett_fc_tree,
    &ett_proto_flags,
    &ett_fragments,
    &ett_fragment,
    &ett_80211_mgt,
    &ett_fixed_parameters,
    &ett_tagged_parameters,
    &ett_qos_parameters,
    &ett_qos_ps_buf_state,
    &ett_wep_parameters,
    &ett_cap_tree,
    &ett_rsn_cap_tree,
    &ett_80211_mgt_ie,
    &ett_tsinfo_tree,
    &ett_sched_tree,
  };
  module_t *wlan_module;


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

  prefs_register_bool_preference(wlan_module, "ignore_wep",
				 "Ignore the WEP bit",
				 "Some 802.11 cards leave the WEP bit set even though the packet is decrypted.",
				 &wlan_ignore_wep);

#ifndef USE_ENV

  prefs_register_obsolete_preference(wlan_module, "wep_keys");

  prefs_register_bool_preference(wlan_module, "enable_decryption",
	"Enable decryption", "Enable WEP decryption",
	&enable_decryption);

  for (i = 0; i < MAX_ENCRYPTION_KEYS; i++) {
    key_name = g_string_new("");
    key_title = g_string_new("");
    key_desc = g_string_new("");
    wep_keystr[i] = NULL;
    /* prefs_register_*_preference() expects unique strings, so
     * we build them using g_string_sprintf and just leave them
     * allocated. */
    g_string_sprintf(key_name, "wep_key%d", i + 1);
    g_string_sprintf(key_title, "WEP key #%d", i + 1);
    g_string_sprintf(key_desc, "WEP key #%d bytes in hexadecimal (A:B:C:D:E) "
	    "[40bit], (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key "
	    "length you're using", i + 1);

    prefs_register_string_preference(wlan_module, key_name->str,
	    key_title->str, key_desc->str, &wep_keystr[i]);

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

      goto done;
    }
  }

 done:
  if ((!decr_tvb) && (tmp))    g_free(tmp);

#if 0
  printf("de-wep %p\n", decr_tvb);
#endif

  return decr_tvb;
}


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
