/* packet-simulcrypt.c
 * Simulcrypt protocol interface as defined in ETSI TS 103.197 v 1.5.1
 *
 * ECMG <-> SCS support
 * David Castleford, Orange Labs / France Telecom R&D
 * Oct 2008
 *
 * EMMG <-> MUX support and generic interface support
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>

#define PROTO_TAG_SIMULCRYPT            "SIMULCRYPT"
#define CA_SYSTEM_ID_MIKEY              0x9999  /* CA_system_ID corresponding to MIKEY ECM */
#define CA_SYSTEM_ID_MIKEY_PROTO        "mikey" /* Protocol name to be used to "decode as" ECMs with CA_SYSTEM_ID_MIKEY */

/* Tecm_interpretation links ca_system_id to ecmg port and protocol name for dissection of ecm_datagram in ECM_Response message
* Currently size is 1 as only have MIKEY protocol but could add extra protocols
* could add option in preferences for new ca_system_id for new protocol for example
*/
typedef struct Tecm_interpretation
{
	int ca_system_id;
	char *protocol_name;
	dissector_handle_t protocol_handle;
	guint ecmg_port;
} ecm_interpretation;

#define ECM_MIKEY_INDEX 0  /* must agree with tab_ecm_inter initialization */

static ecm_interpretation tab_ecm_inter[]={
	{CA_SYSTEM_ID_MIKEY, CA_SYSTEM_ID_MIKEY_PROTO, NULL, -1}
};

#define ECM_INTERPRETATION_SIZE (sizeof(tab_ecm_inter)/sizeof(ecm_interpretation))

static void  dissect_simulcrypt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_simulcrypt_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset);

/* Wireshark ID of the SIMULCRYPT protocol */
static guint proto_simulcrypt = -1;

/* Preferences (with default values) */
static guint global_simulcrypt_tcp_port = 0;   /* Simulcrypt registered only if pref set to non-zero value */
static guint global_simulcrypt_udp_port = 0;   /* Simulcrypt registered only if pref set to non-zero value */
static int ca_system_id_mikey = CA_SYSTEM_ID_MIKEY; /* MIKEY ECM CA_system_ID */

/* MIKEY payload start bytes */
/*unsigned char mikey_start[3]={0x01,0x00,0x15};
* mikey_start[0]=0x01;	 first byte mikey payload (version)
* mikey_start[1]=0x00;	 second byte mikey payload (data type)
* mikey_start[2]=0x15;	 third byte (next payload)
*/

/* Dissector-internal values to determine interface, can be re-organized */
#define SIMULCRYPT_RESERVED     0
#define SIMULCRYPT_ECMG_SCS     1
#define SIMULCRYPT_EMMG_MUX     2
#define SIMULCRYPT_CPSIG_PSIG   3
#define SIMULCRYPT_EIS_SCS      4
#define SIMULCRYPT_PSIG_MUX     5
#define SIMULCRYPT_MUX_CIM      6
#define SIMULCRYPT_PSIG_CIP     7
#define SIMULCRYPT_USER_DEFINED 8

static const value_string interfacenames[] = {
	{ SIMULCRYPT_RESERVED,     "DVB reserved" },
	{ SIMULCRYPT_ECMG_SCS,     "ECMG <-> SCS" },
	{ SIMULCRYPT_EMMG_MUX,     "EMMG <-> MUX" },
	{ SIMULCRYPT_CPSIG_PSIG,   "C(P)SIG <-> (P)SIG" },
	{ SIMULCRYPT_EIS_SCS,      "EIS <-> SCS" },
	{ SIMULCRYPT_PSIG_MUX,     "(P)SIG <-> MUX" },
	{ SIMULCRYPT_MUX_CIM,      "Carousel in the MUX - CiM" },
	{ SIMULCRYPT_PSIG_CIP,     "Carousel in the (P) - CiP" },
	{ SIMULCRYPT_USER_DEFINED, "User defined" },
	{ 0, NULL }
};

/* Reserved 0x0000 */
#define SIMULCRYPT_ECMG_CHANNEL_SETUP                   0x0001
#define SIMULCRYPT_ECMG_CHANNEL_TEST                    0x0002
#define SIMULCRYPT_ECMG_CHANNEL_STATUS                  0x0003
#define SIMULCRYPT_ECMG_CHANNEL_CLOSE                   0x0004
#define SIMULCRYPT_ECMG_CHANNEL_ERROR                   0x0005
/* Reserved 0x0006 - 0x0010 */
#define SIMULCRYPT_EMMG_CHANNEL_SETUP                   0x0011
#define SIMULCRYPT_EMMG_CHANNEL_TEST                    0x0012
#define SIMULCRYPT_EMMG_CHANNEL_STATUS                  0x0013
#define SIMULCRYPT_EMMG_CHANNEL_CLOSE                   0x0014
#define SIMULCRYPT_EMMG_CHANNEL_ERROR                   0x0015
/* Reserved 0x0016 - 0x0100 */
#define SIMULCRYPT_ECMG_STREAM_SETUP                    0x0101
#define SIMULCRYPT_ECMG_STREAM_TEST                     0x0102
#define SIMULCRYPT_ECMG_STREAM_STATUS                   0x0103
#define SIMULCRYPT_ECMG_STREAM_CLOSE_REQUEST            0x0104
#define SIMULCRYPT_ECMG_STREAM_CLOSE_RESPONSE           0x0105
#define SIMULCRYPT_ECMG_STREAM_ERROR                    0x0106
/* Reserved 0x0107 - 0x0110 */
#define SIMULCRYPT_EMMG_STREAM_SETUP                    0x0111
#define SIMULCRYPT_EMMG_STREAM_TEST                     0x0112
#define SIMULCRYPT_EMMG_STREAM_STATUS                   0x0113
#define SIMULCRYPT_EMMG_STREAM_CLOSE_REQUEST            0x0114
#define SIMULCRYPT_EMMG_STREAM_CLOSE_RESPONSE           0x0115
#define SIMULCRYPT_EMMG_STREAM_ERROR                    0x0116
#define SIMULCRYPT_EMMG_STREAM_BW_REQUEST               0x0117
#define SIMULCRYPT_EMMG_STREAM_BW_ALLOCATION            0x0118
/* Reserved 0x0119 - 0x0200 */
#define SIMULCRYPT_ECMG_CW_PROVISION                    0x0201
#define SIMULCRYPT_ECMG_ECM_RESPONSE                    0x0202
/* Reserved 0x0203 - 0x0210 */
#define SIMULCRYPT_EMMG_DATA_PROVISION                  0x0211
/* Reserved 0x0212 - 0x0300 */
/* Not implemented 0x0301 - 0x7FFF */
/* User defined 0x8000 - 0xFFFF */

static const value_string messagetypenames[] = {
	{ SIMULCRYPT_ECMG_CHANNEL_SETUP,         "CHANNEL_SETUP" },
	{ SIMULCRYPT_ECMG_CHANNEL_TEST,          "CHANNEL_TEST" },
	{ SIMULCRYPT_ECMG_CHANNEL_STATUS,        "CHANNEL_STATUS" },
	{ SIMULCRYPT_ECMG_CHANNEL_CLOSE,         "CHANNEL_CLOSE" },
	{ SIMULCRYPT_ECMG_CHANNEL_ERROR,         "CHANNEL_ERROR" },

	{ SIMULCRYPT_EMMG_CHANNEL_SETUP,         "CHANNEL_SETUP" },
	{ SIMULCRYPT_EMMG_CHANNEL_TEST,          "CHANNEL_TEST" },
	{ SIMULCRYPT_EMMG_CHANNEL_STATUS,        "CHANNEL_STATUS" },
	{ SIMULCRYPT_EMMG_CHANNEL_CLOSE,         "CHANNEL_CLOSE" },
	{ SIMULCRYPT_EMMG_CHANNEL_ERROR,         "CHANNEL_ERROR" },

	{ SIMULCRYPT_ECMG_STREAM_SETUP,          "STREAM_SETUP" },
	{ SIMULCRYPT_ECMG_STREAM_TEST,           "STREAM_TEST" },
	{ SIMULCRYPT_ECMG_STREAM_STATUS,         "STREAM_STATUS" },
	{ SIMULCRYPT_ECMG_STREAM_CLOSE_REQUEST,  "STREAM_CLOSE_REQUEST" },
	{ SIMULCRYPT_ECMG_STREAM_CLOSE_RESPONSE, "STREAM_CLOSE_RESPONSE" },
	{ SIMULCRYPT_ECMG_STREAM_ERROR,          "STREAM_ERROR" },

	{ SIMULCRYPT_EMMG_STREAM_SETUP,          "STREAM_SETUP" },
	{ SIMULCRYPT_EMMG_STREAM_TEST,           "STREAM_TEST" },
	{ SIMULCRYPT_EMMG_STREAM_STATUS,         "STREAM_STATUS" },
	{ SIMULCRYPT_EMMG_STREAM_CLOSE_REQUEST,  "STREAM_CLOSE_REQUEST" },
	{ SIMULCRYPT_EMMG_STREAM_CLOSE_RESPONSE, "STREAM_CLOSE_RESPONSE" },
	{ SIMULCRYPT_EMMG_STREAM_ERROR,          "STREAM_ERROR" },
	{ SIMULCRYPT_EMMG_STREAM_BW_REQUEST,     "STREAM_BW_REQUEST" },
	{ SIMULCRYPT_EMMG_STREAM_BW_ALLOCATION,  "STREAM_BW_ALLOCATION" },

	{ SIMULCRYPT_ECMG_CW_PROVISION,          "CW_PROVISION" },
	{ SIMULCRYPT_ECMG_ECM_RESPONSE,          "ECM_RESPONSE" },

	{ SIMULCRYPT_EMMG_DATA_PROVISION,        "DATA_PROVISION" },
	{ 0, NULL }
};	

/* Simulcrypt ECMG Parameter Types */
#define SIMULCRYPT_ECMG_DVB_RESERVED                    0x0000
#define SIMULCRYPT_ECMG_SUPER_CAS_ID                    0x0001
#define SIMULCRYPT_ECMG_SECTION_TSPKT_FLAG              0x0002
#define SIMULCRYPT_ECMG_DELAY_START                     0x0003
#define SIMULCRYPT_ECMG_DELAY_STOP                      0x0004
#define SIMULCRYPT_ECMG_TRANSITION_DELAY_START          0x0005
#define SIMULCRYPT_ECMG_TRANSITION_DELAY_STOP           0x0006
#define SIMULCRYPT_ECMG_ECM_REP_PERIOD                  0x0007
#define SIMULCRYPT_ECMG_MAX_STREAMS                     0x0008
#define SIMULCRYPT_ECMG_MIN_CP_DURATION                 0x0009
#define SIMULCRYPT_ECMG_LEAD_CW                         0x000A
#define SIMULCRYPT_ECMG_CW_PER_MESSAGE                  0x000B
#define SIMULCRYPT_ECMG_MAX_COMP_TIME                   0x000C
#define SIMULCRYPT_ECMG_ACCESS_CRITERIA                 0x000D
#define SIMULCRYPT_ECMG_ECM_CHANNEL_ID                  0x000E
#define SIMULCRYPT_ECMG_ECM_STREAM_ID                   0x000F
#define SIMULCRYPT_ECMG_NOMINAL_CP_DURATION             0x0010
#define SIMULCRYPT_ECMG_ACCESS_CRITERIA_TRANSFER_MODE   0x0011
#define SIMULCRYPT_ECMG_CP_NUMBER                       0x0012
#define SIMULCRYPT_ECMG_CP_DURATION                     0x0013
#define SIMULCRYPT_ECMG_CP_CW_COMBINATION               0x0014
#define SIMULCRYPT_ECMG_ECM_DATAGRAM                    0x0015
#define SIMULCRYPT_ECMG_AC_DELAY_START                  0x0016
#define SIMULCRYPT_ECMG_AC_DELAY_STOP                   0x0017
#define SIMULCRYPT_ECMG_CW_ENCRYPTION                   0x0018
#define SIMULCRYPT_ECMG_ECM_ID                          0x0019
#define SIMULCRYPT_ECMG_ERROR_STATUS                    0x7000
#define SIMULCRYPT_ECMG_ERROR_INFORMATION               0x7001

static const value_string ecmg_parametertypenames[] = {
	{ SIMULCRYPT_ECMG_DVB_RESERVED,                  "DVB_RESERVED" },
	{ SIMULCRYPT_ECMG_SUPER_CAS_ID,                  "SUPER_CAS_ID" },
	{ SIMULCRYPT_ECMG_SECTION_TSPKT_FLAG,            "SECTION_TSPKT_FLAG" },
	{ SIMULCRYPT_ECMG_DELAY_START,                   "DELAY_START" },
	{ SIMULCRYPT_ECMG_DELAY_STOP,                    "DELAY_STOP" },
	{ SIMULCRYPT_ECMG_TRANSITION_DELAY_START,        "TRANSITION_DELAY_START" },
	{ SIMULCRYPT_ECMG_TRANSITION_DELAY_STOP,         "TRANSITION_DELAY_STOP" },
	{ SIMULCRYPT_ECMG_ECM_REP_PERIOD,                "ECM_REP_PERIOD" },
	{ SIMULCRYPT_ECMG_MAX_STREAMS,                   "MAX_STREAMS" },
	{ SIMULCRYPT_ECMG_MIN_CP_DURATION,               "MIN_CP_DURATION" },
	{ SIMULCRYPT_ECMG_LEAD_CW,                       "LEAD_CW" },
	{ SIMULCRYPT_ECMG_CW_PER_MESSAGE,                "CW_PER_MESSAGE" },
	{ SIMULCRYPT_ECMG_MAX_COMP_TIME,                 "MAX_COMP_TIME" },
	{ SIMULCRYPT_ECMG_ACCESS_CRITERIA,               "ACCESS_CRITERIA" },
	{ SIMULCRYPT_ECMG_ECM_CHANNEL_ID,                "ECM_CHANNEL_ID" },
	{ SIMULCRYPT_ECMG_ECM_STREAM_ID,                 "ECM_STREAM_ID" },
	{ SIMULCRYPT_ECMG_NOMINAL_CP_DURATION,           "NOMINAL_CP_DURATION" },
	{ SIMULCRYPT_ECMG_ACCESS_CRITERIA_TRANSFER_MODE, "ACCESS_CRITERIA_TRANSFER_MODE" },
	{ SIMULCRYPT_ECMG_CP_NUMBER,                     "CP_NUMBER" },
	{ SIMULCRYPT_ECMG_CP_DURATION,                   "CP_DURATION" },
	{ SIMULCRYPT_ECMG_CP_CW_COMBINATION,             "CP_CW_COMBINATION" },
	{ SIMULCRYPT_ECMG_ECM_DATAGRAM,                  "ECM_DATAGRAM" },
	{ SIMULCRYPT_ECMG_AC_DELAY_START,                "AC_DELAY_START" },
	{ SIMULCRYPT_ECMG_AC_DELAY_STOP,                 "AC_DELAY_STOP" },
	{ SIMULCRYPT_ECMG_CW_ENCRYPTION,                 "CW_ENCRYPTION" },
	{ SIMULCRYPT_ECMG_ECM_ID,                        "ECM_ID" },
	{ SIMULCRYPT_ECMG_ERROR_STATUS,                  "ERROR_STATUS" },
	{ SIMULCRYPT_ECMG_ERROR_INFORMATION,             "ERROR_INFORMATION" },
	{ 0, NULL }
};

/* Simulcrypt ECMG protocol error values */
static const value_string ecmg_error_values[] = {
	{ 0x0000, "DVB Reserved" },
	{ 0x0001, "Invalid message" },
	{ 0x0002, "Unsupported protocol version" },
	{ 0x0003, "Unknown message type value" },
	{ 0x0004, "Message too long" },
	{ 0x0005, "Unknown super CAS ID value" },
	{ 0x0006, "Unknown ECM channel ID value" },
	{ 0x0007, "Unknown ECM stream ID value" },
	{ 0x0008, "Too many channels on this ECMG" },
	{ 0x0009, "Too many ECM streams on this channel" },
	{ 0x000A, "Too many ECM streams on this ECMG" },
	{ 0x000B, "Not enough control words to compute ECM" },
	{ 0x000C, "ECMG out of storage capacity" },
	{ 0x000D, "ECMG out of computational resources" },
	{ 0x000E, "Unknown parameter type value" },
	{ 0x000F, "Inconsistent length for DVB parameter" },
	{ 0x0010, "Missing mandatory DVB parameter" },
	{ 0x0011, "Invalid value for DVB parameter" },
	{ 0x0012, "Unknown ECM ID value" },
	{ 0x0013, "ECM channel ID value already in use" },
	{ 0x0014, "ECM stream ID value already in use" },
	{ 0x0015, "ECM ID value already in use" },
	{ 0x7000, "Unknown error" },
	{ 0x7001, "Unrecoverable error" },
	{ 0, NULL }
};

/* Simulcrypt EMMG Parameter Types */
#define SIMULCRYPT_EMMG_DVB_RESERVED                    0x0000
#define SIMULCRYPT_EMMG_CLIENT_ID                       0x0001
#define SIMULCRYPT_EMMG_SECTION_TSPKT_FLAG              0x0002
#define SIMULCRYPT_EMMG_DATA_CHANNEL_ID                 0x0003
#define SIMULCRYPT_EMMG_DATA_STREAM_ID                  0x0004
#define SIMULCRYPT_EMMG_DATAGRAM                        0x0005
#define SIMULCRYPT_EMMG_BANDWIDTH                       0x0006
#define SIMULCRYPT_EMMG_DATA_TYPE                       0x0007
#define SIMULCRYPT_EMMG_DATA_ID                         0x0008
#define SIMULCRYPT_EMMG_ERROR_STATUS                    0x7000
#define SIMULCRYPT_EMMG_ERROR_INFORMATION               0x7001

static const value_string emmg_parametertypenames[] = {
	{ SIMULCRYPT_EMMG_DVB_RESERVED,       "DVB_RESERVED" },
	{ SIMULCRYPT_EMMG_CLIENT_ID,          "CLIENT_ID" },
	{ SIMULCRYPT_EMMG_SECTION_TSPKT_FLAG, "SECTION_TSPKT_FLAG" },
	{ SIMULCRYPT_EMMG_DATA_CHANNEL_ID,    "DATA_CHANNEL_ID" },
	{ SIMULCRYPT_EMMG_DATA_STREAM_ID,     "DATA_STREAM_ID" },
	{ SIMULCRYPT_EMMG_DATAGRAM,           "DATAGRAM" },
	{ SIMULCRYPT_EMMG_BANDWIDTH,          "BANDWIDTH" },
	{ SIMULCRYPT_EMMG_DATA_TYPE,          "DATA_TYPE" },
	{ SIMULCRYPT_EMMG_DATA_ID,            "DATA_ID" },
	{ SIMULCRYPT_EMMG_ERROR_STATUS,       "ERROR_STATUS" },
	{ SIMULCRYPT_EMMG_ERROR_INFORMATION,  "ERROR_INFORMATION" },
	{ 0, NULL }
};

/* Simulcrypt EMMG protocol error values */
static const value_string emmg_error_values[] = {
	{ 0x0000, "DVB Reserved" },
	{ 0x0001, "Invalid message" },
	{ 0x0002, "Unsupported protocol version" },
	{ 0x0003, "Unknown message type value" },
	{ 0x0004, "Message too long" },
	{ 0x0005, "Unknown data stream ID value" },
	{ 0x0006, "Unknown data channel ID value" },
	{ 0x0007, "Too many channels on this MUX" },
	{ 0x0008, "Too many data streams on this channel" },
	{ 0x0009, "Too many data streams on this MUX" },
	{ 0x000A, "Unknown parameter type" },
	{ 0x000B, "Inconsistent length for DVB parameter" },
	{ 0x000C, "Missing mandatory DVB parameter" },
	{ 0x000D, "Invalid value for DVB parameter" },
	{ 0x000E, "Unknown client ID value" },
	{ 0x000F, "Exceeded bandwidth" },
	{ 0x0010, "Unknown data ID value" },
	{ 0x0011, "Data channel ID value already in use" },
	{ 0x0012, "Data stream ID value already in use" },
	{ 0x0013, "Data ID value already in use" },
	{ 0x0014, "Client ID value already in use" },
	{ 0x7000, "Unknown error" },
	{ 0x7001, "Unrecoverable error" },
	{ 0, NULL }
};

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_simulcrypt()
*/
static gint hf_simulcrypt_header = -1;
static gint hf_simulcrypt_version = -1;
static gint hf_simulcrypt_message_type = -1;
static gint hf_simulcrypt_interface = -1;
static gint hf_simulcrypt_message_length = -1;
static gint hf_simulcrypt_message = -1;
static gint hf_simulcrypt_parameter = -1;
static gint hf_simulcrypt_parameter_type = -1;
static gint hf_simulcrypt_ecmg_parameter_type = -1;
static gint hf_simulcrypt_emmg_parameter_type = -1;
static gint hf_simulcrypt_parameter_length = -1;
static gint hf_simulcrypt_ca_system_id = -1;
static gint hf_simulcrypt_ca_subsystem_id = -1;
static gint hf_simulcrypt_super_cas_id = -1;
static gint hf_simulcrypt_section_tspkt_flag = -1;
static gint hf_simulcrypt_ecm_channel_id = -1;
static gint hf_simulcrypt_delay_start = -1;
static gint hf_simulcrypt_delay_stop = -1;
static gint hf_simulcrypt_ac_delay_start = -1;
static gint hf_simulcrypt_ac_delay_stop = -1;
static gint hf_simulcrypt_transition_delay_start = -1;
static gint hf_simulcrypt_transition_delay_stop = -1;
static gint hf_simulcrypt_ecm_rep_period = -1;
static gint hf_simulcrypt_max_streams = -1;
static gint hf_simulcrypt_min_cp_duration = -1;
static gint hf_simulcrypt_lead_cw = -1;
static gint hf_simulcrypt_cw_per_msg = -1;
static gint hf_simulcrypt_max_comp_time = -1;
static gint hf_simulcrypt_access_criteria = -1;
static gint hf_simulcrypt_ecm_stream_id = -1;
static gint hf_simulcrypt_nominal_cp_duration = -1;
static gint hf_simulcrypt_access_criteria_transfer_mode = -1;
static gint hf_simulcrypt_cp_number = -1;
static gint hf_simulcrypt_cp_duration = -1;
static gint hf_simulcrypt_cp_cw_combination = -1;
static gint hf_simulcrypt_ecm_datagram = -1;
static gint hf_simulcrypt_cw_encryption = -1;
static gint hf_simulcrypt_ecm_id = -1;
static gint hf_simulcrypt_client_id = -1;
static gint hf_simulcrypt_data_channel_id = -1;
static gint hf_simulcrypt_data_stream_id = -1;
static gint hf_simulcrypt_datagram = -1;
static gint hf_simulcrypt_bandwidth = -1;
static gint hf_simulcrypt_data_type = -1;
static gint hf_simulcrypt_data_id = -1;
static gint hf_simulcrypt_ecmg_error_status = -1;
static gint hf_simulcrypt_emmg_error_status = -1;
static gint hf_simulcrypt_error_information = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_simulcrypt = -1;
static gint ett_simulcrypt_header = -1;
static gint ett_simulcrypt_message = -1;
static gint ett_simulcrypt_parameter = -1;
static gint ett_simulcrypt_super_cas_id = -1;
static gint ett_simulcrypt_ecm_datagram = -1;


#define FRAME_HEADER_LEN 8

/* The main dissecting routine */
static void dissect_simulcrypt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_simulcrypt_message_len, dissect_simulcrypt_message);
}

/* Informative tree structure is shown here:
* TREE 	-
*	- HEADER
*		version
*		message type
*		message length
*	- MESSAGE
*		- TYPE of parameter
*			length of parameter
			value of parameter
			- PARAMETER (optional branch for certain parameters only)
*				parameter value sub items here
* End informative tree structure 
*/

static guint16
get_interface (guint16 type)
{
	int interface;

	if (type >= 0x8000) {
		return SIMULCRYPT_USER_DEFINED;
	}

	/* Hex values fetched from Table 3: Message-type values for command/response-based protocols */
	switch (type & 0xFFF0) {
	case 0x0000:
	case 0x0100:
	case 0x0200:
		interface = SIMULCRYPT_ECMG_SCS;
		break;
	case 0x0010:
	case 0x0110:
	case 0x0210:
		interface = SIMULCRYPT_EMMG_MUX;
		break;
	case 0x0310:
	case 0x0320:
		interface = SIMULCRYPT_CPSIG_PSIG;
		break;
	case 0x0400:
		interface = SIMULCRYPT_EIS_SCS;
		break;
	case 0x0410:
	case 0x0420:
		interface = SIMULCRYPT_PSIG_MUX;
		break;
	case 0x0430:
		interface = SIMULCRYPT_MUX_CIM;
		break;
	case 0x0440:
		interface = SIMULCRYPT_PSIG_CIP;
		break;
	default:
		interface = SIMULCRYPT_RESERVED;
		break;
	}

	return interface;
}

static void 
dissect_ecmg_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, guint16 plen, guint16 ptype, gchar *pvalue_char)
{
	proto_item *simulcrypt_item;
	proto_tree *simulcrypt_super_cas_id_tree;
	proto_tree *simulcrypt_ecm_datagram_tree;
	tvbuff_t   *next_tvb;
	guint32     pvaluedec;    /* parameter decimal value */
	int         ca_system_id;
	guint       i;

	switch (ptype) {
	case SIMULCRYPT_ECMG_SUPER_CAS_ID:
		/* add super_cas_id item */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_super_cas_id, tvb, offset, plen, FALSE); /* value item */
		simulcrypt_super_cas_id_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_super_cas_id);
		
		/* Simulcrypt_super_cas_id_tree */
		simulcrypt_item = proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_system_id, tvb, offset, 2, FALSE );
			
		/* Test for known CA_System_ID */
		ca_system_id = tvb_get_ntohs(tvb,offset);
		for(i=0;i<ECM_INTERPRETATION_SIZE;i++)
		{			
			if(tab_ecm_inter[i].ca_system_id==ca_system_id)
			{
				tab_ecm_inter[i].ecmg_port=pinfo->destport;
				proto_item_append_text(simulcrypt_item, ", Port %d, Protocol %s",tab_ecm_inter[i].ecmg_port, tab_ecm_inter[i].protocol_name);
				break;
			}
		}
		proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_subsystem_id, tvb, offset+2, 2, FALSE );
		break;
	case SIMULCRYPT_ECMG_SECTION_TSPKT_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_section_tspkt_flag, tvb, offset, plen, FALSE); /* value item */
		break;
	case SIMULCRYPT_ECMG_ECM_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_channel_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_delay_start, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_delay_stop, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms"); 
		break;
	case SIMULCRYPT_ECMG_TRANSITION_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_transition_delay_start, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_TRANSITION_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_transition_delay_stop, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_AC_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ac_delay_start, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_AC_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ac_delay_stop, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_ECM_REP_PERIOD:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ecm_rep_period, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_MAX_STREAMS:
		proto_tree_add_item(tree, hf_simulcrypt_max_streams, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_MIN_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte min CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_min_cp_duration, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " (%d ms)",pvaluedec);
		break;
	case SIMULCRYPT_ECMG_LEAD_CW:
		proto_tree_add_item(tree, hf_simulcrypt_lead_cw, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_CW_PER_MESSAGE:
		proto_tree_add_item(tree, hf_simulcrypt_cw_per_msg, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_MAX_COMP_TIME:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_max_comp_time, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_ACCESS_CRITERIA:
		proto_tree_add_item(tree, hf_simulcrypt_access_criteria, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_ECM_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_stream_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_NOMINAL_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte nominal CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_nominal_cp_duration, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_ECMG_ACCESS_CRITERIA_TRANSFER_MODE:
		proto_tree_add_item(tree, hf_simulcrypt_access_criteria_transfer_mode, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_CP_NUMBER:
		proto_tree_add_item(tree, hf_simulcrypt_cp_number, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_cp_duration, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_ECMG_CP_CW_COMBINATION:
		proto_tree_add_item(tree, hf_simulcrypt_cp_cw_combination, tvb, offset, plen, FALSE); 
		break;
	case SIMULCRYPT_ECMG_ECM_DATAGRAM:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ecm_datagram, tvb, offset, plen, FALSE); 
		/* Test srcport against table of ECMG ports & CA_System_ID for known protocol types */
		for(i=0;i<ECM_INTERPRETATION_SIZE;i++)
		{
			if(tab_ecm_inter[i].ecmg_port==pinfo->srcport) /* ECMG source port */
			{ /* recognise port & ca_system_id and hence protocol name for ECM datagram */
				next_tvb = tvb_new_subset_remaining(tvb, offset);
				simulcrypt_ecm_datagram_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_ecm_datagram);
				if(tab_ecm_inter[i].protocol_handle != NULL)
				{
					call_dissector(tab_ecm_inter[i].protocol_handle, next_tvb,pinfo, simulcrypt_ecm_datagram_tree);
				}
				break;
			}
		}
		break;
	case SIMULCRYPT_ECMG_CW_ENCRYPTION:
		proto_tree_add_item(tree, hf_simulcrypt_cw_encryption, tvb, offset, plen, FALSE); 
		break;
	case SIMULCRYPT_ECMG_ECM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_ecmg_error_status, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_ECMG_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, FALSE);
		break;
	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char); 
		break;
	} /* end parameter type switch */
}

static void 
dissect_emmg_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint32 offset, guint16 plen, guint16 ptype, gchar *pvalue_char)
{
	proto_item *simulcrypt_item;

	switch (ptype) {
	case SIMULCRYPT_EMMG_CLIENT_ID:
		proto_tree_add_item(tree, hf_simulcrypt_client_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_SECTION_TSPKT_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_section_tspkt_flag, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_DATA_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_channel_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_DATA_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_stream_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_DATAGRAM:
		proto_tree_add_item(tree, hf_simulcrypt_datagram, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_BANDWIDTH:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_bandwidth, tvb, offset, plen, FALSE);
		proto_item_append_text(simulcrypt_item, " kbit/s");
		break;
	case SIMULCRYPT_EMMG_DATA_TYPE:
		proto_tree_add_item(tree, hf_simulcrypt_data_type, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_DATA_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_id, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_emmg_error_status, tvb, offset, plen, FALSE);
		break;
	case SIMULCRYPT_EMMG_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, FALSE);
		break;
	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char); 
		break;
	} /* end parameter type switch */
}


/* This method dissects fully reassembled messages */
static void dissect_simulcrypt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *simulcrypt_item;
	proto_tree *simulcrypt_tree;
	proto_tree *simulcrypt_header_tree;
	proto_tree *simulcrypt_message_tree;
	proto_tree *simulcrypt_parameter_tree;
	guint16     type, iftype;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SIMULCRYPT);
	col_clear(pinfo->cinfo,COL_INFO);

	/* get 2 byte type value */
	type =  tvb_get_ntohs(tvb, 1); /* 2 bytes starting at offset 1 are the message type */
	iftype = get_interface (type);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Info Type:[%s]",
		     pinfo->srcport, pinfo->destport, 
		     val_to_str(type, messagetypenames, "Unknown Type:0x%02x"));

	if (tree)
	{
		/* we are being asked for details */
		guint32 offset = 0;
		guint32 msg_length;
		
		simulcrypt_item = proto_tree_add_item(tree, proto_simulcrypt, tvb, 0, -1, FALSE);
		simulcrypt_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt);

		proto_item_append_text(simulcrypt_item, ", Interface: %s", val_to_str(iftype, interfacenames, "Unknown (0x%02x)"));

		/* Simulcrypt_tree analysis */
		/* we are being asked for details */
		/* ADD HEADER BRANCH */
		simulcrypt_item = proto_tree_add_item(simulcrypt_tree, hf_simulcrypt_header, tvb, offset, 5, FALSE );
		simulcrypt_header_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_header);
		proto_item_append_text(simulcrypt_header_tree, ", Length: %s", "5 bytes"); /* add text to Header tree indicating Length 5 bytes */

		/* Simulcrypt_header_tree analysis */
		/* Message Version 1 Byte */
		proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_version, tvb, offset, 1, FALSE);		
		offset+=1;

		/* Message Type 2 Bytes */
		proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_message_type, tvb, offset, 2, FALSE);
		simulcrypt_item = proto_tree_add_uint_format(simulcrypt_header_tree, hf_simulcrypt_interface, tvb, offset, 2, iftype, 
							     "Interface: %s", val_to_str(iftype, interfacenames, "Unknown"));
		PROTO_ITEM_SET_GENERATED (simulcrypt_item);
		offset+=2;

		/* Message Length 2 Bytes */
		simulcrypt_item = proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_message_length, tvb, offset, 2, FALSE);
		proto_item_append_text(simulcrypt_item, " (bytes)");
		msg_length = tvb_get_ntohs(tvb, offset); /* read 2 byte message length value */
		offset+=2;
	
		/* ADD MESSAGE BRANCH */
		simulcrypt_item = proto_tree_add_item(simulcrypt_tree, hf_simulcrypt_message, tvb, offset, -1, FALSE );
		simulcrypt_message_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_message);
		proto_item_append_text(simulcrypt_message_tree, " containing TLV parameters"); /* add text to Message tree	*/	
		proto_item_append_text(simulcrypt_message_tree, ", Length: %d (bytes)", msg_length); /* add length info to message_tree */
		
		/* end header details */
 
		/* Simulcrypt_message_tree analysis */
		/*  we are being asked for details */
		/* Navigate through message after header to find one or more parameters */
		while (offset < (msg_length+5))  /* offset is from beginning of the 5 byte header */
		{
			guint16 plen;         /* parameter length */
			guint16 ptype;        /* parameter type */
			gchar  *pvalue_char;  /* parameter value string */
			
			/* Parameter  Type 2 Bytes */
			ptype = tvb_get_ntohs(tvb, offset); /* read 2 byte type value */
			/* Parameter  Length 2 Bytes */
			plen = tvb_get_ntohs(tvb, offset+2); /* read 2 byte length value */
			/* Parameter  Value plen Bytes */
			pvalue_char = tvb_bytes_to_str(tvb, offset+4, plen);

			simulcrypt_item = proto_tree_add_item(simulcrypt_message_tree, hf_simulcrypt_parameter, tvb, offset, plen+2+2, FALSE );

			/* add length and value info to type */
			switch (iftype) {
			case SIMULCRYPT_ECMG_SCS:
				proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, ecmg_parametertypenames, "Unknown Type:0x%02x"));
				break;
			case SIMULCRYPT_EMMG_MUX:
				proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, emmg_parametertypenames, "Unknown Type:0x%02x"));
				break;
			default:
				proto_item_append_text(simulcrypt_item, ": Type=0x%02x", ptype);
				break;
			}
			proto_item_append_text(simulcrypt_item, ", Value Length=%d (bytes)", plen); /* add length info to parameter */
			proto_item_append_text(simulcrypt_item, ", Value=0x%s", pvalue_char); /* add value info to parameter */
			/* add subtree for parameter type, length and value items */
			simulcrypt_parameter_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_parameter); /* add subtree for Length and Value */
			switch (iftype) { /* parameter type */
			case SIMULCRYPT_ECMG_SCS:
				proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_ecmg_parameter_type, tvb, offset, 2, FALSE);
				break;
			case SIMULCRYPT_EMMG_MUX:
				proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_emmg_parameter_type, tvb, offset, 2, FALSE);
				break;
			default:
				proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_parameter_type, tvb, offset, 2, FALSE);
				break;
			}
			simulcrypt_item = proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_parameter_length, tvb, offset+2, 2, FALSE); /* length item */
			proto_item_append_text(simulcrypt_item, " (bytes)");
			offset += 2+2;  /* offset --> parameter value */
			
			switch (iftype) {
			case SIMULCRYPT_ECMG_SCS:
				dissect_ecmg_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
				break;
			case SIMULCRYPT_EMMG_MUX:
				dissect_emmg_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
				break;
			default:
				proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char); 
				break;
			}

			offset += plen;
		} /* end parameter tree details */
			
	} /* end tree */
}	

/* determine PDU length of protocol foo */
static guint get_simulcrypt_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint iLg;
	
	iLg = tvb_get_ntohs(tvb,offset+3); /*length is at offset 3 */
	iLg += 5; /* add 1 byte version + 2 byte type + 2 byte length (simulcrypt "header" */
	return iLg;
}	

/* Clean out the ecm_interpretation port association whenever            */
/* making a pass through a capture file to dissect all its packets       */
/*  (e.g., reading in a new capture file, changing a simulcrypt pref,    */
/*  or running a "filter packets" or "colorize packets" pass over the    */
/*  current capture file.                                                */

static void 
simulcrypt_init(void) 
{
	guint i;

	for(i=0;i<ECM_INTERPRETATION_SIZE;i++)
	{
		tab_ecm_inter[i].ecmg_port = -1;
	}
}

void proto_reg_handoff_simulcrypt(void);

void proto_register_simulcrypt (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] =
	{
		{ &hf_simulcrypt_header,
		{ "Header", "simulcrypt.header", FT_NONE, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},
		 
		{ &hf_simulcrypt_version,
		{ "Version", "simulcrypt.version", FT_UINT8, BASE_HEX, NULL, 0x0, 	/* version 1 byte */
		NULL, HFILL }},

		{ &hf_simulcrypt_message_type,
		{ "Message Type", "simulcrypt.message.type", FT_UINT16, BASE_HEX, VALS(messagetypenames), 0x0,		/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_interface,
		{ "Interface", "simulcrypt.message.interface", FT_UINT16, BASE_DEC, VALS(interfacenames), 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_message_length,
		{ "Message Length", "simulcrypt.message.len", FT_UINT16, BASE_DEC, NULL, 0x0,		/* length 2 bytes, print as decimal value */
		NULL, HFILL }},

		{ &hf_simulcrypt_message,
		{ "Message", "simulcrypt.message", FT_NONE, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }}, 
		 
		{ &hf_simulcrypt_parameter,
		{ "Parameter", "simulcrypt.parameter", FT_NONE, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }}, 
		 
		{ &hf_simulcrypt_parameter_type,
		{ "Parameter Type", "simulcrypt.parameter.type", FT_UINT16, BASE_HEX, NULL, 0x0,	/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecmg_parameter_type,
		{ "Parameter Type", "simulcrypt.parameter.type", FT_UINT16, BASE_HEX, VALS(ecmg_parametertypenames), 0x0,	/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_emmg_parameter_type,
		{ "Parameter Type", "simulcrypt.parameter.type", FT_UINT16, BASE_HEX, VALS(emmg_parametertypenames), 0x0,	/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_parameter_length,
		{ "Parameter Length", "simulcrypt.parameter.len", FT_UINT16, BASE_DEC, NULL, 0x0,		/* length 2 bytes, print as decimal value */
		NULL, HFILL }},

		{ &hf_simulcrypt_ca_system_id,
		{ "CA System ID", "simulcrypt.parameter.ca_system_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }}, 

		{ &hf_simulcrypt_ca_subsystem_id,
		{ "CA Subsystem ID", "simulcrypt.parameter.ca_subsystem_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},
		 
		{ &hf_simulcrypt_super_cas_id,
		{ "SuperCAS ID", "simulcrypt.super_cas_id", FT_UINT32, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_section_tspkt_flag,
		{ "Section TS pkt flag", "simulcrypt.section_tspkt_flag", FT_UINT8, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecm_channel_id,
		{ "ECM channel ID", "simulcrypt.ecm_channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_delay_start,	
		{ "Delay start", "simulcrypt.delay_start", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_delay_stop,	
		{ "Delay stop", "simulcrypt.delay_stop", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ac_delay_start,	
		{ "AC delay start", "simulcrypt.ac_delay_start", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ac_delay_stop,	
		{ "AC delay stop", "simulcrypt.ac_delay_stop", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_transition_delay_start,	
		{ "Transition delay start", "simulcrypt.transition_delay_start", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_transition_delay_stop,	
		{ "Transition delay stop", "simulcrypt.transition_delay_stop", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},	

		{ &hf_simulcrypt_ecm_rep_period,
		{ "ECM repetition period", "simulcrypt.ecm_rep_period", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_max_streams,
		{ "Max streams", "simulcrypt.max_streams", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_min_cp_duration,
		{ "Min CP duration", "simulcrypt.min_cp_duration", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_lead_cw,
		{ "Lead CW", "simulcrypt.lead_cw", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cw_per_msg,
		{ "CW per msg", "simulcrypt.cw_per_msg", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_max_comp_time,
		{ "Max comp time", "simulcrypt.max_comp_time", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_access_criteria,
		{ "Access criteria", "simulcrypt.access_criteria", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecm_stream_id,
		{ "ECM stream ID", "simulcrypt.ecm_stream_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},	

		{ &hf_simulcrypt_nominal_cp_duration,
		{ "Nominal CP duration", "simulcrypt.nominal_cp_duration", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_access_criteria_transfer_mode,
		{ "AC transfer mode", "simulcrypt.access_criteria_transfer_mode", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cp_number,
		{ "CP number", "simulcrypt.cp_number", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cp_duration,
		{ "CP duration", "simulcrypt.cp_duration", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cp_cw_combination,
		{ "CP CW combination", "simulcrypt.cp_cw_combination", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},
		 
		{ &hf_simulcrypt_ecm_datagram,
		{ "ECM datagram", "simulcrypt.ecm_datagram", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cw_encryption,
		{ "CW encryption", "simulcrypt.cw_encryption", FT_NONE, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecm_id,
		{ "ECM ID", "simulcrypt.ecm_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_client_id,
		{ "Client ID", "simulcrypt.client_id", FT_UINT32, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_data_channel_id,
		{ "Data Channel ID", "simulcrypt.data_channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_data_stream_id,
		{ "Data Stream ID", "simulcrypt.data_stream_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_datagram,
		{ "Datagram", "simulcrypt.datagram", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_bandwidth,
		{ "Bandwidth", "simulcrypt.bandwidth", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_data_type,
		{ "Data Type", "simulcrypt.data_type", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_data_id,
		{ "Data ID", "simulcrypt.data_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecmg_error_status,
		{ "Error status", "simulcrypt.error_status", FT_UINT16, BASE_DEC, VALS(ecmg_error_values), 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_emmg_error_status,
		{ "Error status", "simulcrypt.error_status", FT_UINT16, BASE_DEC, VALS(emmg_error_values), 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_error_information,
		{ "Error information", "simulcrypt.error_information", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }}		 
	};
	
	static gint *ett[] =
	{
		&ett_simulcrypt,
		&ett_simulcrypt_header,
		&ett_simulcrypt_message,
		&ett_simulcrypt_parameter,
		&ett_simulcrypt_super_cas_id,
		&ett_simulcrypt_ecm_datagram
	};
	
	module_t *simulcrypt_module;
	
	/* execute protocol initialization only once */
	proto_simulcrypt = proto_register_protocol ("SIMULCRYPT Protocol", "SIMULCRYPT", "simulcrypt");

	proto_register_field_array (proto_simulcrypt, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
	register_init_routine(simulcrypt_init);

	/* Register our configuration options for Simulcrypt, particularly our port. */
	/* This registers our preferences; function proto_reg_handoff_simulcrypt is  */
	/*  called when preferences are applied.                                     */
	simulcrypt_module = prefs_register_protocol(proto_simulcrypt, proto_reg_handoff_simulcrypt);
	
	prefs_register_uint_preference(simulcrypt_module, "tcp.port", "Simulcrypt TCP Port",
				 "Set the TCP port for Simulcrypt messages ('0' means no port is assigned)",
				 10, &global_simulcrypt_tcp_port);
									
	prefs_register_uint_preference(simulcrypt_module, "udp.port", "Simulcrypt UDP Port",
				 "Set the UDP port for Simulcrypt messages ('0' means no port is assigned)",
				 10, &global_simulcrypt_udp_port);
									
	prefs_register_uint_preference(simulcrypt_module, "ca_system_id_mikey","MIKEY ECM CA_system_ID (in hex)",
					"Set the CA_system_ID used to decode ECM datagram as MIKEY", 16, &ca_system_id_mikey);		
}

/* this is run every time preferences are changed and also during Wireshark initialization */
void proto_reg_handoff_simulcrypt(void)
{
	static gboolean initialized=FALSE;
	static dissector_handle_t simulcrypt_handle;
	static guint tcp_port, udp_port;
	guint  i;

	if (!initialized) {
		simulcrypt_handle = create_dissector_handle(dissect_simulcrypt, proto_simulcrypt);
		for(i=0;i<ECM_INTERPRETATION_SIZE;i++)
		{
			tab_ecm_inter[i].protocol_handle = find_dissector(tab_ecm_inter[i].protocol_name);
		}
		dissector_add_handle("tcp.port", simulcrypt_handle);   /* for "decode_as" */
		dissector_add_handle("udp.port", simulcrypt_handle);   /* for "decode_as" */
		initialized = TRUE;
	}
	else {
		dissector_delete("tcp.port", tcp_port, simulcrypt_handle);
		dissector_delete("udp.port", udp_port, simulcrypt_handle);
	}	
	if (global_simulcrypt_tcp_port != 0) {
		dissector_add("tcp.port", global_simulcrypt_tcp_port, simulcrypt_handle);
	}
	if (global_simulcrypt_udp_port != 0) {
		dissector_add("udp.port", global_simulcrypt_udp_port, simulcrypt_handle);
	}
	tcp_port = global_simulcrypt_tcp_port;
	udp_port = global_simulcrypt_udp_port;

	/* update tab_ecm_inter table (always do this) */
	tab_ecm_inter[ECM_MIKEY_INDEX].ca_system_id=ca_system_id_mikey;
}

