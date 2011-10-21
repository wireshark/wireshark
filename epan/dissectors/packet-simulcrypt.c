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
 * EIS <-> SCS support, (P)SIG <-> MUX support, MUX <-> CiM support and (P) <-> CiP support
 * Copyright 2010, Giuliano Fabris <giuliano.fabris@appeartv.com> / AppearTV
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

/* Tecm_interpretation links ca_system_id to ecmg port and protocol name for dissection of
 * ecm_datagram in ECM_Response message.
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

static ecm_interpretation tab_ecm_inter[] = {
	{CA_SYSTEM_ID_MIKEY, CA_SYSTEM_ID_MIKEY_PROTO, NULL, -1}
};

#define ECM_INTERPRETATION_SIZE (sizeof(tab_ecm_inter)/sizeof(ecm_interpretation))

static void  dissect_simulcrypt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_simulcrypt_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset);
static void dissect_simulcrypt_data(proto_tree *simulcrypt_tree, proto_item *simulcrypt_item, packet_info *pinfo _U_,
                                    tvbuff_t *tvb, proto_tree *tree, int offset,
                                    int container_data_length, guint16 iftype, gboolean is_subtree);

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

/* Reserved 0x0322 - 0x0400 */
#define SIMULCRYPT_EIS_CHANNEL_SET_UP                   0x0401
#define SIMULCRYPT_EIS_CHANNEL_TEST                     0x0402
#define SIMULCRYPT_EIS_CHANNEL_STATUS                   0x0403
#define SIMULCRYPT_EIS_CHANNEL_CLOSE                    0x0404
#define SIMULCRYPT_EIS_CHANNEL_ERROR                    0x0405
#define SIMULCRYPT_EIS_CHANNEL_RESET                    0x0406

#define SIMULCRYPT_EIS_SCG_PROVISION                    0x0408
#define SIMULCRYPT_EIS_SCG_TEST                         0x0409
#define SIMULCRYPT_EIS_SCG_STATUS                       0x040A
#define SIMULCRYPT_EIS_SCG_ERROR                        0x040B
#define SIMULCRYPT_EIS_SCG_LIST_REQUEST                 0x040C
#define SIMULCRYPT_EIS_SCG_LIST_RESPONSE                0x040D

#define SIMULCRYPT_PSIG_CHANNEL_SETUP                   0x0411
#define SIMULCRYPT_PSIG_CHANNEL_TEST                    0x0412
#define SIMULCRYPT_PSIG_CHANNEL_STATUS                  0x0413
#define SIMULCRYPT_PSIG_CHANNEL_CLOSE                   0x0414
#define SIMULCRYPT_PSIG_CHANNEL_ERROR                   0x0415

#define SIMULCRYPT_PSIG_STREAM_SETUP                    0x0421
#define SIMULCRYPT_PSIG_STREAM_TEST                     0x0422
#define SIMULCRYPT_PSIG_STREAM_STATUS                   0x0423
#define SIMULCRYPT_PSIG_STREAM_CLOSE_REQUEST            0x0424
#define SIMULCRYPT_PSIG_STREAM_CLOSE_RESPONSE           0x0425
#define SIMULCRYPT_PSIG_STREAM_ERROR                    0x0426

#define SIMULCRYPT_PSIG_CIM_STREAM_SECTION_PROVISION    0x0431
#define SIMULCRYPT_PSIG_CIM_CHANNEL_RESET               0x0432

#define SIMULCRYPT_PSIG_CIM_STREAM_BW_REQUEST           0x0441
#define SIMULCRYPT_PSIG_CIM_STREAM_BW_ALLOCATION        0x0442
#define SIMULCRYPT_PSIG_CIM_STREAM_DATA_PROVISION       0x0443

/* User defined 0x8000 - 0xFFFF */

static const value_string messagetypenames[] = {
	{ SIMULCRYPT_ECMG_CHANNEL_SETUP,                  "CHANNEL_SETUP" },
	{ SIMULCRYPT_ECMG_CHANNEL_TEST,                   "CHANNEL_TEST" },
	{ SIMULCRYPT_ECMG_CHANNEL_STATUS,                 "CHANNEL_STATUS" },
	{ SIMULCRYPT_ECMG_CHANNEL_CLOSE,                  "CHANNEL_CLOSE" },
	{ SIMULCRYPT_ECMG_CHANNEL_ERROR,                  "CHANNEL_ERROR" },

	{ SIMULCRYPT_EMMG_CHANNEL_SETUP,                  "CHANNEL_SETUP" },
	{ SIMULCRYPT_EMMG_CHANNEL_TEST,                   "CHANNEL_TEST" },
	{ SIMULCRYPT_EMMG_CHANNEL_STATUS,                 "CHANNEL_STATUS" },
	{ SIMULCRYPT_EMMG_CHANNEL_CLOSE,                  "CHANNEL_CLOSE" },
	{ SIMULCRYPT_EMMG_CHANNEL_ERROR,                  "CHANNEL_ERROR" },

	{ SIMULCRYPT_ECMG_STREAM_SETUP,                   "STREAM_SETUP" },
	{ SIMULCRYPT_ECMG_STREAM_TEST,                    "STREAM_TEST" },
	{ SIMULCRYPT_ECMG_STREAM_STATUS,                  "STREAM_STATUS" },
	{ SIMULCRYPT_ECMG_STREAM_CLOSE_REQUEST,           "STREAM_CLOSE_REQUEST" },
	{ SIMULCRYPT_ECMG_STREAM_CLOSE_RESPONSE,          "STREAM_CLOSE_RESPONSE" },
	{ SIMULCRYPT_ECMG_STREAM_ERROR,                   "STREAM_ERROR" },

	{ SIMULCRYPT_EMMG_STREAM_SETUP,                   "STREAM_SETUP" },
	{ SIMULCRYPT_EMMG_STREAM_TEST,                    "STREAM_TEST" },
	{ SIMULCRYPT_EMMG_STREAM_STATUS,                  "STREAM_STATUS" },
	{ SIMULCRYPT_EMMG_STREAM_CLOSE_REQUEST,           "STREAM_CLOSE_REQUEST" },
	{ SIMULCRYPT_EMMG_STREAM_CLOSE_RESPONSE,          "STREAM_CLOSE_RESPONSE" },
	{ SIMULCRYPT_EMMG_STREAM_ERROR,                   "STREAM_ERROR" },
	{ SIMULCRYPT_EMMG_STREAM_BW_REQUEST,              "STREAM_BW_REQUEST" },
	{ SIMULCRYPT_EMMG_STREAM_BW_ALLOCATION,           "STREAM_BW_ALLOCATION" },

	{ SIMULCRYPT_ECMG_CW_PROVISION,                   "CW_PROVISION" },
	{ SIMULCRYPT_ECMG_ECM_RESPONSE,                   "ECM_RESPONSE" },

	{ SIMULCRYPT_EMMG_DATA_PROVISION,                 "DATA_PROVISION" },

	{ SIMULCRYPT_EIS_CHANNEL_SET_UP,                  "CHANNEL_SET_UP" },
	{ SIMULCRYPT_EIS_CHANNEL_TEST,                    "CHANNEL_TEST" },
	{ SIMULCRYPT_EIS_CHANNEL_STATUS,                  "CHANNEL_STATUS" },
	{ SIMULCRYPT_EIS_CHANNEL_CLOSE,                   "CHANNEL_CLOSE" },
	{ SIMULCRYPT_EIS_CHANNEL_ERROR,                   "CHANNEL_ERROR" },
	{ SIMULCRYPT_EIS_CHANNEL_RESET,                   "CHANNEL_RESET" },

	{ SIMULCRYPT_EIS_SCG_PROVISION,                   "SCG_PROVISION" },
	{ SIMULCRYPT_EIS_SCG_TEST,                        "SCG_TEST" },
	{ SIMULCRYPT_EIS_SCG_STATUS,                      "SCG_STATUS" },
	{ SIMULCRYPT_EIS_SCG_ERROR,                       "SCG_ERROR" },
	{ SIMULCRYPT_EIS_SCG_LIST_REQUEST,                "SCG_LIST_REQUEST" },
	{ SIMULCRYPT_EIS_SCG_LIST_RESPONSE,               "SCG_LIST_RESPONSE" },


	{ SIMULCRYPT_PSIG_CHANNEL_SETUP,                  "CHANNEL_SETUP" },
	{ SIMULCRYPT_PSIG_CHANNEL_TEST,                   "CHANNEL_TEST" },
	{ SIMULCRYPT_PSIG_CHANNEL_STATUS,                 "CHANNEL_STATUS" },
	{ SIMULCRYPT_PSIG_CHANNEL_CLOSE,                  "CHANNEL_CLOSE" },
	{ SIMULCRYPT_PSIG_CHANNEL_ERROR,                  "CHANNEL_ERROR" },

	{ SIMULCRYPT_PSIG_STREAM_SETUP,                   "STREAM_SETUP" },
	{ SIMULCRYPT_PSIG_STREAM_TEST,                    "STREAM_TEST" },
	{ SIMULCRYPT_PSIG_STREAM_STATUS,                  "STREAM_STATUS" },
	{ SIMULCRYPT_PSIG_STREAM_CLOSE_REQUEST,           "STREAM_CLOSE_REQUEST" },
	{ SIMULCRYPT_PSIG_STREAM_CLOSE_RESPONSE,          "STREAM_CLOSE_RESPONSE" },
	{ SIMULCRYPT_PSIG_STREAM_ERROR,                   "STREAM_ERROR" },

	{ SIMULCRYPT_PSIG_CIM_STREAM_SECTION_PROVISION,   "CIM_STREAM_SECTION_PROVISION"},
	{ SIMULCRYPT_PSIG_CIM_CHANNEL_RESET,              "CIM_CHANNEL_RESET"},

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

/* Simulcrypt EIS Parameter Types */
#define SIMULCRYPT_EIS_DVB_RESERVED                     0x0000
#define SIMULCRYPT_EIS_CHANNEL_ID                       0x0001
#define SIMULCRYPT_EIS_SERVICE_FLAG                     0x0002
#define SIMULCRYPT_EIS_COMPONENT_FLAG                   0x0003
#define SIMULCRYPT_EIS_MAX_SCG                          0x0004
#define SIMULCRYPT_EIS_ECM_GROUP                        0x0005
#define SIMULCRYPT_EIS_SCG_ID                           0x0006
#define SIMULCRYPT_EIS_SCG_REFERENCE_ID                 0x0007
#define SIMULCRYPT_EIS_SUPER_CAS_ID                     0x0008
#define SIMULCRYPT_EIS_ECM_ID                           0x0009
#define SIMULCRYPT_EIS_ACCESS_CRITERIA                  0x000A
#define SIMULCRYPT_EIS_ACTIVATION_TIME                  0x000B
#define SIMULCRYPT_EIS_ACTIVATION_PENDING_FLAG          0x000C
#define SIMULCRYPT_EIS_COMPONENT_ID                     0x000D
#define SIMULCRYPT_EIS_SERVICE_ID                       0x000E
#define SIMULCRYPT_EIS_TRANSPORT_STREAM_ID              0x000F
#define SIMULCRYPT_EIS_AC_CHANGED_FLAG                  0x0010
#define SIMULCRYPT_EIS_SCG_CURRENT_REFERENCE_ID         0x0011
#define SIMULCRYPT_EIS_SCG_PENDING_REFERENCE_ID         0x0012
#define SIMULCRYPT_EIS_CP_DURATION_FLAG                 0x0013
#define SIMULCRYPT_EIS_RECOMMENDED_CP_DURATION          0x0014
#define SIMULCRYPT_EIS_SCG_NOMINAL_CP_DURATION          0x0015
#define SIMULCRYPT_EIS_ORIGINAL_NETWORK_ID              0x0016

#define SIMULCRYPT_EIS_ERROR_STATUS                     0x7000
#define SIMULCRYPT_EIS_ERROR_INFORMATION                0x7001
#define SIMULCRYPT_EIS_ERROR_DESCRIPTION                0x7002

static const value_string eis_parametertypenames[] = {
	{ SIMULCRYPT_EIS_DVB_RESERVED,                  "DVB_RESERVED" },
	{ SIMULCRYPT_EIS_CHANNEL_ID,                    "EIS_CHANNEL_ID" },
	{ SIMULCRYPT_EIS_SERVICE_FLAG,                  "SERVICE_FLAG" },
	{ SIMULCRYPT_EIS_COMPONENT_FLAG,                "COMPONENT_FLAG" },
	{ SIMULCRYPT_EIS_MAX_SCG,                       "MAX_SCG" },
	{ SIMULCRYPT_EIS_ECM_GROUP,                     "ECM_GROUP" },
	{ SIMULCRYPT_EIS_SCG_ID,                        "SCG_ID" },
	{ SIMULCRYPT_EIS_SCG_REFERENCE_ID,              "SCG_REFERENCE_ID" },
	{ SIMULCRYPT_EIS_SUPER_CAS_ID,                  "SUPER_CAS_ID" },
	{ SIMULCRYPT_EIS_ECM_ID,                        "ECM_ID" },
	{ SIMULCRYPT_EIS_ACCESS_CRITERIA,               "ACCESS_CRITERIA" },
	{ SIMULCRYPT_EIS_ACTIVATION_TIME,               "ACTIVATION_TIME" },
	{ SIMULCRYPT_EIS_ACTIVATION_PENDING_FLAG,       "ACTIVATION_PENDING_FLAG" },
	{ SIMULCRYPT_EIS_COMPONENT_ID,                  "COMPONENT_ID" },
	{ SIMULCRYPT_EIS_SERVICE_ID,                    "SERVICE_ID" },
	{ SIMULCRYPT_EIS_TRANSPORT_STREAM_ID,           "TRANSPORT_STREAM_ID" },
	{ SIMULCRYPT_EIS_AC_CHANGED_FLAG,               "AC_CHANGED_FLAG" },
	{ SIMULCRYPT_EIS_SCG_CURRENT_REFERENCE_ID,      "SCG_CURRENT_REFERENCE_ID" },
	{ SIMULCRYPT_EIS_SCG_PENDING_REFERENCE_ID,      "SCG_PENDING_REFERENCE_ID" },
	{ SIMULCRYPT_EIS_CP_DURATION_FLAG,              "CP_DURATION_FLAG" },
	{ SIMULCRYPT_EIS_RECOMMENDED_CP_DURATION,       "RECOMMENDED_CP_DURATION" },
	{ SIMULCRYPT_EIS_SCG_NOMINAL_CP_DURATION,       "SCG_NOMINAL_CP_DURATION" },
	{ SIMULCRYPT_EIS_ORIGINAL_NETWORK_ID,           "ORIGINAL_NETWORK_ID" },

	{ SIMULCRYPT_EIS_ERROR_STATUS,                  "ERROR_STATUS" },
	{ SIMULCRYPT_EIS_ERROR_INFORMATION,             "ERROR_INFORMATION" },
	{ SIMULCRYPT_EIS_ERROR_DESCRIPTION,             "ERROR_DESCRIPTION" },

	{ 0, NULL }
};

/* Simulcrypt EIS protocol error values */
static const value_string eis_error_values[] = {
	{ 0x0000, "DVB Reserved" },
	{ 0x0001, "Invalid message" },
	{ 0x0002, "Unsupported protocol version" },
	{ 0x0003, "Unknown message_type value" },
	{ 0x0004, "Message too long" },
	{ 0x0005, "Inconsistent length for parameter" },
	{ 0x0006, "Missing mandatory parameter" },
	{ 0x0007, "Invalid value for parameter" },
	{ 0x0008, "Unknown EIS_channel_ID value" },
	{ 0x0009, "Unknown SCG_ID value" },
	{ 0x000A, "Max SCGs already defined" },
	{ 0x000B, "Service level SCG definitions not supportend" },
	{ 0x000C, "Elementary Stream level SCG definitions not supported" },
	{ 0x000D, "Activation_time possibly too soon for SCS to be accurate" },
	{ 0x000E, "SCG definition cannot span transport boundaries" },
	{ 0x000F, "A resource does not exist on this SCG" },
	{ 0x0010, "A resource is already defined in an existing SCG" },
	{ 0x0011, "SCG may not contain one or more content entries and no ECM_Group entries" },
	{ 0x0012, "SCG may not contain one or more ECM_Group entries and no content entries" },
	{ 0x0013, "EIS_channel_ID value already in use" },
	{ 0x0014, "Unknown Super_CAS_Id" },

	{ 0x7000, "Unknown error" },
	{ 0x7001, "Unrecoverable error" },

	{ 0, NULL }
};

/* Simulcrypt PSIG Parameter Types */
#define SIMULCRYPT_PSIG_DVB_RESERVED                    0x0000
#define SIMULCRYPT_PSIG_PSIG_TYPE                       0x0001
#define SIMULCRYPT_PSIG_CHANNEL_ID                      0x0002
#define SIMULCRYPT_PSIG_STREAM_ID                       0x0003
#define SIMULCRYPT_PSIG_TRANSPORT_STREAM_ID             0x0004
#define SIMULCRYPT_PSIG_ORIGINAL_NETWORK_ID             0x0005
#define SIMULCRYPT_PSIG_PACKET_ID                       0x0006
#define SIMULCRYPT_PSIG_INTERFACE_MODE_CONFIGURATION    0x0007
#define SIMULCRYPT_PSIG_MAX_STREAM                      0x0008
#define SIMULCRYPT_PSIG_TABLE_PERIOD_PAIR               0x0009
#define SIMULCRYPT_PSIG_MPEG_SECTION                    0x000A
#define SIMULCRYPT_PSIG_REPETITION_RATE                 0x000B
#define SIMULCRYPT_PSIG_ACTIVATION_TIME                 0x000C
#define SIMULCRYPT_PSIG_DATAGRAM                        0x000D
#define SIMULCRYPT_PSIG_BANDWIDTH                       0x000E
#define SIMULCRYPT_PSIG_INITIAL_BANDWIDTH               0x000F
#define SIMULCRYPT_PSIG_MAX_COMP_TIME                   0x0010
#define SIMULCRYPT_PSIG_ASI_INPUT_PACKET_ID             0x0011

#define SIMULCRYPT_PSIG_ERROR_STATUS                    0x7000
#define SIMULCRYPT_PSIG_ERROR_INFORMATION               0x7001

static const value_string psig_parametertypenames[] = {
	{ SIMULCRYPT_PSIG_DVB_RESERVED,                  "DVB_RESERVED" },
	{ SIMULCRYPT_PSIG_PSIG_TYPE,                     "PSIG_TYPE" },
	{ SIMULCRYPT_PSIG_CHANNEL_ID,                    "PSIG_CHANNEL_ID" },
	{ SIMULCRYPT_PSIG_STREAM_ID,                     "STREAM_ID" },
	{ SIMULCRYPT_PSIG_TRANSPORT_STREAM_ID,           "TRANSPORT_STREAM_ID" },
	{ SIMULCRYPT_PSIG_ORIGINAL_NETWORK_ID,           "ORIGINAL_NETWORK_ID" },
	{ SIMULCRYPT_PSIG_PACKET_ID,                     "PACKET_ID" },
	{ SIMULCRYPT_PSIG_INTERFACE_MODE_CONFIGURATION,  "INTERFACE_MODE_CONFIGURATION" },
	{ SIMULCRYPT_PSIG_MAX_STREAM,                    "MAX_STREAM" },
	{ SIMULCRYPT_PSIG_TABLE_PERIOD_PAIR,             "TABLE_PERIOD_PAIR" },
	{ SIMULCRYPT_PSIG_MPEG_SECTION,                  "MPEG_SECTION" },
	{ SIMULCRYPT_PSIG_REPETITION_RATE,               "REPETITION_RATE" },
	{ SIMULCRYPT_PSIG_ACTIVATION_TIME,               "ACTIVATION_TIME" },
	{ SIMULCRYPT_PSIG_DATAGRAM,                      "DATAGRAM" },
	{ SIMULCRYPT_PSIG_BANDWIDTH,                     "BANDWIDTH" },
	{ SIMULCRYPT_PSIG_INITIAL_BANDWIDTH,             "INITIAL_BANDWIDTH" },
	{ SIMULCRYPT_PSIG_MAX_COMP_TIME,                 "MAX_COMP_TIME" },
	{ SIMULCRYPT_PSIG_ASI_INPUT_PACKET_ID,           "ASI_INPUT_PACKET_ID" },

	{ SIMULCRYPT_PSIG_ERROR_STATUS,                  "ERROR_STATUS" },
	{ SIMULCRYPT_PSIG_ERROR_INFORMATION,             "ERROR_INFORMATION" },

	{ 0, NULL }
};

/* Simulcrypt PSIG protocol error values */
static const value_string psig_error_values[] = {
	{ 0x0000, "DVB Reserved" },
	{ 0x0001, "Invalid message" },
	{ 0x0002, "Unsupported protocol version" },
	{ 0x0003, "Unknown message_type value" },
	{ 0x0004, "Message too long" },
	{ 0x0005, "Unknown stream_ID value" },
	{ 0x0006, "Unknown channel_ID value" },
	{ 0x0007, "Too many channels on this MUX" },
	{ 0x0008, "Too many data streams on this channel" },
	{ 0x0009, "Too many data streams on this MUX" },
	{ 0x000A, "Unknown parameter_type" },
	{ 0x000B, "Inconsistent length for parameter" },
	{ 0x000C, "Missing mandatory parameter" },
	{ 0x000D, "Invalid value for parameter" },
	{ 0x000E, "Inconsistent value of transport_stream_ID" },
	{ 0x000F, "Inconsistent value of packet_ID" },
	{ 0x0010, "channel_ID value already in use" },
	{ 0x0011, "stream_ID value already in use" },
	{ 0x0012, "Stream already open for this pair (transport_stream_ID, packet_ID)" },
	{ 0x0013, "Overflow error when receiving the list of MPEG (CiM error type)" },
	{ 0x0014, "Inconsistent format of TOT template (CiM error type)" },
	{ 0x0015, "Warning: Difficulties in respecting the requested repetition_rates for the last 5 minutes (CiM error type)" },
	{ 0x0016, "Warning: Difficulties in respecting the requested Bandwidth for the last 5 minutes (CiM error type)" },

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

static gint hf_simulcrypt_eis_parameter_type = -1;
static gint hf_simulcrypt_eis_channel_id = -1;
static gint hf_simulcrypt_service_flag = -1;
static gint hf_simulcrypt_component_flag = -1;
static gint hf_simulcrypt_max_scg = -1;
static gint hf_simulcrypt_ecm_group = -1;
static gint hf_simulcrypt_scg_id = -1;
static gint hf_simulcrypt_scg_reference_id = -1;
static gint hf_simulcrypt_activation_time = -1;
static gint hf_simulcrypt_year = -1;
static gint hf_simulcrypt_month = -1;
static gint hf_simulcrypt_day = -1;
static gint hf_simulcrypt_hour = -1;
static gint hf_simulcrypt_minute = -1;
static gint hf_simulcrypt_second = -1;
static gint hf_simulcrypt_hundredth_second = -1;
static gint hf_simulcrypt_activation_pending_flag = -1;
static gint hf_simulcrypt_component_id = -1;
static gint hf_simulcrypt_service_id = -1;
static gint hf_simulcrypt_transport_stream_id = -1;
static gint hf_simulcrypt_ac_changed_flag = -1;
static gint hf_simulcrypt_scg_current_reference_id = -1;
static gint hf_simulcrypt_scg_pending_reference_id = -1;
static gint hf_simulcrypt_cp_duration_flag = -1;
static gint hf_simulcrypt_recommended_cp_duration = -1;
static gint hf_simulcrypt_scg_nominal_cp_duration = -1;
static gint hf_simulcrypt_original_network_id = -1;
static gint hf_simulcrypt_eis_error_status = -1;
static gint hf_simulcrypt_error_description = -1;

static gint hf_simulcrypt_psig_parameter_type = -1;
static gint hf_simulcrypt_psig_type = -1;
static gint hf_simulcrypt_channel_id = -1;
static gint hf_simulcrypt_stream_id = -1;
static gint hf_simulcrypt_packet_id = -1;
static gint hf_simulcrypt_interface_mode_configuration = -1;
static gint hf_simulcrypt_max_stream = -1;
static gint hf_simulcrypt_table_period_pair = -1;
static gint hf_simulcrypt_mpeg_section = -1;
static gint hf_simulcrypt_repetition_rate = -1;
static gint hf_simulcrypt_initial_bandwidth = -1;
static gint hf_simulcrypt_asi_input_packet_id = -1;
static gint hf_simulcrypt_psig_error_status = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_simulcrypt = -1;
static gint ett_simulcrypt_header = -1;
static gint ett_simulcrypt_message = -1;
static gint ett_simulcrypt_parameter = -1;
static gint ett_simulcrypt_super_cas_id = -1;
static gint ett_simulcrypt_ecm_datagram = -1;
static gint ett_simulcrypt_ecm_group = -1;
static gint ett_simulcrypt_activation_time = -1;
static gint ett_simulcrypt_table_period_pair = -1;


#define FRAME_HEADER_LEN 8

/* The main dissecting routine */
static void
dissect_simulcrypt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
dissect_ecmg_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
                              guint16 plen, guint16 ptype, gchar *pvalue_char)
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
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_super_cas_id, tvb, offset, plen, ENC_BIG_ENDIAN); /* value item */
		simulcrypt_super_cas_id_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_super_cas_id);

		/* Simulcrypt_super_cas_id_tree */
		simulcrypt_item = proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_system_id, tvb, offset, 2, ENC_BIG_ENDIAN );

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
		proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_subsystem_id, tvb, offset+2, 2, ENC_BIG_ENDIAN );
		break;
	case SIMULCRYPT_ECMG_SECTION_TSPKT_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_section_tspkt_flag, tvb, offset, plen, ENC_BIG_ENDIAN); /* value item */
		break;
	case SIMULCRYPT_ECMG_ECM_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_channel_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_delay_start, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_delay_stop, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_TRANSITION_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_transition_delay_start, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_TRANSITION_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_transition_delay_stop, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_AC_DELAY_START:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ac_delay_start, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_AC_DELAY_STOP:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ac_delay_stop, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_ECM_REP_PERIOD:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ecm_rep_period, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_MAX_STREAMS:
		proto_tree_add_item(tree, hf_simulcrypt_max_streams, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_MIN_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte min CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_min_cp_duration, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (%d ms)",pvaluedec);
		break;
	case SIMULCRYPT_ECMG_LEAD_CW:
		proto_tree_add_item(tree, hf_simulcrypt_lead_cw, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_CW_PER_MESSAGE:
		proto_tree_add_item(tree, hf_simulcrypt_cw_per_msg, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_MAX_COMP_TIME:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_max_comp_time, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_ECMG_ACCESS_CRITERIA:
		proto_tree_add_item(tree, hf_simulcrypt_access_criteria, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_ECMG_ECM_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_stream_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_NOMINAL_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte nominal CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_nominal_cp_duration, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_ECMG_ACCESS_CRITERIA_TRANSFER_MODE:
		proto_tree_add_item(tree, hf_simulcrypt_access_criteria_transfer_mode, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_CP_NUMBER:
		proto_tree_add_item(tree, hf_simulcrypt_cp_number, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_cp_duration, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_ECMG_CP_CW_COMBINATION:
		proto_tree_add_item(tree, hf_simulcrypt_cp_cw_combination, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_ECMG_ECM_DATAGRAM:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ecm_datagram, tvb, offset, plen, ENC_NA);
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
		proto_tree_add_item(tree, hf_simulcrypt_cw_encryption, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_ECMG_ECM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_ecmg_error_status, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_ECMG_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, ENC_NA);
		break;
	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char);
		break;
	} /* end parameter type switch */
}

static void
dissect_emmg_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint32 offset,
                              guint16 plen, guint16 ptype, gchar *pvalue_char)
{
	proto_item *simulcrypt_item;

	switch (ptype) {
	case SIMULCRYPT_EMMG_CLIENT_ID:
		proto_tree_add_item(tree, hf_simulcrypt_client_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_SECTION_TSPKT_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_section_tspkt_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_DATA_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_channel_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_DATA_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_stream_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_DATAGRAM:
		proto_tree_add_item(tree, hf_simulcrypt_datagram, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_EMMG_BANDWIDTH:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_bandwidth, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " kbit/s");
		break;
	case SIMULCRYPT_EMMG_DATA_TYPE:
		proto_tree_add_item(tree, hf_simulcrypt_data_type, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_DATA_ID:
		proto_tree_add_item(tree, hf_simulcrypt_data_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_emmg_error_status, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EMMG_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, ENC_NA);
		break;
	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char);
		break;
	} /* end parameter type switch */
}


static void
dissect_eis_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint32 offset,
                             guint16 plen, guint16 ptype, gchar *pvalue_char)
{
	proto_item *simulcrypt_item;
	proto_tree *simulcrypt_super_cas_id_tree;
	proto_tree *simulcrypt_ecm_group_tree;
	proto_tree *simulcrypt_activation_time_tree;
	guint32     pvaluedec;    /* parameter decimal value */
	int         ca_system_id;
	guint       i;

	switch (ptype) {
	case SIMULCRYPT_EIS_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_eis_channel_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SERVICE_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_service_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_COMPONENT_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_component_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_MAX_SCG:
		proto_tree_add_item(tree, hf_simulcrypt_max_scg, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_ECM_GROUP:
		/* add ECM_Group item */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_ecm_group, tvb, offset, plen, ENC_NA); /* value item */

		/* create subtree */
		simulcrypt_ecm_group_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_ecm_group);

		/* dissect subtree */
		dissect_simulcrypt_data(simulcrypt_ecm_group_tree, simulcrypt_item, pinfo, tvb, tree, offset, plen, SIMULCRYPT_EIS_SCS, TRUE);
		break;
	case SIMULCRYPT_EIS_SCG_ID:
		proto_tree_add_item(tree, hf_simulcrypt_scg_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SCG_REFERENCE_ID:
		proto_tree_add_item(tree, hf_simulcrypt_scg_reference_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SUPER_CAS_ID:
		/* add super_cas_id item */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_super_cas_id, tvb, offset, plen, ENC_BIG_ENDIAN); /* value item */
		simulcrypt_super_cas_id_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_super_cas_id);

		/* Simulcrypt_super_cas_id_tree */
		simulcrypt_item = proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_system_id, tvb, offset, 2, ENC_BIG_ENDIAN );

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
		proto_tree_add_item(simulcrypt_super_cas_id_tree, hf_simulcrypt_ca_subsystem_id, tvb, offset+2, 2, ENC_BIG_ENDIAN );
		break;
	case SIMULCRYPT_EIS_ECM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_ecm_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_ACCESS_CRITERIA:
		proto_tree_add_item(tree, hf_simulcrypt_access_criteria, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_EIS_ACTIVATION_TIME:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_activation_time, tvb, offset, plen, ENC_NA); /* value item */

		/* create subtree */
		simulcrypt_activation_time_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_activation_time);

		/* dissect subtree */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_year, tvb, offset, 2, ENC_BIG_ENDIAN); /* first 2 bytes */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_month, tvb, offset+2, 1, ENC_BIG_ENDIAN); /* third byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_day, tvb, offset+3, 1, ENC_BIG_ENDIAN); /*fourth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_hour, tvb, offset+4, 1, ENC_BIG_ENDIAN); /*fifth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_minute, tvb, offset+5, 1, ENC_BIG_ENDIAN); /* sixth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_second, tvb, offset+6, 1, ENC_BIG_ENDIAN); /* seventh byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_hundredth_second, tvb, offset+7, 1, ENC_BIG_ENDIAN); /* eighth byte */
		break;
	case SIMULCRYPT_EIS_ACTIVATION_PENDING_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_activation_pending_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_COMPONENT_ID:
		proto_tree_add_item(tree, hf_simulcrypt_component_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SERVICE_ID:
		proto_tree_add_item(tree, hf_simulcrypt_service_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_TRANSPORT_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_transport_stream_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_AC_CHANGED_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_ac_changed_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SCG_CURRENT_REFERENCE_ID:
		proto_tree_add_item(tree, hf_simulcrypt_scg_current_reference_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_SCG_PENDING_REFERENCE_ID:
		proto_tree_add_item(tree, hf_simulcrypt_scg_pending_reference_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_CP_DURATION_FLAG:
		proto_tree_add_item(tree, hf_simulcrypt_cp_duration_flag, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_RECOMMENDED_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_recommended_cp_duration, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_EIS_SCG_NOMINAL_CP_DURATION:
		/* convert value to ms (in units 100 ms) */
		pvaluedec = tvb_get_ntohs(tvb, offset); /* read 2 byte CP duration value */
		pvaluedec = pvaluedec*100; /* in ms now */
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_scg_nominal_cp_duration, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (%d ms)", pvaluedec);
		break;
	case SIMULCRYPT_EIS_ORIGINAL_NETWORK_ID:
		proto_tree_add_item(tree, hf_simulcrypt_original_network_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;

	case SIMULCRYPT_EIS_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_eis_error_status, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_EIS_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_EIS_ERROR_DESCRIPTION:
		proto_tree_add_item(tree, hf_simulcrypt_error_description, tvb, offset, plen, ENC_ASCII|ENC_NA);
		break;

	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char);
		break;
	} /* end parameter type switch */
}

static void
dissect_psig_parameter_value (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint32 offset,
                              guint16 plen, guint16 ptype, gchar *pvalue_char)
{
	proto_tree *simulcrypt_psig_table_period_pair_tree;
	proto_tree *simulcrypt_activation_time_tree;
	proto_item *simulcrypt_item;
	guint32     pvaluedec;    /* parameter decimal value */

	switch (ptype) {
	case SIMULCRYPT_PSIG_PSIG_TYPE:
		pvaluedec = tvb_get_guint8(tvb, offset);
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_psig_type, tvb, offset, plen, ENC_BIG_ENDIAN);
		switch(pvaluedec){
		case 1:
			proto_item_append_text(simulcrypt_item, " (PSIG)");
			break;
		case 2:
			proto_item_append_text(simulcrypt_item, " (SIG)");
			break;
		case 3:
			proto_item_append_text(simulcrypt_item, " (PSISIG)");
			break;
		default:
			break;
		}
		break;
	case SIMULCRYPT_PSIG_CHANNEL_ID:
		proto_tree_add_item(tree, hf_simulcrypt_channel_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_stream_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_TRANSPORT_STREAM_ID:
		proto_tree_add_item(tree, hf_simulcrypt_transport_stream_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_ORIGINAL_NETWORK_ID:
		proto_tree_add_item(tree, hf_simulcrypt_original_network_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_PACKET_ID:
		proto_tree_add_item(tree, hf_simulcrypt_packet_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_INTERFACE_MODE_CONFIGURATION:
		proto_tree_add_item(tree, hf_simulcrypt_interface_mode_configuration, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_MAX_STREAM:
		proto_tree_add_item(tree, hf_simulcrypt_max_stream, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_TABLE_PERIOD_PAIR:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_table_period_pair, tvb, offset, plen, ENC_NA); /* value item */

		/* create subtree */
		simulcrypt_psig_table_period_pair_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_table_period_pair);

		/* dissect subtree */
		dissect_simulcrypt_data(simulcrypt_psig_table_period_pair_tree, simulcrypt_item, pinfo, tvb, tree, offset, plen, SIMULCRYPT_MUX_CIM, TRUE);
		break;
	case SIMULCRYPT_PSIG_MPEG_SECTION:
		proto_tree_add_item(tree, hf_simulcrypt_mpeg_section, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_PSIG_REPETITION_RATE:
		proto_tree_add_item(tree, hf_simulcrypt_repetition_rate, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_ACTIVATION_TIME:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_activation_time, tvb, offset, plen, ENC_NA); /* value item */

		/* create subtree */
		simulcrypt_activation_time_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_activation_time);

		/* dissect subtree */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_year, tvb, offset, 2, ENC_BIG_ENDIAN); /* first 2 bytes */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_month, tvb, offset+2, 1, ENC_BIG_ENDIAN); /* third byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_day, tvb, offset+3, 1, ENC_BIG_ENDIAN); /*fourth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_hour, tvb, offset+4, 1, ENC_BIG_ENDIAN); /*fifth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_minute, tvb, offset+5, 1, ENC_BIG_ENDIAN); /* sixth byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_second, tvb, offset+6, 1, ENC_BIG_ENDIAN); /* seventh byte */
		proto_tree_add_item(simulcrypt_activation_time_tree, hf_simulcrypt_hundredth_second, tvb, offset+7, 1, ENC_BIG_ENDIAN); /* eighth byte */
		break;
	case SIMULCRYPT_PSIG_DATAGRAM:
		proto_tree_add_item(tree, hf_simulcrypt_datagram, tvb, offset, plen, ENC_NA);
		break;
	case SIMULCRYPT_PSIG_BANDWIDTH:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_bandwidth, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " kbit/s");
		break;
	case SIMULCRYPT_PSIG_INITIAL_BANDWIDTH:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_initial_bandwidth, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " kbit/s");
		break;
	case SIMULCRYPT_PSIG_MAX_COMP_TIME:
		simulcrypt_item = proto_tree_add_item(tree, hf_simulcrypt_max_comp_time, tvb, offset, plen, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " ms");
		break;
	case SIMULCRYPT_PSIG_ASI_INPUT_PACKET_ID:
		proto_tree_add_item(tree, hf_simulcrypt_asi_input_packet_id, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_ERROR_STATUS:
		proto_tree_add_item(tree, hf_simulcrypt_psig_error_status, tvb, offset, plen, ENC_BIG_ENDIAN);
		break;
	case SIMULCRYPT_PSIG_ERROR_INFORMATION:
		proto_tree_add_item(tree, hf_simulcrypt_error_information, tvb, offset, plen, ENC_NA);
		break;
	default:  /* Unknown parameter type */
		proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char);
		break;
	} /* end parameter type switch */
}

/* This method dissects fully reassembled messages */
static void
dissect_simulcrypt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *simulcrypt_item;
	proto_tree *simulcrypt_tree;
	proto_tree *simulcrypt_header_tree;
	proto_tree *simulcrypt_message_tree;
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

		simulcrypt_item = proto_tree_add_item(tree, proto_simulcrypt, tvb, 0, -1, ENC_NA);
		simulcrypt_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt);

		proto_item_append_text(simulcrypt_item, ", Interface: %s", val_to_str(iftype, interfacenames, "Unknown (0x%02x)"));

		/* Simulcrypt_tree analysis */
		/* we are being asked for details */
		/* ADD HEADER BRANCH */
		simulcrypt_item = proto_tree_add_item(simulcrypt_tree, hf_simulcrypt_header, tvb, offset, 5, ENC_NA );
		simulcrypt_header_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_header);
		proto_item_append_text(simulcrypt_header_tree, ", Length: %s", "5 bytes"); /* add text to Header tree indicating Length 5 bytes */

		/* Simulcrypt_header_tree analysis */
		/* Message Version 1 Byte */
		proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		/* Message Type 2 Bytes */
		proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		simulcrypt_item = proto_tree_add_uint_format(simulcrypt_header_tree, hf_simulcrypt_interface, tvb, offset, 2, iftype,
							     "Interface: %s", val_to_str(iftype, interfacenames, "Unknown"));
		PROTO_ITEM_SET_GENERATED (simulcrypt_item);
		offset+=2;

		/* Message Length 2 Bytes */
		simulcrypt_item = proto_tree_add_item(simulcrypt_header_tree, hf_simulcrypt_message_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(simulcrypt_item, " (bytes)");
		msg_length = tvb_get_ntohs(tvb, offset); /* read 2 byte message length value */
		offset+=2;

		/* ADD MESSAGE BRANCH */
		simulcrypt_item = proto_tree_add_item(simulcrypt_tree, hf_simulcrypt_message, tvb, offset, -1, ENC_NA );
		simulcrypt_message_tree = proto_item_add_subtree(simulcrypt_item, ett_simulcrypt_message);
		proto_item_append_text(simulcrypt_message_tree, " containing TLV parameters"); /* add text to Message tree	*/
		proto_item_append_text(simulcrypt_message_tree, ", Length: %d (bytes)", msg_length); /* add length info to message_tree */

		/* end header details */

		/* Simulcrypt_message_tree analysis */
		/*  we are being asked for details */
		/* Navigate through message after header to find one or more parameters */

		dissect_simulcrypt_data(simulcrypt_message_tree, simulcrypt_item, pinfo, tvb, tree, offset, (msg_length+5), iftype, FALSE); /* offset is from beginning of the 5 byte header */

	} /* end tree */
}

/* this method is used to dissect TLV parameters */
/* can be used both from the main tree (simulcrypt_message_tree) and the subtrees (created from TLV items) */
static void
dissect_simulcrypt_data(proto_tree *simulcrypt_tree, proto_item *simulcrypt_item, packet_info *pinfo _U_,
                        tvbuff_t *tvb, proto_tree *tree, int offset,
                        int container_data_length, guint16 iftype, gboolean is_subtree)
{
	int subtree_offset = 0;
	proto_tree *simulcrypt_parameter_tree;
	int applied_offset;

	if(is_subtree)
	{
		applied_offset = subtree_offset;
	}
	else
	{
		applied_offset = offset;
	}

	while (applied_offset < container_data_length)
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

		simulcrypt_item = proto_tree_add_item(simulcrypt_tree, hf_simulcrypt_parameter, tvb, offset, plen+2+2, ENC_NA );

		/* add length and value info to type */
		switch (iftype) {
		case SIMULCRYPT_ECMG_SCS:
			proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, ecmg_parametertypenames, "Unknown Type:0x%02x"));
			break;
		case SIMULCRYPT_EMMG_MUX:
			proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, emmg_parametertypenames, "Unknown Type:0x%02x"));
			break;
		case SIMULCRYPT_EIS_SCS:
			proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, eis_parametertypenames, "Unknown Type:0x%02x"));
			break;
		case SIMULCRYPT_PSIG_MUX:
		case SIMULCRYPT_MUX_CIM:
		case SIMULCRYPT_PSIG_CIP:
			proto_item_append_text(simulcrypt_item, ": Type=%s", val_to_str(ptype, psig_parametertypenames, "Unknown Type:0x%02x"));
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
			proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_ecmg_parameter_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		case SIMULCRYPT_EMMG_MUX:
			proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_emmg_parameter_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		case SIMULCRYPT_EIS_SCS:
			proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_eis_parameter_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		case SIMULCRYPT_PSIG_MUX:
		case SIMULCRYPT_MUX_CIM:
		case SIMULCRYPT_PSIG_CIP:
			proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_psig_parameter_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		default:
			proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_parameter_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		}
		simulcrypt_item = proto_tree_add_item(simulcrypt_parameter_tree, hf_simulcrypt_parameter_length, tvb, offset+2, 2, ENC_BIG_ENDIAN); /* length item */
		proto_item_append_text(simulcrypt_item, " (bytes)");
		offset += 2+2;  /* offset --> parameter value */

		switch (iftype) {
		case SIMULCRYPT_ECMG_SCS:
			dissect_ecmg_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
			break;
		case SIMULCRYPT_EMMG_MUX:
			dissect_emmg_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
			break;
		case SIMULCRYPT_EIS_SCS:
			dissect_eis_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
			break;
		case SIMULCRYPT_PSIG_MUX:
		case SIMULCRYPT_MUX_CIM:
		case SIMULCRYPT_PSIG_CIP:
			dissect_psig_parameter_value (simulcrypt_parameter_tree, tvb, pinfo, offset, plen, ptype, pvalue_char);
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, plen, "Parameter Value: %s", pvalue_char);
			break;
		}
		offset         += plen;
		subtree_offset += 2+2+plen;

		if(is_subtree)
		{
			applied_offset = subtree_offset;
		}
		else
		{
			applied_offset = offset;
		}
	} /* end parameter tree details */
}


/* determine PDU length of protocol foo */
static guint
get_simulcrypt_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
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

void
proto_register_simulcrypt (void)
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
		 NULL, HFILL }},

		{ &hf_simulcrypt_eis_parameter_type,
		{ "Parameter Type", "simulcrypt.parameter.type", FT_UINT16, BASE_HEX, VALS(eis_parametertypenames), 0x0,	/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_eis_channel_id,
		{ "EIS channel ID", "simulcrypt.parameter.eis_channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_service_flag,
		{ "Service flag", "simulcrypt.parameter.service_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_component_flag,
		{ "Component flag", "simulcrypt.parameter.component_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_max_scg,
		{ "Max SCG", "simulcrypt.parameter.max_scg", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ecm_group,
		{ "ECM group", "simulcrypt.parameter.ecm_group", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_scg_id,
		{ "SCG ID", "simulcrypt.parameter.scg_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_scg_reference_id,
		{ "SCG reference ID", "simulcrypt.parameter.scg_reference_id", FT_UINT32, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_activation_time,
		{ "Activation time", "simulcrypt.parameter.activation_time", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_year,
		{ "Year", "simulcrypt.parameter.year", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_month,
		{ "Month", "simulcrypt.parameter.month", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_day,
		{ "Day", "simulcrypt.parameter.day", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_hour,
		{ "Hour", "simulcrypt.parameter.hour", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_minute,
		{ "Minute", "simulcrypt.parameter.minute", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_second,
		{ "Second", "simulcrypt.parameter.second", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_hundredth_second,
		{ "Hundredth_second", "simulcrypt.parameter.hundredth_second", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_activation_pending_flag,
		{ "Activation pending flag", "simulcrypt.parameter.activation_pending_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_component_id,
		{ "Component ID", "simulcrypt.parameter.component_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_service_id,
		{ "Service ID", "simulcrypt.parameter.service_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_transport_stream_id,
		{ "Transport stream ID", "simulcrypt.parameter.transport_stream_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_ac_changed_flag,
		{ "AC changed flag", "simulcrypt.parameter.ac_changed_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_scg_current_reference_id,
		{ "SCG current reference ID", "simulcrypt.parameter.scg_current_reference_id", FT_UINT32, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_scg_pending_reference_id,
		{ "SCG pending reference ID", "simulcrypt.parameter.scg_pending_reference_id", FT_UINT32, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_cp_duration_flag,
		{ "CP duration flag", "simulcrypt.parameter.cp_duration_flag", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_recommended_cp_duration,
		{ "Recommended CP duration", "simulcrypt.parameter.recommended_cp_duration", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_scg_nominal_cp_duration,
		{ "SCG nominal CP duration", "simulcrypt.parameter.scg_nominal_cp_duration", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_original_network_id,
		{ "Original network ID", "simulcrypt.parameter.original_network_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_eis_error_status,
		{ "Error status", "simulcrypt.error_status", FT_UINT16, BASE_DEC, VALS(eis_error_values), 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_error_description,
		{ "Error status", "simulcrypt.error_description", FT_STRING, BASE_NONE, NULL, 0x0,   /* error_description --> ASCII byte string */
		 NULL, HFILL }},

		{ &hf_simulcrypt_psig_parameter_type,
		{ "Parameter Type", "simulcrypt.parameter.type", FT_UINT16, BASE_HEX, VALS(psig_parametertypenames), 0x0,	/* type 2 bytes */
		 NULL, HFILL }},

		{ &hf_simulcrypt_psig_type,
		{ "PSIG type", "simulcrypt.parameter.psig_type", FT_UINT8, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_channel_id,
		{ "Channel ID", "simulcrypt.parameter.channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_stream_id,
		{ "Stream ID", "simulcrypt.parameter.stream_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_packet_id,
		{ "Packet ID", "simulcrypt.parameter.packet_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_interface_mode_configuration,
		{ "Interface mode configuration", "simulcrypt.parameter.interface_mode_configuration", FT_UINT8, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_max_stream,
		{ "Max stream", "simulcrypt.parameter.max_stream", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_table_period_pair,
		{ "Table period pair", "simulcrypt.parameter.table_period_pair", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_mpeg_section,
		{ "MPEG section", "simulcrypt.parameter.mpeg_section", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_repetition_rate,
		{ "Repetition rate", "simulcrypt.parameter.repetition_rate", FT_UINT32, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_initial_bandwidth,
		{ "Initial bandwidth", "simulcrypt.parameter.initial_bandwidth", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_simulcrypt_asi_input_packet_id,
		{ "ASI input packet ID", "simulcrypt.parameter.asi_input_packet_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

 		{ &hf_simulcrypt_psig_error_status,
		{ "Error status", "simulcrypt.parameter.error_status", FT_UINT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }}
	};

	static gint *ett[] =
	{
		&ett_simulcrypt,
		&ett_simulcrypt_header,
		&ett_simulcrypt_message,
		&ett_simulcrypt_parameter,
		&ett_simulcrypt_super_cas_id,
		&ett_simulcrypt_ecm_datagram,
		&ett_simulcrypt_ecm_group,
		&ett_simulcrypt_activation_time,
		&ett_simulcrypt_table_period_pair
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
void
proto_reg_handoff_simulcrypt(void)
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
		dissector_delete_uint("tcp.port", tcp_port, simulcrypt_handle);
		dissector_delete_uint("udp.port", udp_port, simulcrypt_handle);
	}
	if (global_simulcrypt_tcp_port != 0) {
		dissector_add_uint("tcp.port", global_simulcrypt_tcp_port, simulcrypt_handle);
	}
	if (global_simulcrypt_udp_port != 0) {
		dissector_add_uint("udp.port", global_simulcrypt_udp_port, simulcrypt_handle);
	}
	tcp_port = global_simulcrypt_tcp_port;
	udp_port = global_simulcrypt_udp_port;

	/* update tab_ecm_inter table (always do this) */
	tab_ecm_inter[ECM_MIKEY_INDEX].ca_system_id=ca_system_id_mikey;
}

