/* packet-sua.c
 * Routines for SS7 SCCP-User Adaptation Layer (SUA) dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-sua-08.txt
 * http://www.ietf.org/rfc/rfc3868.txt
 *
 * Copyright 2002, 2003, 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/tap.h>

#include "packet-mtp3.h"
#include "packet-sccp.h"
#include <epan/emem.h>

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)
#define SCTP_PORT_SUA          14001

#define RESERVED_1_LENGTH      1
#define RESERVED_2_LENGTH      2
#define RESERVED_3_LENGTH      3

#define VERSION_LENGTH         1
#define RESERVED_LENGTH        1
#define MESSAGE_CLASS_LENGTH   1
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_LENGTH_LENGTH  4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + RESERVED_LENGTH + MESSAGE_CLASS_LENGTH + \
                                MESSAGE_TYPE_LENGTH + MESSAGE_LENGTH_LENGTH)

#define COMMON_HEADER_OFFSET   0
#define VERSION_OFFSET         COMMON_HEADER_OFFSET
#define RESERVED_OFFSET        (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_CLASS_OFFSET   (RESERVED_OFFSET + RESERVED_LENGTH)
#define MESSAGE_TYPE_OFFSET    (MESSAGE_CLASS_OFFSET + MESSAGE_CLASS_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET      0
#define PARAMETER_LENGTH_OFFSET   (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET    (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET   PARAMETER_TAG_OFFSET

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_TFER_MESSAGE        1
#define MESSAGE_CLASS_SSNM_MESSAGE        2
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_CL_MESSAGE          7
#define MESSAGE_CLASS_CO_MESSAGE          8
#define MESSAGE_CLASS_RKM_MESSAGE         9

static const value_string message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_CL_MESSAGE,     "Connectionless messages" },
  { MESSAGE_CLASS_CO_MESSAGE,     "Connection-Oriented messages" },
  { MESSAGE_CLASS_RKM_MESSAGE,    "Routing key management Messages" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

#define MESSAGE_TYPE_DUNA                 1
#define MESSAGE_TYPE_DAVA                 2
#define MESSAGE_TYPE_DAUD                 3
#define MESSAGE_TYPE_SCON                 4
#define MESSAGE_TYPE_DUPU                 5
#define MESSAGE_TYPE_DRST                 6

#define MESSAGE_TYPE_UP                   1
#define MESSAGE_TYPE_DOWN                 2
#define MESSAGE_TYPE_BEAT                 3
#define MESSAGE_TYPE_UP_ACK               4
#define MESSAGE_TYPE_DOWN_ACK             5
#define MESSAGE_TYPE_BEAT_ACK             6

#define MESSAGE_TYPE_ACTIVE               1
#define MESSAGE_TYPE_INACTIVE             2
#define MESSAGE_TYPE_ACTIVE_ACK           3
#define MESSAGE_TYPE_INACTIVE_ACK         4

#define MESSAGE_TYPE_CLDT                 1
#define MESSAGE_TYPE_CLDR                 2

#define MESSAGE_TYPE_CORE                 1
#define MESSAGE_TYPE_COAK                 2
#define MESSAGE_TYPE_COREF                3
#define MESSAGE_TYPE_RELRE                4
#define MESSAGE_TYPE_RELCO                5
#define MESSAGE_TYPE_RESCO                6
#define MESSAGE_TYPE_RESRE                7
#define MESSAGE_TYPE_CODT                 8
#define MESSAGE_TYPE_CODA                 9
#define MESSAGE_TYPE_COERR               10
#define MESSAGE_TYPE_COIT                11

#define MESSAGE_TYPE_REG_REQ              1
#define MESSAGE_TYPE_REG_RSP              2
#define MESSAGE_TYPE_DEREG_REQ            3
#define MESSAGE_TYPE_DEREG_RSP            4


static const value_string message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "Destination unavailable (DUNA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "Destination available (DAVA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "Destination state audit (DAUD)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SS7 Network congestion state (SCON)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "Destination userpart unavailable (DUPU)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "Destination Restricted (DRST)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASP up (UP)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASP down (DOWN)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "Heartbeat (BEAT)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASP up ack (UP ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP down ack (DOWN ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "Heartbeat ack (BEAT ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASP active (ACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASP inactive (INACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASP active ack (ACTIVE ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASP inactive ack (INACTIVE ACK)" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDR ,         "Connectionless Data Response (CLDR)" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDT ,         "Connectionless Data Transfer (CLDT)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CORE ,         "Connection Request (CORE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COAK ,         "Connection Acknowledge (COAK)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COREF ,        "Connection Refused (COREF)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELRE ,        "Release Request (RELRE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELCO ,        "Release Complete (RELCO)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESCO ,        "Reset Confirm (RESCO)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESRE ,        "Reset Request (RESRE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODT ,         "Connection Oriented Data Transfer (CODT)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODA ,         "Connection Oriented Data Acknowledge (CODA)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COERR ,        "Connection Oriented Error (COERR)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COIT ,         "Inactivity Test (COIT)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "Registration Request (REG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "Registration Response (REG_RSP)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "Deregistration Request (DEREG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "Deregistration Response (DEREG_RSP)" },
  { 0,                           NULL } };

static const value_string message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "NTFY" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "DUNA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "DAVA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "DAUD" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SCON" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "DUPU" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "DRST" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASP_UP" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASP_DOWN" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "BEAT" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASP_UP_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP_DOWN_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "BEAT_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASP_ACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASP_INACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASP_ACTIVE_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASP_INACTIVE_ACK" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDR ,         "CLDR" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDT ,         "CLDT" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CORE ,         "CORE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COAK ,         "COAK" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COREF ,        "COREF" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELRE ,        "RELRE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELCO ,        "RELCO" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESCO ,        "RESCO" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESRE ,        "RESRE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODT ,         "CODT" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODA ,         "CODA" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COERR ,        "COERR" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COIT ,         "COIT" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "REG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "REG_RSP" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "DEREG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "DEREG_RSP" },
  { 0,                           NULL } };

const value_string sua_co_class_type_acro_values[] = {
	{ MESSAGE_TYPE_CORE ,         "CORE" },
	{ MESSAGE_TYPE_COAK ,         "COAK" },
	{ MESSAGE_TYPE_COREF ,        "COREF" },
	{ MESSAGE_TYPE_RELRE ,        "RELRE" },
	{ MESSAGE_TYPE_RELCO ,        "RELCO" },
	{ MESSAGE_TYPE_RESCO ,        "RESCO" },
	{ MESSAGE_TYPE_RESRE ,        "RESRE" },
	{ MESSAGE_TYPE_CODT ,         "CODT" },
	{ MESSAGE_TYPE_CODA ,         "CODA" },
	{ MESSAGE_TYPE_COERR ,        "COERR" },
	{ MESSAGE_TYPE_COIT ,         "COIT" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_sua = -1;
static int hf_sua_version = -1;
static int hf_sua_reserved = -1;
static int hf_sua_message_class = -1;
static int hf_sua_message_type = -1;
static int hf_sua_message_length = -1;
static int hf_sua_parameter_tag = -1;
static int hf_sua_v8_parameter_tag = -1;
static int hf_sua_parameter_length = -1;
static int hf_sua_parameter_value = -1;
static int hf_sua_parameter_padding = -1;
static int hf_sua_info_string = -1;
static int hf_sua_routing_context = -1;
static int hf_sua_diagnostic_information_info = -1;
static int hf_sua_heartbeat_data = -1;
static int hf_sua_traffic_mode_type = -1;
static int hf_sua_error_code = -1;
static int hf_sua_v8_error_code = -1;
static int hf_sua_status_type = -1;
static int hf_sua_status_info = -1;
static int hf_sua_congestion_level = -1;
static int hf_sua_asp_identifier = -1;
static int hf_sua_mask = -1;
static int hf_sua_dpc = -1;
static int hf_sua_registration_status = -1;
static int hf_sua_deregistration_status = -1;
static int hf_sua_local_routing_key_identifier = -1;
static int hf_sua_source_address_routing_indicator = -1;
static int hf_sua_source_address_reserved_bits = -1;
static int hf_sua_source_address_gt_bit = -1;
static int hf_sua_source_address_pc_bit = -1;
static int hf_sua_source_address_ssn_bit = -1;
static int hf_sua_destination_address_routing_indicator = -1;
static int hf_sua_destination_address_reserved_bits = -1;
static int hf_sua_destination_address_gt_bit = -1;
static int hf_sua_destination_address_pc_bit = -1;
static int hf_sua_destination_address_ssn_bit = -1;
static int hf_sua_ss7_hop_counter_counter = -1;
static int hf_sua_ss7_hop_counter_reserved = -1;
static int hf_sua_destination_reference_number = -1;
static int hf_sua_source_reference_number = -1;
static int hf_sua_cause_reserved = -1;
static int hf_sua_cause_type = -1;
static int hf_sua_cause_value = -1;
static int hf_sua_sequence_number_reserved = -1;
static int hf_sua_sequence_number_rec_number = -1;
static int hf_sua_sequence_number_spare_bit = -1;
static int hf_sua_sequence_number_sent_number = -1;
static int hf_sua_sequence_number_more_data_bit = -1;
static int hf_sua_receive_sequence_number_reserved = -1;
static int hf_sua_receive_sequence_number_number = -1;
static int hf_sua_receive_sequence_number_spare_bit = -1;
static int hf_sua_asp_capabilities_reserved = -1;
static int hf_sua_asp_capabilities_reserved_bits = -1;
static int hf_sua_asp_capabilities_a_bit =-1;
static int hf_sua_asp_capabilities_b_bit =-1;
static int hf_sua_asp_capabilities_c_bit =-1;
static int hf_sua_asp_capabilities_d_bit =-1;
static int hf_sua_asp_capabilities_interworking = -1;
static int hf_sua_credit = -1;
static int hf_sua_data = -1;
static int hf_sua_cause = -1;
static int hf_sua_user = -1;
static int hf_sua_network_appearance = -1;
static int hf_sua_routing_key_identifier = -1;
static int hf_sua_correlation_id = -1;
static int hf_sua_importance_reserved = -1;
static int hf_sua_importance = -1;
static int hf_sua_message_priority_reserved = -1;
static int hf_sua_message_priority = -1;
static int hf_sua_protocol_class_reserved = -1;
static int hf_sua_return_on_error_bit = -1;
static int hf_sua_protocol_class = -1;
static int hf_sua_sequence_control = -1;
static int hf_sua_first_bit = -1;
static int hf_sua_number_of_remaining_segments = -1;
static int hf_sua_segmentation_reference = -1;
static int hf_sua_smi = -1;
static int hf_sua_smi_reserved = -1;
static int hf_sua_tid_label_start = -1;
static int hf_sua_tid_label_end = -1;
static int hf_sua_tid_label_value = -1;
static int hf_sua_drn_label_start = -1;
static int hf_sua_drn_label_end = -1;
static int hf_sua_drn_label_value = -1;
static int hf_sua_gt_reserved = -1;
static int hf_sua_gti = -1;
static int hf_sua_number_of_digits = -1;
static int hf_sua_translation_type = -1;
static int hf_sua_numbering_plan = -1;
static int hf_sua_nature_of_address = -1;
static int hf_sua_global_title_digits = -1;
static int hf_sua_point_code_dpc = -1;
static int hf_sua_ssn_reserved = -1;
static int hf_sua_ssn_number = -1;
static int hf_sua_ipv4 = -1;
static int hf_sua_hostname = -1;
static int hf_sua_ipv6 = -1;
static int hf_sua_assoc_id = -1;
static int hf_sua_assoc_msg = -1;

/* Initialize the subtree pointers */
static gint ett_sua = -1;
static gint ett_sua_parameter = -1;
static gint ett_sua_source_address_indicator = -1;
static gint ett_sua_destination_address_indicator = -1;
static gint ett_sua_affected_destination = -1;
static gint ett_sua_first_remaining = -1;
static gint ett_sua_sequence_number_rec_number = -1;
static gint ett_sua_sequence_number_sent_number = -1;
static gint ett_sua_receive_sequence_number_number = -1;
static gint ett_sua_return_on_error_bit_and_protocol_class = -1;
static gint ett_sua_protcol_classes = -1;
static gint ett_sua_assoc = -1;

static int sua_tap = -1;

static mtp3_addr_pc_t *sua_dpc;
static mtp3_addr_pc_t *sua_opc;
static guint16 sua_ri;
static gchar *sua_source_gt;
static gchar *sua_destination_gt;

static dissector_handle_t data_handle;
static dissector_table_t sccp_ssn_dissector_table;
static heur_dissector_list_t heur_subdissector_list;

static guint32  message_class, message_type, drn, srn;

#define INVALID_SSN 0xff
static guint next_assoc_id = 1;

/* Based om  association tracking in the SCCP dissector */
typedef struct _sua_assoc_info_t {
    guint assoc_id;
    guint32 calling_routing_ind;
    guint32 called_routing_ind;
    guint32 calling_dpc;
    guint32 called_dpc;
    guint8 calling_ssn;
    guint8 called_ssn;
    gboolean has_bw_key;
    gboolean has_fw_key;
} sua_assoc_info_t;

static emem_tree_t* assocs = NULL;
sua_assoc_info_t* assoc;
sua_assoc_info_t no_sua_assoc = {
	0,		/* assoc_id */
	0,		/* calling_routing_ind */
	0,		/* called_routing_ind */
	0,		/* calling_dpc */
	0,		/* called_dpc */
	0,		/* calling_ssn */
	0,		/* called_ssn */
	FALSE,  /* has_bw_key */
	FALSE   /* has_fw_key */
};

static sua_assoc_info_t *
new_assoc(guint32 calling, guint32 called)
{
	sua_assoc_info_t* a = se_alloc0(sizeof(sua_assoc_info_t));

    a->assoc_id               = next_assoc_id++;
    a->calling_routing_ind    = 0;
    a->called_routing_ind     = 0;
    a->calling_dpc            = calling;
    a->called_dpc             = called;
    a->calling_ssn            = INVALID_SSN;
    a->called_ssn             = INVALID_SSN;

	return a;
}

static sua_assoc_info_t* 
sua_assoc(packet_info* pinfo, address* opc, address* dpc, guint src_rn, guint dst_rn)
{
	guint32 opck, dpck;
	if (!src_rn && !dst_rn)
	{
		return &no_sua_assoc;
	}
	opck = opc->type == AT_SS7PC ? mtp3_pc_hash(opc->data) : g_str_hash(address_to_str(opc));
	dpck = dpc->type == AT_SS7PC ? mtp3_pc_hash(dpc->data) : g_str_hash(address_to_str(dpc));
	switch (message_type) 
	{
		case MESSAGE_TYPE_CORE:
		{
			/* Calling and called is seen from initiator of CORE */
       		emem_tree_key_t bw_key[] = {
                		{1,&dpck},
                		{1,&opck},
                		{1,&src_rn},
                		{0,NULL}
            		};
			
        	if (! ( assoc = se_tree_lookup32_array(assocs,bw_key) ) && ! pinfo->fd->flags.visited ) 
			{
                assoc = new_assoc(opck, dpck);
        		se_tree_insert32_array(assocs,bw_key,assoc);
				assoc->has_bw_key = TRUE;
				/*g_warning("CORE dpck %u,opck %u,src_rn %u",dpck,opck,src_rn);*/
    		}
    		break;

		}

		case MESSAGE_TYPE_COAK:
        	{ 
    		/* Calling and called is seen from initiator of CORE */
    		emem_tree_key_t fw_key[] = {
        				{1,&dpck},
        				{1,&opck},
        				{1,&src_rn},
        				{0,NULL}
    					};
    		emem_tree_key_t bw_key[] = {
        				{1,&opck},
        				{1,&dpck},
        				{1,&dst_rn},
        				{0,NULL}
    					};
			/*g_warning("MESSAGE_TYPE_COAK dst_rn %u,src_rn %u ",dst_rn,src_rn);*/
			if ( ( assoc = se_tree_lookup32_array(assocs, bw_key) ) ) {
				goto got_assoc;
			}
			if ( (assoc = se_tree_lookup32_array(assocs, fw_key) ) ) {
				goto got_assoc;
			}

           assoc = new_assoc(dpck,opck);

     got_assoc:

            pinfo->p2p_dir = P2P_DIR_RECV;

            if ( ! pinfo->fd->flags.visited && ! assoc->has_bw_key ) {
                se_tree_insert32_array(assocs, bw_key, assoc);
                assoc->has_bw_key = TRUE;
            }

            if ( ! pinfo->fd->flags.visited && ! assoc->has_fw_key ) {
                se_tree_insert32_array(assocs, fw_key, assoc);
                assoc->has_fw_key = TRUE;
            }

            break;
        }

       	default:
        	{ 
    		emem_tree_key_t key[] = {
        				{1,&opck},
        				{1,&dpck},
        				{1,&dst_rn},
        				{0,NULL}
    					};
   			assoc = se_tree_lookup32_array(assocs,key);
   			/* Should a check be made on pinfo->p2p_dir ??? */
            break;
        }
	}

	return assoc ? assoc : &no_sua_assoc;
}

/* stuff for supporting multiple versions */
typedef enum {
  SUA_V08,
  SUA_RFC
} Version_Type;

static gint version = SUA_RFC;
static gboolean set_addresses = FALSE;

static void
dissect_parameters(tvbuff_t *tlv_tvb, proto_tree *tree, tvbuff_t **data_tvb, guint8 *source_ssn, guint8 *dest_ssn);

static void
dissect_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *sua_tree)
{

  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_class * 256 + message_type, message_class_type_acro_values, "reserved"));

  if (sua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(sua_tree, hf_sua_version,        common_header_tvb, VERSION_OFFSET,        VERSION_LENGTH,        ENC_BIG_ENDIAN);
    proto_tree_add_item(sua_tree, hf_sua_reserved,       common_header_tvb, RESERVED_OFFSET,       RESERVED_LENGTH,       ENC_NA);
    proto_tree_add_item(sua_tree, hf_sua_message_class,  common_header_tvb, MESSAGE_CLASS_OFFSET,  MESSAGE_CLASS_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(sua_tree, hf_sua_message_type, common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, message_type, "Message Type: %s (%u)",
			                   val_to_str(message_class * 256 + message_type, message_class_type_values, "reserved"), message_type);
    proto_tree_add_item(sua_tree, hf_sua_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  };
}

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
                         tvb_get_ephemeral_string(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
}

#define ROUTING_CONTEXT_LENGTH 4

static void
dissect_routing_context_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_contexts, context_number;
  gint context_offset;

  number_of_contexts = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / 4;
  context_offset = PARAMETER_VALUE_OFFSET;
  for(context_number=1; context_number <= number_of_contexts; context_number++) {
    proto_tree_add_item(parameter_tree, hf_sua_routing_context, parameter_tvb, context_offset, ROUTING_CONTEXT_LENGTH, ENC_BIG_ENDIAN);
    context_offset += ROUTING_CONTEXT_LENGTH;
  };
  proto_item_append_text(parameter_item, " (%u context%s)", number_of_contexts, plurality(number_of_contexts, "", "s"));
}

#define DIAGNOSTIC_INFO_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 diag_info_length;

  diag_info_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_diagnostic_information_info, parameter_tvb, DIAGNOSTIC_INFO_OFFSET, diag_info_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", diag_info_length, plurality(diag_info_length, "", "s"));
}

#define HEARTBEAT_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 heartbeat_data_length;

  heartbeat_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define TRAFFIC_MODE_TYPE_LENGTH 4

static const value_string traffic_mode_type_values[] = {
  { 1, "Over-ride" },
  { 2, "Load-share" },
  { 3, "Broadcast" },
  { 0, NULL } };

static void
dissect_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), traffic_mode_type_values, "unknown"));
}

#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET
#define ERROR_CODE_LENGTH 4

static const value_string v8_error_code_values[] = {
  { 0x01, "Invalid version" },
  { 0x02, "Invalid interface identifier" },
  { 0x03, "Unsupported message class" },
  { 0x04, "Unsupported message type" },
  { 0x05, "Unsupported traffic handling mode" },
  { 0x06, "Unexpected message" },
  { 0x07, "Protocol error" },
  { 0x09, "Invalid stream identifier" },
  { 0x0d, "Refused - management blocking" },
  { 0x0e, "ASP identifier required" },
  { 0x0f, "Invalid ASP identifier" },
  { 0x11, "Invalid parameter value" },
  { 0x12, "Parameter field error" },
  { 0x13, "Unexpected parameter" },
  { 0x14, "Destination status unknown" },
  { 0x15, "Invalid network appearance" },
  { 0x16, "Missing parameter" },
  { 0x17, "Routing key change refused" },
  { 0x18, "Invalid loadsharing label" },
  { 0,    NULL } };

static void
dissect_v8_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_v8_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), v8_error_code_values, "unknown"));
}

static const value_string error_code_values[] = {
  { 0x01, "Invalid version" },
  { 0x03, "Unsupported message class" },
  { 0x04, "Unsupported message type" },
  { 0x05, "Unsupported traffic handling mode" },
  { 0x06, "Unexpected message" },
  { 0x07, "Protocol error" },
  { 0x09, "Invalid stream identifier" },
  { 0x0d, "Refused - management blocking" },
  { 0x0e, "ASP identifier required" },
  { 0x0f, "Invalid ASP identifier" },
  { 0x11, "Invalid parameter value" },
  { 0x12, "Parameter field error" },
  { 0x13, "Unexpected parameter" },
  { 0x14, "Destination status unknown" },
  { 0x15, "Invalid network appearance" },
  { 0x16, "Missing parameter" },
  { 0x19, "Invalid routing context" },
  { 0x1a, "No configured AS for ASP" },
  { 0x1b, "Subsystem status unknown" },
  { 0x1c, "Invalid loadsharing label" },
  { 0,    NULL } };

static void
dissect_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), error_code_values, "unknown"));
}

#define STATUS_TYPE_LENGTH 2
#define STATUS_INFO_LENGTH 2
#define STATUS_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define STATUS_INFO_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

#define AS_STATE_CHANGE_TYPE       1
#define OTHER_TYPE                 2

static const value_string status_type_values[] = {
  { AS_STATE_CHANGE_TYPE,            "Application server state change" },
  { OTHER_TYPE,                      "Other" },
  { 0,                               NULL } };

#define RESERVED_INFO              1
#define AS_INACTIVE_INFO           2
#define AS_ACTIVE_INFO             3
#define AS_PENDING_INFO            4

#define INSUFFICIENT_ASP_RES_INFO  1
#define ALTERNATE_ASP_ACTIVE_INFO  2
#define ASP_FAILURE                3

static const value_string status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  { OTHER_TYPE           * 256 * 256 + ASP_FAILURE,               "ASP Failure" },
  {0,                           NULL } };

static void
dissect_status_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_item(parameter_tree, hf_sua_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_uint_format(parameter_tree, hf_sua_status_info, parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH,
			                 status_info, "Status info: %s (%u)", val_to_str(status_type * 256 * 256 + status_info, status_type_info_values, "unknown"), status_info);

  proto_item_append_text(parameter_item, " (%s)", val_to_str(status_type * 256 * 256 + status_info, status_type_info_values, "unknown"));
}

#define ASP_IDENTIFIER_LENGTH 4
#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_asp_identifier, parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, ASP_IDENTIFIER_OFFSET));
}

#define AFFECTED_MASK_LENGTH 1
#define AFFECTED_DPC_LENGTH  3
#define AFFECTED_DESTINATION_LENGTH (AFFECTED_MASK_LENGTH + AFFECTED_DPC_LENGTH)

#define AFFECTED_MASK_OFFSET 0
#define AFFECTED_DPC_OFFSET  1

static void
dissect_affected_destinations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_destinations, destination_number;
  gint destination_offset;
  proto_item *dpc_item;

  number_of_destinations= (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / 4;
  destination_offset = PARAMETER_VALUE_OFFSET;
  for(destination_number=1; destination_number <= number_of_destinations; destination_number++) {
    proto_tree_add_item(parameter_tree, hf_sua_mask, parameter_tvb, destination_offset + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH, ENC_BIG_ENDIAN);
    dpc_item = proto_tree_add_item(parameter_tree, hf_sua_dpc,  parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET,  AFFECTED_DPC_LENGTH,  ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(dpc_item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET)));
    destination_offset += AFFECTED_DESTINATION_LENGTH;
  }
  proto_item_append_text(parameter_item, " (%u destination%s)", number_of_destinations, plurality(number_of_destinations, "", "s"));
}

#define CORRELATION_ID_LENGTH 4
#define CORRELATION_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_correlation_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

static void
dissect_registration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, PARAMETER_VALUE_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, NULL, NULL);
}

static void
dissect_deregistration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, PARAMETER_VALUE_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, NULL, NULL);
}

#define REGISTRATION_STATUS_LENGTH 4
#define REGISTRATION_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static const value_string registration_status_values[] = {
  {  0,            "Successfully registered" },
  {  1,            "Error - unknown" },
  {  2,            "Error - invalid destination address" },
  {  3,            "Error - invalid network appearance" },
  {  4,            "Error - invalid routing key" },
  {  5,            "Error - permission denied" },
  {  6,            "Error - cannot support unique routing" },
  {  7,            "Error - routing key not currently provisioned" },
  {  8,            "Error - insufficient resources" },
  {  9,            "Error - unsupported RK parameter field" },
  { 10,            "Error - unsupported/invalid traffic mode type" },
  { 11,            "Error - routing key change refused" },
  {  0,            NULL } };

static void
dissect_registration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_registration_status, parameter_tvb, REGISTRATION_STATUS_OFFSET, REGISTRATION_STATUS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, REGISTRATION_STATUS_OFFSET), registration_status_values, "unknown"));
}

#define DEREGISTRATION_STATUS_LENGTH 4
#define DEREGISTRATION_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static const value_string deregistration_status_values[] = {
  {  0,            "Successfully deregistered" },
  {  1,            "Error - unknown" },
  {  2,            "Error - invalid routing context" },
  {  3,            "Error - permission denied" },
  {  4,            "Error - not registered" },
  {  5,            "Error - ASP currently active for routing context" },
  {  0,            NULL } };

static void
dissect_deregistration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_deregistration_status, parameter_tvb, DEREGISTRATION_STATUS_OFFSET, DEREGISTRATION_STATUS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, DEREGISTRATION_STATUS_OFFSET), deregistration_status_values, "unknown"));
}

#define LOCAL_ROUTING_KEY_IDENTIFIER_LENGTH 4
#define LOCAL_ROUTING_KEY_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_local_routing_key_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_local_routing_key_identifier, parameter_tvb, LOCAL_ROUTING_KEY_IDENTIFIER_OFFSET, LOCAL_ROUTING_KEY_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%d)", tvb_get_ntohl(parameter_tvb, LOCAL_ROUTING_KEY_IDENTIFIER_OFFSET));
}

#define SS7_HOP_COUNTER_LENGTH 1
#define SS7_HOP_COUNTER_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_ss7_hop_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_ss7_hop_counter_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,      ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_ss7_hop_counter_counter,  parameter_tvb, SS7_HOP_COUNTER_OFFSET, SS7_HOP_COUNTER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_guint8(parameter_tvb,  SS7_HOP_COUNTER_OFFSET));
}

#define ROUTING_INDICATOR_LENGTH  2
#define ADDRESS_INDICATOR_LENGTH  2

#define ROUTING_INDICATOR_OFFSET  PARAMETER_VALUE_OFFSET
#define ADDRESS_INDICATOR_OFFSET  (ROUTING_INDICATOR_OFFSET + ROUTING_INDICATOR_LENGTH)
#define ADDRESS_PARAMETERS_OFFSET (ADDRESS_INDICATOR_OFFSET + ADDRESS_INDICATOR_LENGTH)

#define RESERVED_ROUTING_INDICATOR              0
#define ROUTE_ON_GT_ROUTING_INDICATOR           1
#define ROUTE_ON_SSN_PC_ROUTING_INDICATOR       2
#define ROUTE_ON_HOSTNAMEROUTING_INDICATOR      3
#define ROUTE_ON_SSN_IP_ROUTING_INDICATOR       4

static const value_string routing_indicator_values[] = {
  { RESERVED_ROUTING_INDICATOR,            "Reserved" },
  { ROUTE_ON_GT_ROUTING_INDICATOR,         "Route on Global Title" },
  { ROUTE_ON_SSN_PC_ROUTING_INDICATOR,     "Route on SSN + PC" },
  { ROUTE_ON_HOSTNAMEROUTING_INDICATOR,    "Route on Hostname" },
  { ROUTE_ON_SSN_IP_ROUTING_INDICATOR,     "Route on SSN + IP Address" },
  { 0,                                     NULL } };

#define ADDRESS_RESERVED_BITMASK 0xfff8
#define ADDRESS_GT_BITMASK       0x0004
#define ADDRESS_PC_BITMASK       0x0002
#define ADDRESS_SSN_BITMASK      0x0001

static void
dissect_source_address_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, guint8 *ssn)
{
  proto_item *address_indicator_item;
  proto_tree *address_indicator_tree;
  tvbuff_t *parameters_tvb;

  sua_ri = tvb_get_ntohs(parameter_tvb, ROUTING_INDICATOR_OFFSET);

  if(parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_sua_source_address_routing_indicator, parameter_tvb, ROUTING_INDICATOR_OFFSET, ROUTING_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    address_indicator_item = proto_tree_add_text(parameter_tree, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, "Address Indicator");
    address_indicator_tree = proto_item_add_subtree(address_indicator_item, ett_sua_source_address_indicator);
    proto_tree_add_item(address_indicator_tree, hf_sua_source_address_reserved_bits, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_source_address_gt_bit,        parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_source_address_pc_bit,        parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_source_address_ssn_bit,       parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
  }

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, ADDRESS_PARAMETERS_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, ssn, NULL);
}

static void
dissect_destination_address_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, guint8 *ssn)
{
  proto_item *address_indicator_item;
  proto_tree *address_indicator_tree;
  tvbuff_t *parameters_tvb;

  sua_ri = tvb_get_ntohs(parameter_tvb, ROUTING_INDICATOR_OFFSET);

  if(parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_sua_destination_address_routing_indicator, parameter_tvb, ROUTING_INDICATOR_OFFSET, ROUTING_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    address_indicator_item = proto_tree_add_text(parameter_tree, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, "Address Indicator");
    address_indicator_tree = proto_item_add_subtree(address_indicator_item, ett_sua_destination_address_indicator);
    proto_tree_add_item(address_indicator_tree, hf_sua_destination_address_reserved_bits, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_destination_address_gt_bit,        parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_destination_address_pc_bit,        parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(address_indicator_tree, hf_sua_destination_address_ssn_bit,       parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, ENC_BIG_ENDIAN);
  }

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, ADDRESS_PARAMETERS_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, NULL, ssn);
}

#define SOURCE_REFERENCE_NUMBER_LENGTH 4
#define SOURCE_REFERENCE_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_source_reference_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  srn = tvb_get_ntohl(parameter_tvb, SOURCE_REFERENCE_NUMBER_OFFSET);
  proto_tree_add_item(parameter_tree, hf_sua_source_reference_number, parameter_tvb, SOURCE_REFERENCE_NUMBER_OFFSET, SOURCE_REFERENCE_NUMBER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, SOURCE_REFERENCE_NUMBER_OFFSET));
}

#define DESTINATION_REFERENCE_NUMBER_LENGTH 4
#define DESTINATION_REFERENCE_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_destination_reference_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  drn = tvb_get_ntohl(parameter_tvb, DESTINATION_REFERENCE_NUMBER_OFFSET);
  proto_tree_add_item(parameter_tree, hf_sua_destination_reference_number, parameter_tvb, DESTINATION_REFERENCE_NUMBER_OFFSET, DESTINATION_REFERENCE_NUMBER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, DESTINATION_REFERENCE_NUMBER_OFFSET));
}

#define CAUSE_TYPE_LENGTH 1
#define CAUSE_VALUE_LENGTH 1

#define CAUSE_TYPE_OFFSET  (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define CAUSE_VALUE_OFFSET (CAUSE_TYPE_OFFSET + CAUSE_TYPE_LENGTH)

#define CAUSE_TYPE_RETURN  0x1
#define CAUSE_TYPE_REFUSAL 0x2
#define CAUSE_TYPE_RELEASE 0x3
#define CAUSE_TYPE_RESET   0x4
#define CAUSE_TYPE_ERROR   0x5
static const value_string cause_type_values[] = {
  { CAUSE_TYPE_RETURN,	"Return Cause" },
  { CAUSE_TYPE_REFUSAL,	"Refusal Cause" },
  { CAUSE_TYPE_RELEASE,	"Release Cause" },
  { CAUSE_TYPE_RESET,	"Reset Cause" },
  { CAUSE_TYPE_ERROR,	"Error cause" },
  { 0,			NULL } };

static void
dissect_sccp_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 cause_type, cause;
  proto_item *pi;
  const gchar *cause_string;

  proto_tree_add_item(parameter_tree, hf_sua_cause_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH,  ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_cause_type,     parameter_tvb, CAUSE_TYPE_OFFSET,      CAUSE_TYPE_LENGTH,  ENC_BIG_ENDIAN);
  cause_type = tvb_get_guint8(parameter_tvb, CAUSE_TYPE_OFFSET);
  pi = proto_tree_add_item(parameter_tree, hf_sua_cause_value, parameter_tvb, CAUSE_VALUE_OFFSET,   CAUSE_VALUE_LENGTH, ENC_BIG_ENDIAN);
  cause = tvb_get_guint8(parameter_tvb, CAUSE_VALUE_OFFSET);

  switch (cause_type) {
  case CAUSE_TYPE_RETURN:
    cause_string = val_to_str(cause, sccp_return_cause_values, "unknown");
    break;
  case CAUSE_TYPE_REFUSAL:
    cause_string = val_to_str(cause, sccp_refusal_cause_values, "unknown");
    break;
  case CAUSE_TYPE_RELEASE:
    cause_string = val_to_str(cause, sccp_release_cause_values, "unknown");
    break;
  case CAUSE_TYPE_RESET:
    cause_string = val_to_str(cause, sccp_reset_cause_values, "unknown");
    break;
  case CAUSE_TYPE_ERROR:
    cause_string = val_to_str(cause, sccp_error_cause_values, "unknown");
    break;
  default:
    cause_string = "unknown";
  }

  proto_item_append_text(pi, " (%s)", cause_string);
  proto_item_append_text(parameter_item, " (%s: %s)", val_to_str(cause_type, cause_type_values, "unknown"), cause_string);
}

#define SEQUENCE_NUMBER_REC_SEQ_LENGTH  1
#define SEQUENCE_NUMBER_SENT_SEQ_LENGTH 1
#define SEQUENCE_NUMBER_REC_SEQ_OFFSET  (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define SEQUENCE_NUMBER_SENT_SEQ_OFFSET (SEQUENCE_NUMBER_REC_SEQ_OFFSET + SEQUENCE_NUMBER_REC_SEQ_LENGTH)

#define SEQ_NUM_MASK       0xFE
#define SPARE_BIT_MASK     0x01
#define MORE_DATA_BIT_MASK 0x01

static const true_false_string more_data_bit_value = {
  "More Data",
  "Not More Data"
};

static void
dissect_sequence_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_item *sent_sequence_number_item;
  proto_tree *sent_sequence_number_tree;
  proto_item *receive_sequence_number_item;
  proto_tree *receive_sequence_number_tree;

  proto_tree_add_item(parameter_tree, hf_sua_sequence_number_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH, ENC_NA);

  receive_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET, SEQUENCE_NUMBER_REC_SEQ_LENGTH, "Receive Sequence Number");
  receive_sequence_number_tree = proto_item_add_subtree(receive_sequence_number_item, ett_sua_sequence_number_rec_number);
  proto_tree_add_item(receive_sequence_number_tree, hf_sua_sequence_number_rec_number,    parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET, SEQUENCE_NUMBER_REC_SEQ_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(receive_sequence_number_tree, hf_sua_sequence_number_more_data_bit, parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET, SEQUENCE_NUMBER_REC_SEQ_LENGTH, ENC_BIG_ENDIAN);

  sent_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET, SEQUENCE_NUMBER_SENT_SEQ_LENGTH, "Sent Sequence Number");
  sent_sequence_number_tree = proto_item_add_subtree(sent_sequence_number_item, ett_sua_sequence_number_sent_number);
  proto_tree_add_item(sent_sequence_number_tree, hf_sua_sequence_number_sent_number, parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET, SEQUENCE_NUMBER_SENT_SEQ_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(sent_sequence_number_tree, hf_sua_sequence_number_spare_bit,   parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET, SEQUENCE_NUMBER_SENT_SEQ_LENGTH, ENC_BIG_ENDIAN);
}

#define RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH 1
#define RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_receive_sequence_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_item *receive_sequence_number_item;
  proto_tree *receive_sequence_number_tree;

  proto_tree_add_item(parameter_tree, hf_sua_receive_sequence_number_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH, ENC_NA);
  receive_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH, "Receive Sequence Number");
  receive_sequence_number_tree = proto_item_add_subtree(receive_sequence_number_item, ett_sua_receive_sequence_number_number);
  proto_tree_add_item(receive_sequence_number_tree, hf_sua_receive_sequence_number_number,    parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(receive_sequence_number_tree, hf_sua_receive_sequence_number_spare_bit, parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH, ENC_BIG_ENDIAN);
}

#define PROTOCOL_CLASSES_LENGTH        1
#define INTERWORKING_LENGTH            1
#define PROTOCOL_CLASSES_OFFSET        (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define INTERWORKING_OFFSET            (PROTOCOL_CLASSES_OFFSET + PROTOCOL_CLASSES_LENGTH)

#define A_BIT_MASK 0x08
#define B_BIT_MASK 0x04
#define C_BIT_MASK 0x02
#define D_BIT_MASK 0x01
#define RESERVED_BITS_MASK 0xF0

static const value_string interworking_values[] = {
  { 0x0,   "No Interworking with SS7 Networks" },
  { 0x1,   "IP-Signalling Endpoint interworking with with SS7 networks" },
  { 0x2,   "Signalling Gateway" },
  { 0x3,   "Relay Node Support" },
  { 0,     NULL } };

static void
dissect_asp_capabilities_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_item *protocol_classes_item;
  proto_tree *protocol_classes_tree;

  proto_tree_add_item(parameter_tree, hf_sua_asp_capabilities_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH, ENC_NA);
  protocol_classes_item = proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, "Protocol classes");
  protocol_classes_tree = proto_item_add_subtree(protocol_classes_item, ett_sua_protcol_classes);
  proto_tree_add_item(protocol_classes_tree, hf_sua_asp_capabilities_reserved_bits, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(protocol_classes_tree, hf_sua_asp_capabilities_a_bit, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(protocol_classes_tree, hf_sua_asp_capabilities_b_bit, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(protocol_classes_tree, hf_sua_asp_capabilities_c_bit, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(protocol_classes_tree, hf_sua_asp_capabilities_d_bit, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_asp_capabilities_interworking, parameter_tvb, INTERWORKING_OFFSET, INTERWORKING_LENGTH, ENC_BIG_ENDIAN);
}

#define CREDIT_LENGTH 4
#define CREDIT_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_credit_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_credit, parameter_tvb, CREDIT_OFFSET, CREDIT_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, CREDIT_OFFSET));
}

#define DATA_PARAMETER_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, tvbuff_t **data_tvb)
{
  guint16 data_length;

  data_length    = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  if(parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_sua_data, parameter_tvb, DATA_PARAMETER_DATA_OFFSET, data_length, ENC_NA);
    proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", data_length, plurality(data_length, "", "s"));
  }

  if(data_tvb)
  {
    *data_tvb = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, data_length, data_length);
  }
}


#define CAUSE_LENGTH 2
#define USER_LENGTH  2
#define CAUSE_OFFSET PARAMETER_VALUE_OFFSET
#define USER_OFFSET (CAUSE_OFFSET + CAUSE_LENGTH)

static const value_string cause_values[] = {
  { 0x0,  "Remote SCCP unavailable, Reason unknown" },
  { 0x2,  "Remote SCCP unequipped" },
  { 0x3,  "Remote SCCP inaccessible" },
  { 0,    NULL } };

static void
dissect_user_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_sua_cause, parameter_tvb, CAUSE_OFFSET, CAUSE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_user,  parameter_tvb, USER_OFFSET,  USER_LENGTH,  ENC_BIG_ENDIAN);
}

#define NETWORK_APPEARANCE_LENGTH 4
#define NETWORK_APPEARANCE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_network_appearance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_network_appearance, parameter_tvb, NETWORK_APPEARANCE_OFFSET, NETWORK_APPEARANCE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, NETWORK_APPEARANCE_OFFSET));
}

static void
dissect_routing_key_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, PARAMETER_VALUE_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, NULL, NULL);
}
#define DRN_START_LENGTH 1
#define DRN_END_LENGTH 1
#define DRN_VALUE_LENGTH 2

#define DRN_START_OFFSET PARAMETER_VALUE_OFFSET
#define DRN_END_OFFSET   (DRN_START_OFFSET + DRN_START_LENGTH)
#define DRN_VALUE_OFFSET (DRN_END_OFFSET + DRN_END_LENGTH)

static void
dissect_drn_label_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_sua_drn_label_start, parameter_tvb, DRN_START_OFFSET, DRN_START_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_drn_label_end,   parameter_tvb, DRN_END_OFFSET,   DRN_END_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_drn_label_value, parameter_tvb, DRN_VALUE_OFFSET, DRN_VALUE_LENGTH, ENC_BIG_ENDIAN);
}

#define TID_START_LENGTH 1
#define TID_END_LENGTH 1
#define TID_VALUE_LENGTH 2

#define TID_START_OFFSET PARAMETER_VALUE_OFFSET
#define TID_END_OFFSET   (TID_START_OFFSET + TID_START_LENGTH)
#define TID_VALUE_OFFSET (TID_END_OFFSET + TID_END_LENGTH)

static void
dissect_tid_label_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_sua_tid_label_start, parameter_tvb, TID_START_OFFSET, TID_START_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_tid_label_end,   parameter_tvb, TID_END_OFFSET,   TID_END_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_tid_label_value, parameter_tvb, TID_VALUE_OFFSET, TID_VALUE_LENGTH, ENC_BIG_ENDIAN);
}

#define ADDRESS_RANGE_ADDRESS_PARAMETERS_OFFSET  PARAMETER_VALUE_OFFSET

static void
dissect_address_range_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, PARAMETER_VALUE_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree, NULL, NULL, NULL);
}

#define SMI_LENGTH 1
#define SMI_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_smi_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_smi_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH, ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_smi,          parameter_tvb, SMI_OFFSET,             SMI_LENGTH,        ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_guint8(parameter_tvb,  SMI_OFFSET));
}

#define IMPORTANCE_LENGTH 1
#define IMPORTANCE_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_importance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_importance_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH, ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_importance,          parameter_tvb, IMPORTANCE_OFFSET,      IMPORTANCE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_guint8(parameter_tvb,  IMPORTANCE_OFFSET));
}

#define MESSAGE_PRIORITY_LENGTH 1
#define MESSAGE_PRIORITY_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_message_priority_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_message_priority_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET,  RESERVED_3_LENGTH,       ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_message_priority,          parameter_tvb, MESSAGE_PRIORITY_OFFSET, MESSAGE_PRIORITY_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_guint8(parameter_tvb,  MESSAGE_PRIORITY_OFFSET));
}

#define PROTOCOL_CLASS_LENGTH         1
#define PROTOCOL_CLASS_OFFSET         (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

#define RETURN_ON_ERROR_BIT_MASK 0x80
#define PROTOCOL_CLASS_MASK      0x7f


static const true_false_string return_on_error_bit_value = {
  "Return Message On Error",
  "No Special Options"
};

static void
dissect_protocol_class_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *protocol_class_item;
  proto_tree *protocol_class_tree;

  proto_tree_add_item(parameter_tree, hf_sua_protocol_class_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH, ENC_NA);

  protocol_class_item = proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH, "Protocol Class");
  protocol_class_tree = proto_item_add_subtree(protocol_class_item, ett_sua_return_on_error_bit_and_protocol_class);

  proto_tree_add_item(protocol_class_tree, hf_sua_return_on_error_bit, parameter_tvb, PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(protocol_class_tree, hf_sua_protocol_class,      parameter_tvb, PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%d)", tvb_get_guint8(parameter_tvb, PROTOCOL_CLASS_OFFSET) & PROTOCOL_CLASS_MASK);
}

#define SEQUENCE_CONTROL_LENGTH 4
#define SEQUENCE_CONTROL_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sequence_control_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_sequence_control, parameter_tvb, SEQUENCE_CONTROL_OFFSET, SEQUENCE_CONTROL_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, SEQUENCE_CONTROL_OFFSET));
}

#define FIRST_REMAINING_LENGTH        1
#define SEGMENTATION_REFERENCE_LENGTH 3
#define FIRST_REMAINING_OFFSET        PARAMETER_VALUE_OFFSET
#define SEGMENTATION_REFERENCE_OFFSET (FIRST_REMAINING_OFFSET + FIRST_REMAINING_LENGTH)

#define FIRST_BIT_MASK 0x80
#define NUMBER_OF_SEGMENTS_MASK 0x7f

static const true_false_string first_bit_value = {
  "First segment",
  "Subsequent segment"
};

static void
dissect_segmentation_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_item *first_remaining_item;
  proto_tree *first_remaining_tree;

  first_remaining_item = proto_tree_add_text(parameter_tree, parameter_tvb, FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH, "First / Remaining");
  first_remaining_tree = proto_item_add_subtree(first_remaining_item, ett_sua_first_remaining);
  proto_tree_add_item(first_remaining_tree, hf_sua_first_bit,                    parameter_tvb, FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(first_remaining_tree, hf_sua_number_of_remaining_segments, parameter_tvb, FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_segmentation_reference, parameter_tvb, SEGMENTATION_REFERENCE_OFFSET, SEGMENTATION_REFERENCE_LENGTH, ENC_BIG_ENDIAN);
}

#define CONGESTION_LEVEL_LENGTH 4
#define CONGESTION_LEVEL_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_congestion_level_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_congestion_level, parameter_tvb, CONGESTION_LEVEL_OFFSET, CONGESTION_LEVEL_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, CONGESTION_LEVEL_OFFSET));
}

#define GTI_LENGTH               1
#define NO_OF_DIGITS_LENGTH      1
#define TRANSLATION_TYPE_LENGTH  1
#define NUMBERING_PLAN_LENGTH    1
#define NATURE_OF_ADDRESS_LENGTH 1

#define GTI_OFFSET               (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)
#define NO_OF_DIGITS_OFFSET      (GTI_OFFSET + GTI_LENGTH)
#define TRANSLATION_TYPE_OFFSET  (NO_OF_DIGITS_OFFSET + NO_OF_DIGITS_LENGTH)
#define NUMBERING_PLAN_OFFSET    (TRANSLATION_TYPE_OFFSET + TRANSLATION_TYPE_LENGTH)
#define NATURE_OF_ADDRESS_OFFSET (NUMBERING_PLAN_OFFSET + NUMBERING_PLAN_LENGTH)
#define GLOBAL_TITLE_OFFSET      (NATURE_OF_ADDRESS_OFFSET + NATURE_OF_ADDRESS_LENGTH)

#define ISDN_TELEPHONY_NUMBERING_PLAN   1
#define GENERIC_NUMBERING_PLAN          2
#define DATA_NUMBERING_PLAN             3
#define TELEX_NUMBERING_PLAN            4
#define MARITIME_MOBILE_NUMBERING_PLAN  5
#define LAND_MOBILE_NUMBERING_PLAN      6
#define ISDN_MOBILE_NUMBERING_PLAN      7
#define PRIVATE_NETWORK_NUMBERING_PLAN 14

static const value_string numbering_plan_values[] = {
  { ISDN_TELEPHONY_NUMBERING_PLAN,  "ISDN/Telephony Numbering Plan (Rec. E.161 and E.164)" },
  { GENERIC_NUMBERING_PLAN,         "Generic Numbering Plan" },
  { DATA_NUMBERING_PLAN,            "Data Numbering Plan (Rec. X.121)" },
  { TELEX_NUMBERING_PLAN,           "Telex Numbering Plan (Rec. F.69)" },
  { MARITIME_MOBILE_NUMBERING_PLAN, "Maritime Mobile Numbering Plan (Rec. E.210 and E.211)" },
  { LAND_MOBILE_NUMBERING_PLAN,     "Land Mobile Numbering Plan (Rec. E.212)" },
  { ISDN_MOBILE_NUMBERING_PLAN,     "ISDN/Mobile Numbering Plan (Rec. E.214)" },
  { PRIVATE_NETWORK_NUMBERING_PLAN, "Private Network Or Network-Specific Numbering Plan" },
  { 0,                                             NULL } };

#define UNKNOWN_NATURE_OF_ADDRESS                       0
#define SUBSCRIBER_NUMBER_NATURE_OF_ADDRESS             1
#define RESERVED_FOR_NATIONAL_USE_NATURE_OF_ADDRESS     2
#define NATIONAL_SIGNIFICANT_NUMBER_NATURE_OF_ADDRESS   3
#define INTERNATION_NUMBER_NATURE_OF_ADDRESS            4

static const value_string nature_of_address_values[] = {
  { UNKNOWN_NATURE_OF_ADDRESS,                     "Unknown" },
  { SUBSCRIBER_NUMBER_NATURE_OF_ADDRESS,           "Subscriber Number" },
  { RESERVED_FOR_NATIONAL_USE_NATURE_OF_ADDRESS,   "Reserved For National Use" },
  { NATIONAL_SIGNIFICANT_NUMBER_NATURE_OF_ADDRESS, "National Significant Number" },
  { INTERNATION_NUMBER_NATURE_OF_ADDRESS,          "International Number" },
  { 0,                                             NULL } };

static void
dissect_global_title_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, gboolean source)
{
  guint16 global_title_length;
  guint16 offset;
  gboolean even_length;
  guint8 odd_signal, even_signal;
  guint8 number_of_digits;
  char *gt_digits;

  gt_digits = ep_alloc0(GT_MAX_SIGNALS+1);

  global_title_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) -
                        (PARAMETER_HEADER_LENGTH + RESERVED_3_LENGTH + GTI_LENGTH + NO_OF_DIGITS_LENGTH + TRANSLATION_TYPE_LENGTH + NUMBERING_PLAN_LENGTH + NATURE_OF_ADDRESS_LENGTH);
  proto_tree_add_item(parameter_tree, hf_sua_gt_reserved,       parameter_tvb, PARAMETER_VALUE_OFFSET,   RESERVED_3_LENGTH,        ENC_NA);
  proto_tree_add_item(parameter_tree, hf_sua_gti,               parameter_tvb, GTI_OFFSET,               GTI_LENGTH,               ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_number_of_digits,  parameter_tvb, NO_OF_DIGITS_OFFSET,      NO_OF_DIGITS_LENGTH,      ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_translation_type,  parameter_tvb, TRANSLATION_TYPE_OFFSET,  TRANSLATION_TYPE_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_numbering_plan,    parameter_tvb, NUMBERING_PLAN_OFFSET,    NUMBERING_PLAN_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sua_nature_of_address, parameter_tvb, NATURE_OF_ADDRESS_OFFSET, NATURE_OF_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

  number_of_digits = tvb_get_guint8(parameter_tvb, NO_OF_DIGITS_OFFSET);
  even_length = !(number_of_digits % 2);
  offset = GLOBAL_TITLE_OFFSET;

  while(offset < GLOBAL_TITLE_OFFSET + global_title_length) {
    odd_signal = tvb_get_guint8(parameter_tvb, offset) & GT_ODD_SIGNAL_MASK;
    even_signal = tvb_get_guint8(parameter_tvb, offset) & GT_EVEN_SIGNAL_MASK;
    even_signal >>= GT_EVEN_SIGNAL_SHIFT;

    g_strlcat(gt_digits, val_to_str(odd_signal, sccp_address_signal_values,
				    "Unknown"), GT_MAX_SIGNALS+1);

    /* If the last signal is NOT filler */
    if (offset != (GLOBAL_TITLE_OFFSET + global_title_length - 1) || even_length == TRUE)
      g_strlcat(gt_digits, val_to_str(even_signal, sccp_address_signal_values,
				   "Unknown"), GT_MAX_SIGNALS+1);

    offset += GT_SIGNAL_LENGTH;
  }

  proto_tree_add_string_format(parameter_tree, hf_sua_global_title_digits,
			       parameter_tvb, GLOBAL_TITLE_OFFSET,
			       global_title_length, gt_digits,
			       "Address information (digits): %s", gt_digits);

  if (sua_ri == ROUTE_ON_GT_ROUTING_INDICATOR) {
    if (source) {
      sua_source_gt = gt_digits;
    } else {
      sua_destination_gt = gt_digits;
    }
  }
}

#define POINT_CODE_LENGTH 4
#define POINT_CODE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, gboolean source)
{
  guint32 pc;

  pc = tvb_get_ntohl(parameter_tvb, POINT_CODE_OFFSET);

  if (sua_ri == ROUTE_ON_SSN_PC_ROUTING_INDICATOR) {
    if (source) {
      sua_opc->type = mtp3_standard;
      sua_opc->pc = pc;
    } else {
      sua_dpc->type = mtp3_standard;
      sua_dpc->pc = pc;
    }
  }

  proto_tree_add_item(parameter_tree, hf_sua_point_code_dpc, parameter_tvb, POINT_CODE_OFFSET, POINT_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", mtp3_pc_to_str(pc));
}

#define SSN_LENGTH 1
#define SSN_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)
#define INVALID_SSN 0xff

static void
dissect_ssn_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, guint8 *ssn)
{
  *ssn = tvb_get_guint8(parameter_tvb,  SSN_OFFSET);

  if(parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_sua_ssn_reserved, parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH, ENC_NA);
    proto_tree_add_item(parameter_tree, hf_sua_ssn_number,   parameter_tvb, SSN_OFFSET,             SSN_LENGTH,        ENC_BIG_ENDIAN);
    proto_item_append_text(parameter_item, " (%u)", *ssn);
  }
}

#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_ipv4, parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", tvb_ip_to_str(parameter_tvb, IPV4_ADDRESS_OFFSET));
}

#define HOSTNAME_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_hostname_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 hostname_length;

  hostname_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_hostname, parameter_tvb, HOSTNAME_OFFSET, hostname_length, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%.*s)", hostname_length,
                         tvb_get_ephemeral_string(parameter_tvb, HOSTNAME_OFFSET, hostname_length));
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sua_ipv6, parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item, " (%s)", tvb_ip6_to_str(parameter_tvb, IPV6_ADDRESS_OFFSET));
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 parameter_value_length;

  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);
  proto_item_append_text(parameter_item, "(tag %u and %u byte%s value)", tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET), parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define V8_DATA_PARAMETER_TAG                         0x0003
#define V8_INFO_STRING_PARAMETER_TAG                  0x0004
#define V8_ROUTING_CONTEXT_PARAMETER_TAG              0x0006
#define V8_DIAGNOSTIC_INFO_PARAMETER_TAG              0x0007
#define V8_HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define V8_TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define V8_ERROR_CODE_PARAMETER_TAG                   0x000c
#define V8_STATUS_PARAMETER_TAG                       0x000d
#define V8_CONGESTION_LEVEL_PARAMETER_TAG             0x000f
#define V8_ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define V8_AFFECTED_POINT_CODE_PARAMETER_TAG          0x0012

#define V8_SS7_HOP_COUNTER_PARAMETER_TAG              0x0101
#define V8_SOURCE_ADDRESS_PARAMETER_TAG               0x0102
#define V8_DESTINATION_ADDRESS_PARAMETER_TAG          0x0103
#define V8_SOURCE_REFERENCE_NUMBER_PARAMETER_TAG      0x0104
#define V8_DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG 0x0105
#define V8_SCCP_CAUSE_PARAMETER_TAG                   0x0106
#define V8_SEQUENCE_NUMBER_PARAMETER_TAG              0x0107
#define V8_RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG      0x0108
#define V8_ASP_CAPABILITIES_PARAMETER_TAG             0x0109
#define V8_CREDIT_PARAMETER_TAG                       0x010a
#define V8_USER_CAUSE_PARAMETER_TAG                   0x010c
#define V8_NETWORK_APPEARANCE_PARAMETER_TAG           0x010d
#define V8_ROUTING_KEY_PARAMETER_TAG                  0x010e
#define V8_REGISTRATION_RESULT_PARAMETER_TAG          0x010f
#define V8_DEREGISTRATION_RESULT_PARAMETER_TAG        0x0110
#define V8_ADDRESS_RANGE_PARAMETER_TAG                0x0111
#define V8_CORRELATION_ID_PARAMETER_TAG               0x0112
#define V8_IMPORTANCE_PARAMETER_TAG                   0x0113
#define V8_MESSAGE_PRIORITY_PARAMETER_TAG             0x0114
#define V8_PROTOCOL_CLASS_PARAMETER_TAG               0x0115
#define V8_SEQUENCE_CONTROL_PARAMETER_TAG             0x0116
#define V8_SEGMENTATION_PARAMETER_TAG                 0x0117
#define V8_SMI_PARAMETER_TAG                          0x0118
#define V8_TID_LABEL_PARAMETER_TAG                    0x0119
#define V8_DRN_LABEL_PARAMETER_TAG                    0x011a

#define V8_GLOBAL_TITLE_PARAMETER_TAG                 0x8001
#define V8_POINT_CODE_PARAMETER_TAG                   0x8002
#define V8_SUBSYSTEM_NUMBER_PARAMETER_TAG             0x8003
#define V8_IPV4_ADDRESS_PARAMETER_TAG                 0x8004
#define V8_HOSTNAME_PARAMETER_TAG                     0x8005
#define V8_IPV6_ADDRESS_PARAMETER_TAG                 0x8006

static const value_string v8_parameter_tag_values[] = {
  { V8_DATA_PARAMETER_TAG,                         "Data" },
  { V8_INFO_STRING_PARAMETER_TAG,                  "Info String" },
  { V8_ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { V8_DIAGNOSTIC_INFO_PARAMETER_TAG,              "Diagnostic info" },
  { V8_HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { V8_TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { V8_ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { V8_STATUS_PARAMETER_TAG,                       "Status" },
  { V8_CONGESTION_LEVEL_PARAMETER_TAG,             "Congestion level" },
  { V8_ASP_IDENTIFIER_PARAMETER_TAG,               "ASP identifier" },
  { V8_AFFECTED_POINT_CODE_PARAMETER_TAG,          "Affected point code" },
  { V8_SS7_HOP_COUNTER_PARAMETER_TAG,              "SS7 hop counter" },
  { V8_SOURCE_ADDRESS_PARAMETER_TAG,               "Source address" },
  { V8_DESTINATION_ADDRESS_PARAMETER_TAG,          "Destination address" },
  { V8_SOURCE_REFERENCE_NUMBER_PARAMETER_TAG,      "Source reference number" },
  { V8_DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG, "Destination reference number" },
  { V8_SCCP_CAUSE_PARAMETER_TAG,                   "SCCP cause" },
  { V8_SEQUENCE_NUMBER_PARAMETER_TAG,              "Sequence number" },
  { V8_RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG,      "Receive sequence number" },
  { V8_ASP_CAPABILITIES_PARAMETER_TAG,             "ASP capabilities" },
  { V8_CREDIT_PARAMETER_TAG,                       "Credit" },
  { V8_USER_CAUSE_PARAMETER_TAG,                   "User/Cause" },
  { V8_NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { V8_ROUTING_KEY_PARAMETER_TAG,                  "Routing key" },
  { V8_REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" },
  { V8_DEREGISTRATION_RESULT_PARAMETER_TAG,        "Deregistration result" },
  { V8_ADDRESS_RANGE_PARAMETER_TAG,                "Address range" },
  { V8_CORRELATION_ID_PARAMETER_TAG,               "Correlation ID" },
  { V8_IMPORTANCE_PARAMETER_TAG,                   "Importance" },
  { V8_MESSAGE_PRIORITY_PARAMETER_TAG,             "Message priority" },
  { V8_PROTOCOL_CLASS_PARAMETER_TAG,               "Protocol class" },
  { V8_SEQUENCE_CONTROL_PARAMETER_TAG,             "Sequence control" },
  { V8_SEGMENTATION_PARAMETER_TAG,                 "Segmentation" },
  { V8_SMI_PARAMETER_TAG,                          "SMI" },
  { V8_TID_LABEL_PARAMETER_TAG,                    "TID label" },
  { V8_DRN_LABEL_PARAMETER_TAG,                    "DRN label" },
  { V8_GLOBAL_TITLE_PARAMETER_TAG,                 "Global title" },
  { V8_POINT_CODE_PARAMETER_TAG,                   "Point code" },
  { V8_SUBSYSTEM_NUMBER_PARAMETER_TAG,             "Subsystem number" },
  { V8_IPV4_ADDRESS_PARAMETER_TAG,                 "IPv4 address" },
  { V8_HOSTNAME_PARAMETER_TAG,                     "Hostname" },
  { V8_IPV6_ADDRESS_PARAMETER_TAG,                 "IPv6 address" },
  { 0,                                          NULL } };

static void
dissect_v8_parameter(tvbuff_t *parameter_tvb, proto_tree *tree, tvbuff_t **data_tvb, guint8 *source_ssn, guint8 *dest_ssn)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  guint8 ssn = INVALID_SSN;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (tree) {
    /* create proto_tree stuff */
    parameter_item   = proto_tree_add_text(tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, v8_parameter_tag_values, "Unknown parameter"));
    parameter_tree   = proto_item_add_subtree(parameter_item, ett_sua_parameter);

    /* add tag and length to the sua tree */
    proto_tree_add_item(parameter_tree, hf_sua_v8_parameter_tag,    parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_sua_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  } else {
    parameter_tree = NULL;
    parameter_item = NULL;
  }

  /*
  ** If no tree, only the data and ssn parameters in the source and destination
  ** address need to be dissected. This in order to make dissection of the data
  ** possible when there is no tree.
  */
  if (!tree && tag != V8_DATA_PARAMETER_TAG
            && tag != V8_SOURCE_ADDRESS_PARAMETER_TAG
            && tag != V8_DESTINATION_ADDRESS_PARAMETER_TAG
			&& tag != V8_DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG
			&& tag != V8_SOURCE_REFERENCE_NUMBER_PARAMETER_TAG
            && tag != V8_SUBSYSTEM_NUMBER_PARAMETER_TAG)
    return;

  switch(tag) {
  case V8_DATA_PARAMETER_TAG:
    dissect_data_parameter(parameter_tvb, parameter_tree, parameter_item, data_tvb);
    break;
  case V8_INFO_STRING_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_DIAGNOSTIC_INFO_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_ERROR_CODE_PARAMETER_TAG:
    dissect_v8_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_STATUS_PARAMETER_TAG:
    dissect_status_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_CONGESTION_LEVEL_PARAMETER_TAG:
    dissect_congestion_level_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_AFFECTED_POINT_CODE_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SS7_HOP_COUNTER_PARAMETER_TAG:
    dissect_ss7_hop_counter_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SOURCE_ADDRESS_PARAMETER_TAG:
    dissect_source_address_parameter(parameter_tvb, parameter_tree, source_ssn);
    break;
  case V8_DESTINATION_ADDRESS_PARAMETER_TAG:
    dissect_destination_address_parameter(parameter_tvb, parameter_tree, dest_ssn);
    break;
  case V8_SOURCE_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_source_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_destination_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SCCP_CAUSE_PARAMETER_TAG:
    dissect_sccp_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_sequence_number_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_receive_sequence_number_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_ASP_CAPABILITIES_PARAMETER_TAG:
    dissect_asp_capabilities_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_CREDIT_PARAMETER_TAG:
    dissect_credit_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_ROUTING_KEY_PARAMETER_TAG:
    dissect_routing_key_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_registration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_deregistration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_ADDRESS_RANGE_PARAMETER_TAG:
    dissect_address_range_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_CORRELATION_ID_PARAMETER_TAG:
    dissect_correlation_id_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_IMPORTANCE_PARAMETER_TAG:
    dissect_importance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_MESSAGE_PRIORITY_PARAMETER_TAG:
    dissect_message_priority_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_PROTOCOL_CLASS_PARAMETER_TAG:
    dissect_protocol_class_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SEQUENCE_CONTROL_PARAMETER_TAG:
    dissect_sequence_control_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_SEGMENTATION_PARAMETER_TAG:
    dissect_segmentation_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_SMI_PARAMETER_TAG:
    dissect_smi_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_TID_LABEL_PARAMETER_TAG:
    dissect_tid_label_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_DRN_LABEL_PARAMETER_TAG:
    dissect_drn_label_parameter(parameter_tvb, parameter_tree);
    break;
  case V8_GLOBAL_TITLE_PARAMETER_TAG:
    /* Reuse whether we have source_ssn or not to determine which address we're looking at */
    dissect_global_title_parameter(parameter_tvb, parameter_tree, (source_ssn != NULL));
    break;
  case V8_POINT_CODE_PARAMETER_TAG:
    /* Reuse whether we have source_ssn or not to determine which address we're looking at */
    dissect_point_code_parameter(parameter_tvb, parameter_tree, parameter_item, (source_ssn != NULL));
    break;
  case V8_SUBSYSTEM_NUMBER_PARAMETER_TAG:
    dissect_ssn_parameter(parameter_tvb, parameter_tree, parameter_item, &ssn);
    if(source_ssn)
    {
        *source_ssn = ssn;
    }
    if(dest_ssn)
    {
        *dest_ssn = ssn;
    }
    break;
  case V8_IPV4_ADDRESS_PARAMETER_TAG:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_HOSTNAME_PARAMETER_TAG:
    dissect_hostname_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V8_IPV6_ADDRESS_PARAMETER_TAG:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  if (parameter_tree && (padding_length > 0))
    proto_tree_add_item(parameter_tree, hf_sua_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

#define INFO_STRING_PARAMETER_TAG                  0x0004
#define ROUTING_CONTEXT_PARAMETER_TAG              0x0006
#define DIAGNOSTIC_INFO_PARAMETER_TAG              0x0007
#define HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define ERROR_CODE_PARAMETER_TAG                   0x000c
#define STATUS_PARAMETER_TAG                       0x000d
#define ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define AFFECTED_POINT_CODE_PARAMETER_TAG          0x0012
#define CORRELATION_ID_PARAMETER_TAG               0x0013
#define REGISTRATION_RESULT_PARAMETER_TAG          0x0014
#define DEREGISTRATION_RESULT_PARAMETER_TAG        0x0015
#define REGISTRATION_STATUS_PARAMETER_TAG          0x0016
#define DEREGISTRATION_STATUS_PARAMETER_TAG        0x0017
#define LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG 0x0018

#define SS7_HOP_COUNTER_PARAMETER_TAG              0x0101
#define SOURCE_ADDRESS_PARAMETER_TAG               0x0102
#define DESTINATION_ADDRESS_PARAMETER_TAG          0x0103
#define SOURCE_REFERENCE_NUMBER_PARAMETER_TAG      0x0104
#define DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG 0x0105
#define SCCP_CAUSE_PARAMETER_TAG                   0x0106
#define SEQUENCE_NUMBER_PARAMETER_TAG              0x0107
#define RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG      0x0108
#define ASP_CAPABILITIES_PARAMETER_TAG             0x0109
#define CREDIT_PARAMETER_TAG                       0x010a
#define DATA_PARAMETER_TAG                         0x010b
#define USER_CAUSE_PARAMETER_TAG                   0x010c
#define NETWORK_APPEARANCE_PARAMETER_TAG           0x010d
#define ROUTING_KEY_PARAMETER_TAG                  0x010e
#define DRN_LABEL_PARAMETER_TAG                    0x010f
#define TID_LABEL_PARAMETER_TAG                    0x0110
#define ADDRESS_RANGE_PARAMETER_TAG                0x0111
#define SMI_PARAMETER_TAG                          0x0112
#define IMPORTANCE_PARAMETER_TAG                   0x0113
#define MESSAGE_PRIORITY_PARAMETER_TAG             0x0114
#define PROTOCOL_CLASS_PARAMETER_TAG               0x0115
#define SEQUENCE_CONTROL_PARAMETER_TAG             0x0116
#define SEGMENTATION_PARAMETER_TAG                 0x0117
#define CONGESTION_LEVEL_PARAMETER_TAG             0x0118

#define GLOBAL_TITLE_PARAMETER_TAG                 0x8001
#define POINT_CODE_PARAMETER_TAG                   0x8002
#define SUBSYSTEM_NUMBER_PARAMETER_TAG             0x8003
#define IPV4_ADDRESS_PARAMETER_TAG                 0x8004
#define HOSTNAME_PARAMETER_TAG                     0x8005
#define IPV6_ADDRESS_PARAMETER_TAG                 0x8006

static const value_string parameter_tag_values[] = {
  { INFO_STRING_PARAMETER_TAG,                  "Info String" },
  { ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { DIAGNOSTIC_INFO_PARAMETER_TAG,              "Diagnostic info" },
  { HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { STATUS_PARAMETER_TAG,                       "Status" },
  { ASP_IDENTIFIER_PARAMETER_TAG,               "ASP identifier" },
  { AFFECTED_POINT_CODE_PARAMETER_TAG,          "Affected point code" },
  { CORRELATION_ID_PARAMETER_TAG,               "Correlation ID" },
  { REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" },
  { DEREGISTRATION_RESULT_PARAMETER_TAG,        "Deregistration result" },
  { REGISTRATION_STATUS_PARAMETER_TAG,          "Registration status" },
  { DEREGISTRATION_STATUS_PARAMETER_TAG,        "Deregistration status" },
  { LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" },
  { SS7_HOP_COUNTER_PARAMETER_TAG,              "SS7 hop counter" },
  { SOURCE_ADDRESS_PARAMETER_TAG,               "Source address" },
  { DESTINATION_ADDRESS_PARAMETER_TAG,          "Destination address" },
  { SOURCE_REFERENCE_NUMBER_PARAMETER_TAG,      "Source reference number" },
  { DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG, "Destination reference number" },
  { SCCP_CAUSE_PARAMETER_TAG,                   "SCCP cause" },
  { SEQUENCE_NUMBER_PARAMETER_TAG,              "Sequence number" },
  { RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG,      "Receive sequence number" },
  { ASP_CAPABILITIES_PARAMETER_TAG,             "ASP capabilities" },
  { CREDIT_PARAMETER_TAG,                       "Credit" },
  { DATA_PARAMETER_TAG,                         "Data" },
  { USER_CAUSE_PARAMETER_TAG,                   "User/Cause" },
  { NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { ROUTING_KEY_PARAMETER_TAG,                  "Routing key" },
  { DRN_LABEL_PARAMETER_TAG,                    "DRN label" },
  { TID_LABEL_PARAMETER_TAG,                    "TID label" },
  { ADDRESS_RANGE_PARAMETER_TAG,                "Address range" },
  { SMI_PARAMETER_TAG,                          "SMI" },
  { IMPORTANCE_PARAMETER_TAG,                   "Importance" },
  { MESSAGE_PRIORITY_PARAMETER_TAG,             "Message priority" },
  { PROTOCOL_CLASS_PARAMETER_TAG,               "Protocol class" },
  { SEQUENCE_CONTROL_PARAMETER_TAG,             "Sequence control" },
  { SEGMENTATION_PARAMETER_TAG,                 "Segmentation" },
  { CONGESTION_LEVEL_PARAMETER_TAG,             "Congestion level" },
  { GLOBAL_TITLE_PARAMETER_TAG,                 "Global title" },
  { POINT_CODE_PARAMETER_TAG,                   "Point code" },
  { SUBSYSTEM_NUMBER_PARAMETER_TAG,             "Subsystem number" },
  { IPV4_ADDRESS_PARAMETER_TAG,                 "IPv4 address" },
  { HOSTNAME_PARAMETER_TAG,                     "Hostname" },
  { IPV6_ADDRESS_PARAMETER_TAG,                 "IPv6 address" },
  { 0,                                          NULL } };

static void
dissect_parameter(tvbuff_t *parameter_tvb, proto_tree *tree, tvbuff_t **data_tvb, guint8 *source_ssn, guint8 *dest_ssn)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  guint8 ssn = INVALID_SSN;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (tree) {
    /* create proto_tree stuff */
    parameter_item   = proto_tree_add_text(tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, parameter_tag_values, "Unknown parameter"));
    parameter_tree   = proto_item_add_subtree(parameter_item, ett_sua_parameter);

    /* add tag and length to the sua tree */
    proto_tree_add_item(parameter_tree, hf_sua_parameter_tag,    parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_sua_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  } else {
    parameter_tree = NULL;
    parameter_item = NULL;
  }

  /*
  ** If no tree, only the data, ssn, PC, and GT parameters in the source and destination
  ** addresses need to be dissected. This in order to make dissection of the data
  ** possible and to allow us to set the source and destination addresses when there is
  ** no tree.
  */
  if (!tree && tag != DATA_PARAMETER_TAG
            && tag != SOURCE_ADDRESS_PARAMETER_TAG
            && tag != DESTINATION_ADDRESS_PARAMETER_TAG
            && tag != POINT_CODE_PARAMETER_TAG
            && tag != GLOBAL_TITLE_PARAMETER_TAG
			&& tag != DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG
			&& tag != SOURCE_REFERENCE_NUMBER_PARAMETER_TAG
            && tag != SUBSYSTEM_NUMBER_PARAMETER_TAG)
    return;	/* Nothing to do here */

  switch(tag) {
  case DATA_PARAMETER_TAG:
    dissect_data_parameter(parameter_tvb, parameter_tree, parameter_item, data_tvb);
    break;
  case INFO_STRING_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFO_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATUS_PARAMETER_TAG:
    dissect_status_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CONGESTION_LEVEL_PARAMETER_TAG:
    dissect_congestion_level_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case AFFECTED_POINT_CODE_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case REGISTRATION_STATUS_PARAMETER_TAG:
    dissect_registration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DEREGISTRATION_STATUS_PARAMETER_TAG:
    dissect_deregistration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SS7_HOP_COUNTER_PARAMETER_TAG:
    dissect_ss7_hop_counter_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SOURCE_ADDRESS_PARAMETER_TAG:
    dissect_source_address_parameter(parameter_tvb, parameter_tree, source_ssn);
    break;
  case DESTINATION_ADDRESS_PARAMETER_TAG:
    dissect_destination_address_parameter(parameter_tvb, parameter_tree, dest_ssn);
    break;
  case SOURCE_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_source_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_destination_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SCCP_CAUSE_PARAMETER_TAG:
    dissect_sccp_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_sequence_number_parameter(parameter_tvb, parameter_tree);
    break;
  case RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_receive_sequence_number_parameter(parameter_tvb, parameter_tree);
    break;
  case ASP_CAPABILITIES_PARAMETER_TAG:
    dissect_asp_capabilities_parameter(parameter_tvb, parameter_tree);
    break;
  case CREDIT_PARAMETER_TAG:
    dissect_credit_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree);
    break;
  case NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_KEY_PARAMETER_TAG:
    dissect_routing_key_parameter(parameter_tvb, parameter_tree);
    break;
  case REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_registration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_deregistration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case ADDRESS_RANGE_PARAMETER_TAG:
    dissect_address_range_parameter(parameter_tvb, parameter_tree);
    break;
  case CORRELATION_ID_PARAMETER_TAG:
    dissect_correlation_id_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IMPORTANCE_PARAMETER_TAG:
    dissect_importance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case MESSAGE_PRIORITY_PARAMETER_TAG:
    dissect_message_priority_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_CLASS_PARAMETER_TAG:
    dissect_protocol_class_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEQUENCE_CONTROL_PARAMETER_TAG:
    dissect_sequence_control_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEGMENTATION_PARAMETER_TAG:
    dissect_segmentation_parameter(parameter_tvb, parameter_tree);
    break;
  case SMI_PARAMETER_TAG:
    dissect_smi_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TID_LABEL_PARAMETER_TAG:
    dissect_tid_label_parameter(parameter_tvb, parameter_tree);
    break;
  case DRN_LABEL_PARAMETER_TAG:
    dissect_drn_label_parameter(parameter_tvb, parameter_tree);
    break;
  case GLOBAL_TITLE_PARAMETER_TAG:
    /* Reuse whether we have source_ssn or not to determine which address we're looking at */
    dissect_global_title_parameter(parameter_tvb, parameter_tree, (source_ssn != NULL));
    break;
  case POINT_CODE_PARAMETER_TAG:
    /* Reuse whether we have source_ssn or not to determine which address we're looking at */
    dissect_point_code_parameter(parameter_tvb, parameter_tree, parameter_item, (source_ssn != NULL));
    break;
  case SUBSYSTEM_NUMBER_PARAMETER_TAG:
    dissect_ssn_parameter(parameter_tvb, parameter_tree, parameter_item, &ssn);
    if(source_ssn)
    {
        *source_ssn = ssn;
    }
    if(dest_ssn)
    {
        *dest_ssn = ssn;
    }
    break;
  case IPV4_ADDRESS_PARAMETER_TAG:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HOSTNAME_PARAMETER_TAG:
    dissect_hostname_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6_ADDRESS_PARAMETER_TAG:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  if (parameter_tree && (padding_length > 0))
    proto_tree_add_item(parameter_tree, hf_sua_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

static void
dissect_parameters(tvbuff_t *parameters_tvb, proto_tree *tree, tvbuff_t **data_tvb, guint8 *source_ssn, guint8 *dest_ssn)
{
  gint offset, length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_length_remaining(parameters_tvb, offset))) {
    length       = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    total_length = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb  = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    switch(version) {
      case SUA_V08:
        dissect_v8_parameter(parameter_tvb, tree, data_tvb, source_ssn, dest_ssn);
        break;
      case SUA_RFC:
        dissect_parameter(parameter_tvb, tree, data_tvb, source_ssn, dest_ssn);
        break;
    }
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

static void
dissect_sua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *sua_tree, proto_tree *tree)
{
  tvbuff_t *common_header_tvb;
  tvbuff_t *parameters_tvb;
  tvbuff_t *data_tvb = NULL;
#if 0
  proto_tree *assoc_tree;
#endif
  guint8 source_ssn = INVALID_SSN;
  guint8 dest_ssn = INVALID_SSN;
  proto_item *assoc_item;

  message_class = 0;
  message_type = 0;
  drn = 0;
  srn = 0;

  assoc = NULL;
  no_sua_assoc.calling_dpc = 0;
  no_sua_assoc.called_dpc = 0;
  no_sua_assoc.calling_ssn = INVALID_SSN;
  no_sua_assoc.called_ssn = INVALID_SSN;
  no_sua_assoc.has_bw_key = FALSE;
  no_sua_assoc.has_fw_key = FALSE;

  sua_opc = ep_alloc0(sizeof(mtp3_addr_pc_t));
  sua_dpc = ep_alloc0(sizeof(mtp3_addr_pc_t));
  sua_source_gt = NULL;
  sua_destination_gt = NULL;

  common_header_tvb = tvb_new_subset(message_tvb, COMMON_HEADER_OFFSET, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_common_header(common_header_tvb, pinfo, sua_tree);

  parameters_tvb = tvb_new_subset_remaining(message_tvb, COMMON_HEADER_LENGTH);
  dissect_parameters(parameters_tvb, sua_tree, &data_tvb, &source_ssn, &dest_ssn);



  if ( message_class == MESSAGE_CLASS_CO_MESSAGE) {
	  /* XXX: this might fail with multihomed SCTP (on a path failure during a call) 
	   * or with "load sharing"?
	   */
	  sccp_assoc_info_t* sccp_assoc;
	  reset_sccp_assoc();
	  /* sua assoc */

	  switch (message_type){
		  case MESSAGE_TYPE_CORE:
			  assoc = sua_assoc(pinfo,&(pinfo->src),&(pinfo->dst), srn , drn);
			  if(assoc){
				  assoc->calling_routing_ind = sua_ri;
				  assoc->calling_ssn = source_ssn;
				  assoc->called_ssn = dest_ssn;
			  }
			  break;
		  case MESSAGE_TYPE_COAK:
			  assoc = sua_assoc(pinfo,&(pinfo->src),&(pinfo->dst), srn , drn);
			  if(assoc){
				  assoc->called_routing_ind = sua_ri;
				  if( (assoc->called_ssn != INVALID_SSN)&& (dest_ssn != INVALID_SSN)){
					  assoc->called_ssn = dest_ssn;
				  }
			  }
			  break;
		  default :
			  assoc = sua_assoc(pinfo,&(pinfo->src),&(pinfo->dst), srn , drn);
	  }

	  switch (message_type){
		  case MESSAGE_TYPE_CORE:
		  case MESSAGE_TYPE_COAK:
			   break;
		  default:
			  if( (assoc && assoc->called_ssn != INVALID_SSN)&& (dest_ssn != INVALID_SSN)){
				  dest_ssn = assoc->called_ssn;
			  }
			  if( (assoc && assoc->calling_ssn != INVALID_SSN)&& (source_ssn != INVALID_SSN)){
				  source_ssn = assoc->calling_ssn;
			  }

	  }
	  if (assoc && assoc->assoc_id !=0){
		  assoc_item = proto_tree_add_uint(tree, hf_sua_assoc_id, message_tvb, 0, 0, assoc->assoc_id);
		  PROTO_ITEM_SET_GENERATED(assoc_item);
#if 0
		  assoc_tree = proto_item_add_subtree(assoc_item, ett_sua_assoc);
		  proto_tree_add_text(assoc_tree, message_tvb, 0, 0, "routing_ind %u", assoc->calling_routing_ind);
		  proto_tree_add_text(assoc_tree, message_tvb, 0, 0, "routing_ind %u", assoc->called_routing_ind);
		  proto_tree_add_text(assoc_tree, message_tvb, 0, 0, "calling_ssn %u", assoc->calling_ssn);
		  proto_tree_add_text(assoc_tree, message_tvb, 0, 0, "called_ssn %u", assoc->called_ssn);
#endif /* 0 */
	  }

	  sccp_assoc = get_sccp_assoc(pinfo, tvb_offset_from_real_beginning(message_tvb), srn, drn, message_type);
	  if (sccp_assoc && sccp_assoc->curr_msg) {
		  pinfo->sccp_info = sccp_assoc->curr_msg;
		  tap_queue_packet(sua_tap,pinfo,sccp_assoc->curr_msg);
	  } else {
		   pinfo->sccp_info = NULL;
	  }
  } else {
	  pinfo->sccp_info = NULL;
  }

  if (set_addresses) {
    if (sua_opc->type)
      SET_ADDRESS(&pinfo->src, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) sua_opc);
    if (sua_dpc->type)
      SET_ADDRESS(&pinfo->dst, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) sua_dpc);

    if (sua_source_gt)
      SET_ADDRESS(&pinfo->src, AT_STRINGZ, 1+(int)strlen(sua_source_gt), sua_source_gt);
    if (sua_destination_gt)
      SET_ADDRESS(&pinfo->dst, AT_STRINGZ, 1+(int)strlen(sua_destination_gt), sua_destination_gt);
  }

  /* If there was SUA data it could be dissected */
  if(data_tvb)
  {
    /* Try subdissectors (if we found a valid SSN on the current message) */
    if ((dest_ssn == INVALID_SSN ||
       !dissector_try_uint(sccp_ssn_dissector_table, dest_ssn, data_tvb, pinfo, tree))
       && (source_ssn == INVALID_SSN ||
       !dissector_try_uint(sccp_ssn_dissector_table, source_ssn, data_tvb, pinfo, tree)))
    {
		/* try heuristic subdissector list to see if there are any takers */
		if (dissector_try_heuristic(heur_subdissector_list, data_tvb, pinfo, tree)) {
			return;
		}
      /* No sub-dissection occured, treat it as raw data */
      call_dissector(data_handle, data_tvb, pinfo, tree);
    }
  }
}

static void
dissect_sua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *sua_item;
  proto_tree *sua_tree;

  /* make entry in the Protocol column on summary display */

  switch (version) {
    case SUA_V08:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "SUA (ID 08)");
      break;
    case SUA_RFC:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "SUA (RFC 3868)");
      break;
  }

  /* Clear entries in Info column on summary display */
  col_clear(pinfo->cinfo, COL_INFO);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sua protocol tree */
    sua_item = proto_tree_add_item(tree, proto_sua, message_tvb, 0, -1, ENC_NA);
    sua_tree = proto_item_add_subtree(sua_item, ett_sua);
  } else {
    sua_tree = NULL;
  }

  /* dissect the message */
  dissect_sua_message(message_tvb, pinfo, sua_tree, tree);

}

/* Register the protocol with Wireshark */
void
proto_register_sua(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_sua_version,                               { "Version",                      "sua.version",                                   FT_UINT8,   BASE_DEC,  VALS(protocol_version_values),      0x0,                      NULL, HFILL } },
    { &hf_sua_reserved,                              { "Reserved",                     "sua.reserved",                                  FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_message_class,                         { "Message Class",                "sua.message_class",                             FT_UINT8,   BASE_DEC,  VALS(message_class_values),         0x0,                      NULL, HFILL } },
    { &hf_sua_message_type,                          { "Message Type",                 "sua.message_type",                              FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_message_length,                        { "Message Length",               "sua.message_length",                            FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_parameter_tag,                         { "Parameter Tag",                "sua.parameter_tag",                             FT_UINT16,  BASE_HEX,  VALS(parameter_tag_values),         0x0,                      NULL, HFILL } },
    { &hf_sua_v8_parameter_tag,                      { "Parameter Tag",                "sua.parameter_tag",                             FT_UINT16,  BASE_HEX,  VALS(v8_parameter_tag_values),      0x0,                      NULL, HFILL } },
    { &hf_sua_parameter_length,                      { "Parameter Length",             "sua.parameter_length",                          FT_UINT16,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_parameter_value,                       { "Parameter Value",              "sua.parameter_value",                           FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_parameter_padding,                     { "Padding",                      "sua.parameter_padding",                         FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_info_string,                           { "Info string",                  "sua.info_string",                               FT_STRING,  BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_routing_context,                       { "Routing context",              "sua.routing_context",                           FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_diagnostic_information_info,           { "Diagnostic Information",       "sua.diagnostic_information",                    FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_heartbeat_data,                        { "Heartbeat Data",               "sua.heartbeat_data",                            FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_traffic_mode_type,                     { "Traffic mode Type",            "sua.traffic_mode_type",                         FT_UINT32,  BASE_DEC,  VALS(traffic_mode_type_values),     0x0,                      NULL, HFILL } },
    { &hf_sua_error_code,                            { "Error code",                   "sua.error_code",                                FT_UINT32,  BASE_DEC,  VALS(error_code_values),            0x0,                      NULL, HFILL } },
    { &hf_sua_v8_error_code,                         { "Error code",                   "sua.error_code",                                FT_UINT32,  BASE_DEC,  VALS(v8_error_code_values),         0x0,                      NULL, HFILL } },
    { &hf_sua_status_type,                           { "Status type",                  "sua.status_type",                               FT_UINT16,  BASE_DEC,  VALS(status_type_values),           0x0,                      NULL, HFILL } },
    { &hf_sua_status_info,                           { "Status info",                  "sua.status_info",                               FT_UINT16,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_congestion_level,                      { "Congestion Level",             "sua.congestion_level",                          FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_asp_identifier,                        { "ASP Identifier",               "sua.asp_identifier",                            FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_mask,                                  { "Mask",                         "sua.affected_point_code_mask",                  FT_UINT8,   BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_dpc,                                   { "Affected DPC",                 "sua.affected_pointcode_dpc",                    FT_UINT24,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_registration_status,                   { "Registration status",          "sua.registration_status",                       FT_UINT32,  BASE_DEC,  VALS(registration_status_values),   0x0,                      NULL, HFILL } },
    { &hf_sua_deregistration_status,                 { "Deregistration status",        "sua.deregistration_status",                     FT_UINT32,  BASE_DEC,  VALS(deregistration_status_values), 0x0,                      NULL, HFILL } },
    { &hf_sua_local_routing_key_identifier,          { "Local routing key identifier", "sua.local_routing_key_identifier",              FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_source_address_routing_indicator,      { "Routing Indicator",            "sua.source_address_routing_indicator",          FT_UINT16,  BASE_DEC,  VALS(routing_indicator_values),     0x0,                      NULL, HFILL } },
    { &hf_sua_source_address_reserved_bits,          { "Reserved Bits",                "sua.source_address_reserved_bits",              FT_UINT16,  BASE_DEC,  NULL,                               ADDRESS_RESERVED_BITMASK, NULL, HFILL } },
    { &hf_sua_source_address_gt_bit,                 { "Include GT",                   "sua.source_address_gt_bit",                     FT_BOOLEAN, 16,        NULL,                               ADDRESS_GT_BITMASK,       NULL, HFILL } },
    { &hf_sua_source_address_pc_bit,                 { "Include PC",                   "sua.source_address_pc_bit",                     FT_BOOLEAN, 16,        NULL,                               ADDRESS_PC_BITMASK,       NULL, HFILL } },
    { &hf_sua_source_address_ssn_bit,                { "Include SSN",                  "sua.source_address_ssn_bit",                    FT_BOOLEAN, 16,        NULL,                               ADDRESS_SSN_BITMASK,      NULL, HFILL } },
    { &hf_sua_destination_address_routing_indicator, { "Routing Indicator",            "sua.destination_address_routing_indicator",     FT_UINT16,  BASE_DEC,  VALS(routing_indicator_values),     0x0,                      NULL, HFILL } },
    { &hf_sua_destination_address_reserved_bits,     { "Reserved Bits",                "sua.destination_address_reserved_bits",         FT_UINT16,  BASE_DEC,  NULL,                               ADDRESS_RESERVED_BITMASK, NULL, HFILL } },
    { &hf_sua_destination_address_gt_bit,            { "Include GT",                   "sua.destination_address_gt_bit",                FT_BOOLEAN, 16,        NULL,                               ADDRESS_GT_BITMASK,       NULL, HFILL } },
    { &hf_sua_destination_address_pc_bit,            { "Include PC",                   "sua.destination_address_pc_bit",                FT_BOOLEAN, 16,        NULL,                               ADDRESS_PC_BITMASK,       NULL, HFILL } },
    { &hf_sua_destination_address_ssn_bit,           { "Include SSN",                  "sua.destination_address_ssn_bit",               FT_BOOLEAN, 16,        NULL,                               ADDRESS_SSN_BITMASK,      NULL, HFILL } },
    { &hf_sua_ss7_hop_counter_counter,               { "SS7 Hop Counter",              "sua.ss7_hop_counter_counter",                   FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_ss7_hop_counter_reserved,              { "Reserved",                     "sua.ss7_hop_counter_reserved",                  FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_destination_reference_number,          { "Destination Reference Number", "sua.destination_reference_number",              FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_source_reference_number,               { "Source Reference Number",      "sua.source_reference_number",                   FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_cause_reserved,                        { "Reserved",                     "sua.sccp_cause_reserved",                       FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_cause_type,                            { "Cause Type",                   "sua.sccp_cause_type",                           FT_UINT8,   BASE_HEX,  VALS(cause_type_values),            0x0,                      NULL, HFILL } },
    { &hf_sua_cause_value,                           { "Cause Value",                  "sua.sccp_cause_value",                          FT_UINT8,   BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_sequence_number_reserved,              { "Reserved",                     "sua.sequence_number_reserved",                  FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_sequence_number_rec_number,            { "Receive Sequence Number P(R)", "sua.sequence_number_receive_sequence_number",   FT_UINT8,   BASE_DEC,  NULL,                               SEQ_NUM_MASK,             NULL, HFILL } },
    { &hf_sua_sequence_number_more_data_bit,         { "More Data Bit",                "sua.sequence_number_more_data_bit",             FT_BOOLEAN, 8,         TFS(&more_data_bit_value),          MORE_DATA_BIT_MASK,       NULL, HFILL } },
    { &hf_sua_sequence_number_sent_number,           { "Sent Sequence Number P(S)",    "sua.sequence_number_sent_sequence_number",      FT_UINT8,   BASE_DEC,  NULL,                               SEQ_NUM_MASK,             NULL, HFILL } },
    { &hf_sua_sequence_number_spare_bit,             { "Spare Bit",                    "sua.sequence_number_spare_bit",                 FT_UINT8,	BASE_DEC,  NULL,                               SPARE_BIT_MASK,           NULL, HFILL } },
    { &hf_sua_receive_sequence_number_reserved,      { "Reserved",                     "sua.receive_sequence_number_reserved",          FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_receive_sequence_number_number,        { "Receive Sequence Number P(R)", "sua.receive_sequence_number_number",            FT_UINT8,   BASE_DEC,  NULL,                               SEQ_NUM_MASK,             NULL, HFILL } },
    { &hf_sua_receive_sequence_number_spare_bit,     { "Spare Bit",                    "sua.receive_sequence_number_spare_bit",         FT_UINT8,   BASE_DEC,  NULL,                               SPARE_BIT_MASK,           NULL, HFILL } },
    { &hf_sua_asp_capabilities_reserved,             { "Reserved",                     "sua.asp_capabilities_reserved",                 FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_asp_capabilities_reserved_bits,        { "Reserved Bits",                "sua.asp_capabilities_reserved_bits",            FT_UINT8,   BASE_HEX,  NULL,                               RESERVED_BITS_MASK,       NULL, HFILL } },
    { &hf_sua_asp_capabilities_a_bit,                { "Protocol Class 3",             "sua.asp_capabilities_a_bit",                    FT_BOOLEAN, 8,         TFS(&tfs_supported_not_supported),      A_BIT_MASK,               NULL, HFILL } },
    { &hf_sua_asp_capabilities_b_bit,                { "Protocol Class 2",             "sua.asp_capabilities_b_bit",                    FT_BOOLEAN, 8,         TFS(&tfs_supported_not_supported),      B_BIT_MASK,               NULL, HFILL } },
    { &hf_sua_asp_capabilities_c_bit,                { "Protocol Class 1",             "sua.asp_capabilities_c_bit",                    FT_BOOLEAN, 8,         TFS(&tfs_supported_not_supported),      C_BIT_MASK,               NULL, HFILL } },
    { &hf_sua_asp_capabilities_d_bit,                { "Protocol Class 0",             "sua.asp_capabilities_d_bit",                    FT_BOOLEAN, 8,         TFS(&tfs_supported_not_supported),      D_BIT_MASK,               NULL, HFILL } },
    { &hf_sua_asp_capabilities_interworking,         { "Interworking",                 "sua.asp_capabilities_interworking",             FT_UINT8,   BASE_HEX,  VALS(interworking_values),          0x0,                      NULL, HFILL } },
    { &hf_sua_credit,                                { "Credit",                       "sua.credit",                                    FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_cause,                                 { "Cause",                        "sua.cause_user_cause",                          FT_UINT16,  BASE_DEC,  VALS(cause_values),                 0x0,                      NULL, HFILL } },
    { &hf_sua_user,                                  { "User",                         "sua.cause_user_user",                           FT_UINT16,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_data,                                  { "Data",                         "sua.data",                                      FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_network_appearance,                    { "Network Appearance",           "sua.network_appearance",                        FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_routing_key_identifier,                { "Local Routing Key Identifier", "sua.routing_key_identifier",                    FT_UINT32,  BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_correlation_id,                        { "Correlation ID",               "sua.correlation_id",                            FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_importance_reserved,                   { "Reserved",                     "sua.importance_reserved",                       FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_importance,                            { "Importance",                   "sua.importance_inportance",                     FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_message_priority_reserved,             { "Reserved",                     "sua.message_priority_reserved",                 FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_message_priority,                      { "Message Priority",             "sua.message_priority_priority",                 FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_protocol_class_reserved,               { "Reserved",                     "sua.protcol_class_reserved",                    FT_BYTES,   BASE_NONE,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_return_on_error_bit,                   { "Return On Error Bit",          "sua.protocol_class_return_on_error_bit",        FT_BOOLEAN, 8,         TFS(&return_on_error_bit_value),    RETURN_ON_ERROR_BIT_MASK, NULL, HFILL } },
    { &hf_sua_protocol_class,                        { "Protocol Class",               "sua.protocol_class_class",                      FT_UINT8,   BASE_DEC,  NULL,                               PROTOCOL_CLASS_MASK,      NULL, HFILL } },
    { &hf_sua_sequence_control,                      { "Sequence Control",             "sua.sequence_control_sequence_control",         FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_first_bit,                             { "First Segment Bit",            "sua.segmentation_first_bit",                    FT_BOOLEAN, 8,         TFS(&first_bit_value),              FIRST_BIT_MASK,           NULL, HFILL } },
    { &hf_sua_number_of_remaining_segments,          { "Number of Remaining Segments", "sua.segmentation_number_of_remaining_segments", FT_UINT8,   BASE_DEC,  NULL,                               NUMBER_OF_SEGMENTS_MASK,  NULL, HFILL } },
    { &hf_sua_segmentation_reference,                { "Segmentation Reference",       "sua.segmentation_reference",                    FT_UINT24,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_smi_reserved,                          { "Reserved",                     "sua.smi_reserved",                              FT_BYTES,   BASE_NONE,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_smi,                                   { "SMI",                          "sua.smi_smi",                                   FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_tid_label_start,                       { "Start",                        "sua.tid_label_start",                           FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_tid_label_end,                         { "End",                          "sua.tid_label_end",                             FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_tid_label_value,                       { "Label Value",                  "sua.tid_label_value",                           FT_UINT16,  BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_drn_label_start,                       { "Start",                        "sua.drn_label_start",                           FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_drn_label_end,                         { "End",                          "sua.drn_label_end",                             FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_drn_label_value,                       { "Label Value",                  "sua.drn_label_value",                           FT_UINT16,  BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_gt_reserved,                           { "Reserved",                     "sua.gt_reserved",                               FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_gti,                                   { "GTI",                          "sua.gti",                                       FT_UINT8,   BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_number_of_digits,                      { "Number of Digits",             "sua.global_title_number_of_digits",             FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_translation_type,                      { "Translation Type",             "sua.global_title_translation_type",             FT_UINT8,   BASE_HEX,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_numbering_plan,                        { "Numbering Plan",               "sua.global_title_numbering_plan",               FT_UINT8,   BASE_HEX,  VALS(numbering_plan_values),        0x0,                      NULL, HFILL } },
    { &hf_sua_nature_of_address,                     { "Nature of Address",            "sua.global_title_nature_of_address",            FT_UINT8,   BASE_HEX,  VALS(nature_of_address_values),     0x0,                      NULL, HFILL } },
    { &hf_sua_global_title_digits,                   { "Global Title Digits",          "sua.global_title_digits",                       FT_STRING,  BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_point_code_dpc,                        { "Point Code",                   "sua.point_code",                                FT_UINT32,  BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_ssn_reserved,                          { "Reserved",                     "sua.ssn_reserved",                              FT_BYTES,   BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_ssn_number,                            { "Subsystem Number",             "sua.ssn",                                       FT_UINT8,   BASE_DEC,  NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_ipv4,                                  { "IP Version 4 address",         "sua.ipv4_address",                              FT_IPv4,    BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_hostname,                              { "Hostname",                     "sua.hostname.name",                             FT_STRING,  BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
    { &hf_sua_ipv6,                                  { "IP Version 6 address",         "sua.ipv6_address",                              FT_IPv6,    BASE_NONE, NULL,                               0x0,                      NULL, HFILL } },
     { &hf_sua_assoc_id,
      { "Association ID", "sua.assoc.id",
	FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sua_assoc_msg,
	{"Message in frame", "sua.assoc.msg",
	FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
 };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sua,
    &ett_sua_parameter,
    &ett_sua_source_address_indicator,
    &ett_sua_destination_address_indicator,
    &ett_sua_affected_destination,
    &ett_sua_sequence_number_rec_number,
    &ett_sua_sequence_number_sent_number,
    &ett_sua_receive_sequence_number_number,
    &ett_sua_protcol_classes,
    &ett_sua_first_remaining,
    &ett_sua_return_on_error_bit_and_protocol_class,
    &ett_sua_assoc

  };

  module_t *sua_module;

  static enum_val_t options[] = {
    { "draft-08", "Internet Draft version 08", SUA_V08  },
    { "rfc3868",  "RFC 3868",                  SUA_RFC  },
    { NULL, NULL, 0 }
  };

  /* Register the protocol name and description */
  proto_sua = proto_register_protocol("SS7 SCCP-User Adaptation Layer", "SUA", "sua");
  register_dissector("sua", dissect_sua, proto_sua);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sua_module = prefs_register_protocol(proto_sua, NULL);
  prefs_register_obsolete_preference(sua_module, "sua_version");
  prefs_register_enum_preference(sua_module, "version", "SUA Version", "Version used by Wireshark", &version, options, FALSE);
  prefs_register_bool_preference(sua_module, "set_addresses", "Set source and destination addresses",
				 "Set the source and destination addresses to the PC or GT digits, depending on the routing indicator."
				 "  This may affect TCAP's ability to recognize which messages belong to which TCAP session.", &set_addresses);

  register_heur_dissector_list("sua", &heur_subdissector_list);
  sua_tap = register_tap("sua");

  assocs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "sua_associations");
}

void
proto_reg_handoff_sua(void)
{
  dissector_handle_t sua_handle;

  sua_handle = find_dissector("sua");
  dissector_add_uint("sctp.ppi",  SUA_PAYLOAD_PROTOCOL_ID, sua_handle);
  dissector_add_uint("sctp.port", SCTP_PORT_SUA,           sua_handle);

  data_handle = find_dissector("data");
  sccp_ssn_dissector_table = find_dissector_table("sccp.ssn");

}
