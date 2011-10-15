/* packet-m3ua.c
 * Routines for MTP3 User Adaptation Layer dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-05.txt (expired)
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-06.txt (expired)
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-07.txt (expired)
 * http://www.ietf.org/rfc/rfc3332.txt
 * http://datatracker.ietf.org/doc/rfc4666/
 *
 * Copyright 2000, 2001, 2002, 2003, 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
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

#include <stdlib.h>


#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/emem.h>
#include "packet-mtp3.h"
#include "packet-q708.h"
#include <epan/tap.h>

#define SCTP_PORT_M3UA         2905
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

#define VERSION_LENGTH         1
#define RESERVED_LENGTH        1
#define MESSAGE_CLASS_LENGTH   1
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_LENGTH_LENGTH  4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + RESERVED_LENGTH + MESSAGE_CLASS_LENGTH + \
                                MESSAGE_TYPE_LENGTH + MESSAGE_LENGTH_LENGTH)

#define VERSION_OFFSET         0
#define RESERVED_OFFSET        (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_CLASS_OFFSET   (RESERVED_OFFSET + RESERVED_LENGTH)
#define MESSAGE_TYPE_OFFSET    (MESSAGE_CLASS_OFFSET + MESSAGE_CLASS_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET    0
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET PARAMETER_TAG_OFFSET

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_TFER_MESSAGE        1
#define MESSAGE_CLASS_SSNM_MESSAGE        2
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_RKM_MESSAGE         9

static const value_string message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_TFER_MESSAGE,   "Transfer messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_RKM_MESSAGE,    "Routing key management messages" },
  { 0,                           NULL } };

static const value_string v5_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_TFER_MESSAGE,   "Transfer messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

#define MESSAGE_TYPE_DATA                 1

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

#define MESSAGE_TYPE_REG_REQ              1
#define MESSAGE_TYPE_REG_RSP              2
#define MESSAGE_TYPE_DEREG_REQ            3
#define MESSAGE_TYPE_DEREG_RSP            4

static const value_string v5_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "Payload data (DATA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "Destination unavailable (DUNA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "Destination available (DAVA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "Destination state audit (DAUD)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SS7 Network congestion state (SCON)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "Destination userpart unavailable (DUPU)" },
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
  { 0,                                                              NULL } };

static const value_string message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "Payload data (DATA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "Destination unavailable (DUNA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "Destination available (DAVA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "Destination state audit (DAUD)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SS7 Network congestion state (SCON)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "Destination userpart unavailable (DUPU)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "Destination Restricted (DRST)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASP up (ASPUP)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASP down (ASPDN)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "Heartbeat (BEAT)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASP up ack (ASPUP_ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP down ack (ASPDN_ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "Heartbeat ack (BEAT_ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASP active (ASPAC)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASP inactive (ASPIA)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASP active ack (ASPAC_ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASP inactive ack (ASPIA_ACK)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "Registration request (REG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "Registration response (REG_RSP)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "Deregistration request (DEREG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "Deregistration response (DEREG_RSP)" },
  { 0,                           NULL } };

static const value_string v5_message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "NTFY" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "DATA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "DUNA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "DAVA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "DAUD" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SCON" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "DUPU" },
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
  { 0,                                                              NULL } };

static const value_string message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "NTFY" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "DATA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "DUNA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "DAVA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "DAUD" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SCON" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "DUPU" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "DRST" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASPUP" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASPDN" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "BEAT" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASPUP_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASPDN_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "BEAT_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASPAC" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASPIA" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASPAC_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASPIA_ACK" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "REG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "REG_RSP" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "DEREG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "DEREG_RSP" },
  { 0,                           NULL } };

/* Initialize the protocol and registered fields */
static int proto_m3ua = -1;
static int hf_version = -1;
static int hf_reserved = -1;
static int hf_message_class = -1;
static int hf_v5_message_class = -1;
static int hf_message_type = -1;
static int hf_message_length = -1;
static int hf_v5_parameter_tag = -1;
static int hf_v6_parameter_tag = -1;
static int hf_v7_parameter_tag = -1;
static int hf_parameter_tag = -1;
static int hf_parameter_length = -1;
static int hf_parameter_value = -1;
static int hf_parameter_padding = -1;
static int hf_parameter_trailer = -1;
static int hf_network_appearance = -1;
static int hf_info_string = -1;
static int hf_routing_context = -1;
static int hf_diagnostic_information = -1;
static int hf_heartbeat_data = -1;
static int hf_v5_error_code = -1;
static int hf_v6_error_code = -1;
static int hf_v7_error_code = -1;
static int hf_error_code = -1;
static int hf_status_type = -1;
static int hf_status_info = -1;
static int hf_asp_identifier = -1;
static int hf_affected_point_code_mask = -1;
static int hf_affected_point_code_pc = -1;
static int hf_cause = -1;
static int hf_user = -1;
static int hf_reason = -1;
static int hf_v5_traffic_mode_type = -1;
static int hf_v6_traffic_mode_type = -1;
static int hf_v7_traffic_mode_type = -1;
static int hf_traffic_mode_type = -1;
static int hf_congestion_reserved = -1;
static int hf_congestion_level = -1;
static int hf_concerned_dest_reserved = -1;
static int hf_concerned_dest_pc = -1;
static int hf_local_rk_identifier = -1;
static int hf_dpc_mask = -1;
static int hf_dpc_pc = -1;
static int hf_si = -1;
static int hf_ssn = -1;
static int hf_opc_list_mask = -1;
static int hf_opc_list_pc = -1;
static int hf_cic_range_mask = -1;
static int hf_cic_range_pc = -1;
static int hf_cic_range_upper = -1;
static int hf_cic_range_lower = -1;
static int hf_protocol_data_opc = -1;
static int hf_protocol_data_dpc = -1;
static int hf_protocol_data_mtp3_opc = -1;
static int hf_protocol_data_mtp3_dpc = -1;
static int hf_protocol_data_mtp3_pc = -1;
static int hf_protocol_data_si = -1;
static int hf_protocol_data_ni = -1;
static int hf_protocol_data_mtp3_ni = -1;
static int hf_protocol_data_mp = -1;
static int hf_protocol_data_sls = -1;
static int hf_protocol_data_mtp3_sls = -1;
static int hf_correlation_identifier = -1;
static int hf_registration_status = -1;
static int hf_deregistration_status = -1;
static int hf_registration_result_identifier = -1;
static int hf_registration_result_status = -1;
static int hf_registration_result_context = -1;
static int hf_v6_deregistration_result_status = -1;
static int hf_v6_deregistration_result_context = -1;
static int hf_li = -1;


static int m3ua_tap = -1;

/* Initialize the subtree pointers */
static gint ett_m3ua = -1;
static gint ett_parameter = -1;
static gint ett_mtp3_equiv = -1;
static gint ett_q708_opc = -1;
static gint ett_q708_dpc = -1;

static module_t *m3ua_module;
static dissector_handle_t mtp3_handle, data_handle;
static dissector_table_t si_dissector_table;

/* stuff for supporting multiple versions */
typedef enum {
  M3UA_V5,
  M3UA_V6,
  M3UA_V7,
  M3UA_RFC
} Version_Type;

static gint version = M3UA_RFC;



static void
dissect_parameters(tvbuff_t *, packet_info *, proto_tree *, proto_tree *);

static void
dissect_v5_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *m3ua_tree)
{
  guint8  message_class, message_type;

  /* Extract the common header */
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_class * 256 + message_type, v5_message_class_type_acro_values, "reserved"));

  if (m3ua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(m3ua_tree, hf_version, common_header_tvb, VERSION_OFFSET, VERSION_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(m3ua_tree, hf_reserved, common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(m3ua_tree, hf_v5_message_class, common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(m3ua_tree, hf_message_type, common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, message_type,
                               "Message type: %s (%u)", val_to_str(message_class * 256 + message_type, v5_message_class_type_values, "reserved"), message_type);
    proto_tree_add_item(m3ua_tree, hf_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  }
}

static void
dissect_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *m3ua_tree)
{
  guint8  message_class, message_type;

  /* Extract the common header */
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO,"%s ", val_to_str(message_class * 256 + message_type, message_class_type_acro_values, "reserved"));

  if (m3ua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(m3ua_tree, hf_version, common_header_tvb, VERSION_OFFSET, VERSION_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(m3ua_tree, hf_reserved, common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(m3ua_tree, hf_message_class, common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(m3ua_tree, hf_message_type, common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, message_type,
                               "Message type: %s (%u)", val_to_str(message_class * 256 + message_type, message_class_type_values, "reserved"), message_type);
    proto_tree_add_item(m3ua_tree, hf_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  }
}

#define NETWORK_APPEARANCE_LENGTH 4
#define NETWORK_APPEARANCE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_network_appearance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_network_appearance, parameter_tvb, NETWORK_APPEARANCE_OFFSET, NETWORK_APPEARANCE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, NETWORK_APPEARANCE_OFFSET));
}

#define V5_PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_v5_protocol_data_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_item *parameter_item)
{
  guint16 length, protocol_data_length;
  tvbuff_t *payload_tvb;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  protocol_data_length = length - PARAMETER_HEADER_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, V5_PROTOCOL_DATA_OFFSET, protocol_data_length, protocol_data_length);
  proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
                         tvb_get_ephemeral_string(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
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
  proto_item *item;

  number_of_destinations = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) >> 2;
  destination_offset = PARAMETER_VALUE_OFFSET;
  for(destination_number=1; destination_number <= number_of_destinations; destination_number++) {
    proto_tree_add_item(parameter_tree, hf_affected_point_code_mask, parameter_tvb, destination_offset + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH, ENC_BIG_ENDIAN);
    item = proto_tree_add_item(parameter_tree, hf_affected_point_code_pc,   parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET,  AFFECTED_DPC_LENGTH,  ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET)));
    destination_offset += AFFECTED_DESTINATION_LENGTH;
  }
  proto_item_append_text(parameter_item, " (%u destination%s)", number_of_destinations, plurality(number_of_destinations, "", "s"));
}

#define ROUTING_CONTEXT_LENGTH 4

static void
dissect_routing_context_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_contexts, context_number;
  gint context_offset;

  number_of_contexts = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) >> 2;
  context_offset = PARAMETER_VALUE_OFFSET;
  for(context_number=1; context_number <= number_of_contexts; context_number++) {
    proto_tree_add_item(parameter_tree, hf_routing_context, parameter_tvb, context_offset, ROUTING_CONTEXT_LENGTH, ENC_BIG_ENDIAN);
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
  proto_tree_add_item(parameter_tree, hf_diagnostic_information, parameter_tvb, DIAGNOSTIC_INFO_OFFSET, diag_info_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", diag_info_length, plurality(diag_info_length, "", "s"));
}

#define HEARTBEAT_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 heartbeat_data_length;

  heartbeat_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

#define UNKNOWN_UNAVAIL_CAUSE                  0
#define UNEQUIPPED_REMOTE_USER_UNAVAIL_CAUSE   1
#define INACCESSIBLE_REMOTE_USER_UNAVAIL_CAUSE 2

static const value_string unavailability_cause_values[] = {
  { UNKNOWN_UNAVAIL_CAUSE,                  "Unknown"                  },
  { UNEQUIPPED_REMOTE_USER_UNAVAIL_CAUSE,   "Unequipped remote user"   },
  { INACCESSIBLE_REMOTE_USER_UNAVAIL_CAUSE, "Inaccessible remote user" },
  {0,                                       NULL } };

#define RESERVED_0_USER_ID                0
#define RESERVED_1_USER_ID                1
#define RESERVED_2_USER_ID                2
#define SCCP_USER_ID                      3
#define TUP_USER_ID                       4
#define ISUP_USER_ID                      5
#define RESERVED_6_USER_ID                6
#define RESERVED_7_USER_ID                7
#define RESERVED_8_USER_ID                8
#define BROADBAND_ISUP_USER_ID            9
#define SATELLITE_ISUP_USER_ID           10
#define RESERVED_11_USER_ID              11
#define AAL_2_SIGNALING_USER_ID          12
#define BICC_USER_ID                     13
#define GATEWAY_CONTROL_PROTOCOL_USER_ID 14
#define RESERVED_15_USER_ID              15

static const value_string user_identity_values[] = {
  { RESERVED_0_USER_ID,     "Reserved"       },
  { RESERVED_1_USER_ID,     "Reserved"       },
  { RESERVED_2_USER_ID,     "Reserved"       },
  { SCCP_USER_ID,           "SCCP"           },
  { TUP_USER_ID,            "TUP"            },
  { ISUP_USER_ID,           "ISUP"           },
  { RESERVED_6_USER_ID,     "Reserved"       },
  { RESERVED_7_USER_ID,     "Reserved"       },
  { RESERVED_8_USER_ID,     "Reserved"       },
  { BROADBAND_ISUP_USER_ID, "Broadband ISUP" },
  { SATELLITE_ISUP_USER_ID, "Satellite ISUP" },
  { RESERVED_11_USER_ID,    "Reserved"       },
  { AAL_2_SIGNALING_USER_ID,"AAL type2 Signaling"},
  { BICC_USER_ID,           "Bearer Independent Call Control (BICC)"},
  { GATEWAY_CONTROL_PROTOCOL_USER_ID, "Gateway Control Protocol"},
  { RESERVED_15_USER_ID,    "Reserved"       },

  {0,                       NULL             } };

#define CAUSE_LENGTH 2
#define USER_LENGTH  2

#define CAUSE_OFFSET  PARAMETER_VALUE_OFFSET
#define USER_OFFSET   (CAUSE_OFFSET + CAUSE_LENGTH)

static void
dissect_user_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_cause, parameter_tvb, CAUSE_OFFSET, CAUSE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_user,  parameter_tvb, USER_OFFSET,  USER_LENGTH,  ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s: %s)",
                         val_to_str(tvb_get_ntohs(parameter_tvb, USER_OFFSET),  user_identity_values,        "Unknown user"),
                         val_to_str(tvb_get_ntohs(parameter_tvb, CAUSE_OFFSET), unavailability_cause_values, "unknown cause"));
}

#define UNSPECIFIED_REASON          0
#define USER_UNAVAILABLE_REASON     1
#define MANAGEMENT_BLOCKING_REASON  2

static const value_string reason_values[] = {
  { UNSPECIFIED_REASON,         "Unspecified" },
  { USER_UNAVAILABLE_REASON,    "User unavailable" },
  { MANAGEMENT_BLOCKING_REASON, "Management blocking" },
  {0,                           NULL } };

#define REASON_LENGTH 4
#define REASON_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_reason, parameter_tvb, REASON_OFFSET, REASON_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, REASON_OFFSET), reason_values, "unknown"));
}

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

static const value_string v5_traffic_mode_type_values[] = {
  { 1, "Over-ride"            },
  { 2, "Load-share"           },
  { 3, "Over-ride (standby)"  },
  { 4, "Load-share (standby)" },
  { 0, NULL                   } };

static void
dissect_v5_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v5_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), v5_traffic_mode_type_values, "unknown"));
}

static const value_string v6_traffic_mode_type_values[] = {
  { 1, "Over-ride"            },
  { 2, "Load-share"           },
  { 3, "Over-ride (standby)"  },
  { 4, "Load-share (standby)" },
  { 0, NULL                   } };

static void
dissect_v6_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v6_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), v6_traffic_mode_type_values, "unknown"));
}

static const value_string v7_traffic_mode_type_values[] = {
  { 1, "Over-ride"            },
  { 2, "Load-share"           },
  { 0, NULL                   } };

static void
dissect_v7_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v7_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), v7_traffic_mode_type_values, "unknown"));
}

static const value_string traffic_mode_type_values[] = {
  { 1, "Over-ride"  },
  { 2, "Load-share" },
  { 3, "Broadcast"  },
  { 0, NULL         } };

static void
dissect_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), traffic_mode_type_values, "unknown"));
}

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

static const value_string v5_error_code_values[] = {
  {  1, "Invalid version"               },
  {  2, "Invalid network appearance"    },
  {  3, "Unsupported message class"     },
  {  4, "Unsupported message type"      },
  {  5, "Invalid traffic handling mode" },
  {  6, "Unexpected message"            },
  {  7, "Protocol error"                },
  {  8, "Invalid routing context"       },
  {  0,  NULL                           } };

static void
dissect_v5_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v5_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), v5_error_code_values, "unknown"));
}

static const value_string v6_error_code_values[] = {
  {  1, "Invalid version"               },
  {  2, "Invalid network appearance"    },
  {  3, "Unsupported message class"     },
  {  4, "Unsupported message type"      },
  {  5, "Invalid traffic handling mode" },
  {  6, "Unexpected message"            },
  {  7, "Protocol error"                },
  {  8, "Invalid routing context"       },
  {  9, "Invalid stream identifier"     },
  { 10, "Invalid parameter value"       },
  {  0,  NULL                           } };


static void
dissect_v6_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v6_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), v6_error_code_values, "unknown"));
}

static const value_string v7_error_code_values[] = {
  {  1, "Invalid version"               },
  {  2, "Invalid network appearance"    },
  {  3, "Unsupported message class"     },
  {  4, "Unsupported message type"      },
  {  5, "Invalid traffic handling mode" },
  {  6, "Unexpected message"            },
  {  7, "Protocol error"                },
  {  8, "Invalid routing context"       },
  {  9, "Invalid stream identifier"     },
  { 10, "Invalid parameter value"       },
  { 11, "Refused - Management Blocking" },
  { 12, "Unknown Routing Context"       },
  {  0,  NULL                           } };


static void
dissect_v7_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_v7_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), v7_error_code_values, "unknown"));
}

static const value_string error_code_values[] = {
  { 0x01, "Invalid version"                   },
  { 0x03, "Unsupported message class"         },
  { 0x04, "Unsupported message type"          },
  { 0x05, "Unsupported traffic handling mode" },
  { 0x06, "Unexpected message"                },
  { 0x07, "Protocol error"                    },
  { 0x09, "Invalid stream identifier"         },
  { 0x0d, "Refused - management blocking"     },
  { 0x0e, "ASP identifier required"           },
  { 0x0f, "Invalid ASP identifier"            },
  { 0x11, "Invalid parameter value"           },
  { 0x12, "Parameter field error"             },
  { 0x13, "Unexpected parameter"              },
  { 0x14, "Destination status unknown"        },
  { 0x15, "Invalid network appearance"        },
  { 0x16, "Missing parameter"                 },
  { 0x19, "Invalid routing context"           },
  { 0x1a, "No configured AS for ASP"          },
  { 0,    NULL                                } };

static void
dissect_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), error_code_values, "unknown"));
}

#define AS_STATE_CHANGE_TYPE       1
#define OTHER_TYPE                 2

static const value_string status_type_values[] = {
  { AS_STATE_CHANGE_TYPE,            "Application server state change" },
  { OTHER_TYPE,                      "Other" },
  { 0,                           NULL } };

#define RESERVED_INFO              1
#define AS_INACTIVE_INFO           2
#define AS_ACTIVE_INFO             3
#define AS_PENDING_INFO            4

#define INSUFFICIENT_ASP_RES_INFO  1
#define ALTERNATE_ASP_ACTIVE_INFO  2
#define ASP_FAILURE_INFO           3

static const value_string v567_status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  {0,                           NULL } };


#define STATUS_TYPE_LENGTH 2
#define STATUS_INFO_LENGTH 2

#define STATUS_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define STATUS_INFO_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

static void
dissect_v567_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_uint_format(parameter_tree, hf_status_info, parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH, status_info,
                             "Status info: %s (%u)", val_to_str(status_type * 256 * 256 + status_info, v567_status_type_info_values, "unknown"), status_info);

  proto_item_append_text(parameter_item, " (%s)", val_to_str(status_type * 256 * 256 + status_info, v567_status_type_info_values, "unknown status information"));
}

static const value_string status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  { OTHER_TYPE           * 256 * 256 + ASP_FAILURE_INFO,          "ASP Failure" },
  {0,                           NULL } };

static void
dissect_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_uint_format(parameter_tree, hf_status_info, parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH, status_info,
                             "Status info: %s (%u)", val_to_str(status_type * 256 * 256 + status_info, status_type_info_values, "unknown"), status_info);

  proto_item_append_text(parameter_item, " (%s)", val_to_str(status_type * 256 * 256 + status_info, status_type_info_values, "unknown status information"));
}

static const value_string congestion_level_values[] = {
  { 0, "No congestion or undefined" },
  { 1, "Congestion level 1"         },
  { 2, "Congestion level 2"         },
  { 3, "Congestion level 3"         },
  { 0, NULL                         } };

#define CONG_IND_RESERVED_LENGTH    3
#define CONG_IND_LEVEL_LENGTH       1

#define CONG_IND_RESERVED_OFFSET     PARAMETER_VALUE_OFFSET
#define CONG_IND_LEVEL_OFFSET        (CONG_IND_RESERVED_OFFSET + CONG_IND_RESERVED_LENGTH)

static void
dissect_congestion_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_congestion_reserved, parameter_tvb, CONG_IND_RESERVED_OFFSET, CONG_IND_RESERVED_LENGTH, ENC_NA);
  proto_tree_add_item(parameter_tree, hf_congestion_level,    parameter_tvb, CONG_IND_LEVEL_OFFSET,    CONG_IND_LEVEL_LENGTH,    ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_guint8(parameter_tvb, CONG_IND_LEVEL_OFFSET), congestion_level_values, "unknown"));
}

#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define ASP_IDENTIFIER_LENGTH  4

static void
dissect_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_asp_identifier, parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, ASP_IDENTIFIER_OFFSET));
}

#define PROTOCOL_DATA_1_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_protocol_data_1_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_item *parameter_item)
{
  guint16 protocol_data_length;
  tvbuff_t *payload_tvb;

  protocol_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, PROTOCOL_DATA_1_OFFSET, protocol_data_length, protocol_data_length);
  proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}

#define LI_OCTETT_LENGTH 1
#define LI_OCTETT_OFFSET PARAMETER_VALUE_OFFSET
#define PROTOCOL_DATA_2_OFFSET (PARAMETER_VALUE_OFFSET + LI_OCTETT_LENGTH)

static void
dissect_protocol_data_2_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 protocol_data_length;
  tvbuff_t *payload_tvb;

  protocol_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - LI_OCTETT_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, PROTOCOL_DATA_2_OFFSET, protocol_data_length, protocol_data_length);
  proto_tree_add_item(parameter_tree, hf_li, parameter_tvb, LI_OCTETT_OFFSET, LI_OCTETT_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + LI_OCTETT_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}



#define CON_DEST_RESERVED_LENGTH    1
#define CON_DEST_PC_LENGTH          3

#define CON_DEST_RESERVED_OFFSET    PARAMETER_VALUE_OFFSET
#define CON_DEST_PC_OFFSET          (CON_DEST_RESERVED_OFFSET + CON_DEST_RESERVED_LENGTH)

static void
dissect_concerned_destination_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *item;

  proto_tree_add_item(parameter_tree, hf_concerned_dest_reserved, parameter_tvb, CON_DEST_RESERVED_OFFSET, CON_DEST_RESERVED_LENGTH, ENC_NA);
  item = proto_tree_add_item(parameter_tree, hf_concerned_dest_pc,       parameter_tvb, CON_DEST_PC_OFFSET,       CON_DEST_PC_LENGTH,       ENC_BIG_ENDIAN);
  if (mtp3_pc_structured())
    proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, CON_DEST_PC_OFFSET)));
  proto_item_append_text(parameter_item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, CON_DEST_PC_OFFSET)));
}

static void
dissect_routing_key_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb          = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

static const value_string registration_result_status_values[] = {
  { 0, "Successfully Registered" } ,
  { 1, "Error - Unknown" } ,
  { 2, "Error - Invalid DPC" } ,
  { 3, "Error - Invalid Network Appearance" } ,
  { 4, "Error - Invalid Routing Key" } ,
  { 5, "Error - Permission Denied" } ,
  { 6, "Error - Overlapping (Non-unique) Routing Key" } ,
  { 7, "Error - Routing Key not Provisioned" } ,
  { 8, "Error - Insufficient Resources" } ,
  { 0, NULL } };

#define REG_RES_IDENTIFIER_LENGTH 4
#define REG_RES_STATUS_LENGTH     4
#define REG_RES_CONTEXT_LENGTH    4

#define REG_RES_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define REG_RES_STATUS_OFFSET     (REG_RES_IDENTIFIER_OFFSET + REG_RES_IDENTIFIER_LENGTH)
#define REG_RES_CONTEXT_OFFSET    (REG_RES_STATUS_OFFSET + REG_RES_STATUS_LENGTH)

static void
dissect_v67_registration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_registration_result_identifier, parameter_tvb, REG_RES_IDENTIFIER_OFFSET, REG_RES_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_registration_result_status,     parameter_tvb, REG_RES_STATUS_OFFSET,     REG_RES_STATUS_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_registration_result_context,    parameter_tvb, REG_RES_CONTEXT_OFFSET,    REG_RES_CONTEXT_LENGTH,    ENC_BIG_ENDIAN);
}

static void
dissect_registration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb          = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

static const value_string v6_deregistration_result_status_values[] = {
  { 0, "Successfully De-registered" } ,
  { 1, "Error - Unknown" } ,
  { 2, "Error - Invalid Routing context" } ,
  { 3, "Error - Permission Denied" } ,
  { 4, "Error - Not registered" } ,
  { 0, NULL } };

#define DEREG_RES_CONTEXT_LENGTH 4
#define DEREG_RES_STATUS_LENGTH  4

#define DEREG_RES_CONTEXT_OFFSET PARAMETER_VALUE_OFFSET
#define DEREG_RES_STATUS_OFFSET  (DEREG_RES_CONTEXT_OFFSET + DEREG_RES_CONTEXT_LENGTH)

static void
dissect_v67_deregistration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_v6_deregistration_result_context, parameter_tvb, DEREG_RES_CONTEXT_OFFSET, DEREG_RES_CONTEXT_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_v6_deregistration_result_status,  parameter_tvb, DEREG_RES_STATUS_OFFSET,  DEREG_RES_STATUS_LENGTH,  ENC_BIG_ENDIAN);
}

static void
dissect_deregistration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;

  length            = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}


#define LOCAL_RK_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define LOCAL_RK_IDENTIFIER_LENGTH 4

static void
dissect_local_routing_key_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_local_rk_identifier, parameter_tvb, LOCAL_RK_IDENTIFIER_OFFSET, LOCAL_RK_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, LOCAL_RK_IDENTIFIER_OFFSET));
}

#define DPC_MASK_LENGTH    1
#define DPC_PC_LENGTH      3

#define DPC_MASK_OFFSET    PARAMETER_VALUE_OFFSET
#define DPC_PC_OFFSET      (DPC_MASK_OFFSET + DPC_MASK_LENGTH)

static void
dissect_destination_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *item;

  proto_tree_add_item(parameter_tree, hf_dpc_mask, parameter_tvb, DPC_MASK_OFFSET, DPC_MASK_LENGTH, ENC_BIG_ENDIAN);
  item = proto_tree_add_item(parameter_tree, hf_dpc_pc,   parameter_tvb, DPC_PC_OFFSET,   DPC_PC_LENGTH,   ENC_BIG_ENDIAN);
  if (mtp3_pc_structured())
    proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, DPC_PC_OFFSET)));
  proto_item_append_text(parameter_item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, DPC_PC_OFFSET)));
}

#define SI_LENGTH 1

static void
dissect_service_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_sis, si_number;
  gint si_offset;

  length        = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_sis = length - PARAMETER_HEADER_LENGTH;

  si_offset = PARAMETER_VALUE_OFFSET;
  for(si_number=1; si_number <= number_of_sis; si_number++) {
    proto_tree_add_item(parameter_tree, hf_si, parameter_tvb, si_offset, SI_LENGTH, ENC_BIG_ENDIAN);
    si_offset += SI_LENGTH;
  };
  proto_item_append_text(parameter_item, " (%u indicator%s)", number_of_sis, plurality(number_of_sis, "", "s"));

}
#define SSN_LENGTH 1

static void
dissect_subsystem_numbers_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_ssns, ssn_number;
  gint ssn_offset;

  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_ssns = length - PARAMETER_HEADER_LENGTH;

  ssn_offset = PARAMETER_VALUE_OFFSET;
  for(ssn_number=1; ssn_number <= number_of_ssns; ssn_number++) {
    proto_tree_add_item(parameter_tree, hf_ssn, parameter_tvb, ssn_offset, SSN_LENGTH, ENC_BIG_ENDIAN);
    ssn_offset += SSN_LENGTH;
  };
  proto_item_append_text(parameter_item, " (%u number%s)", number_of_ssns, plurality(number_of_ssns, "", "s"));

}

#define OPC_MASK_LENGTH             1
#define OPC_PC_LENGTH               3
#define OPC_LENGTH                  (OPC_MASK_LENGTH + OPC_PC_LENGTH)
#define OPC_MASK_OFFSET             0
#define OPC_PC_OFFSET               (OPC_MASK_OFFSET + OPC_MASK_LENGTH)

static void
dissect_originating_point_code_list_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_point_codes, point_code_number;
  gint point_code_offset;
  proto_item *item;

  length                = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_point_codes = (length - PARAMETER_HEADER_LENGTH) / 4;

  point_code_offset = PARAMETER_VALUE_OFFSET;
  for(point_code_number=1; point_code_number <= number_of_point_codes; point_code_number++) {
    proto_tree_add_item(parameter_tree, hf_opc_list_mask, parameter_tvb, point_code_offset + OPC_MASK_OFFSET, OPC_MASK_LENGTH, ENC_BIG_ENDIAN);
    item = proto_tree_add_item(parameter_tree, hf_opc_list_pc,   parameter_tvb, point_code_offset + OPC_PC_OFFSET,   OPC_PC_LENGTH,   ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntoh24(parameter_tvb, point_code_offset + OPC_PC_OFFSET)));
    point_code_offset += OPC_LENGTH;
  };
  proto_item_append_text(parameter_item, " (%u point code%s)", number_of_point_codes, plurality(number_of_point_codes, "", "s"));
}

#define CIC_RANGE_MASK_LENGTH             1
#define CIC_RANGE_PC_LENGTH               3
#define CIC_RANGE_LOWER_LENGTH            2
#define CIC_RANGE_UPPER_LENGTH            2
#define CIC_RANGE_LENGTH                  (CIC_RANGE_MASK_LENGTH + CIC_RANGE_PC_LENGTH + CIC_RANGE_LOWER_LENGTH + CIC_RANGE_UPPER_LENGTH)
#define CIC_RANGE_MASK_OFFSET             0
#define CIC_RANGE_PC_OFFSET               (CIC_RANGE_MASK_OFFSET + CIC_RANGE_MASK_LENGTH)
#define CIC_RANGE_LOWER_OFFSET            (CIC_RANGE_PC_OFFSET + CIC_RANGE_PC_LENGTH)
#define CIC_RANGE_UPPER_OFFSET            (CIC_RANGE_LOWER_OFFSET + CIC_RANGE_LOWER_LENGTH)

static void
dissect_circuit_range_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_point_codes, point_code_number, cic_low, cic_high;
  guint32 pc;
  gint point_code_offset;
  proto_item *pc_item, *cic_range_item;
  proto_tree *cic_range_tree;
  gchar *pc_string;

  length                = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_point_codes = (length - PARAMETER_HEADER_LENGTH) / CIC_RANGE_LENGTH;

  point_code_offset = PARAMETER_VALUE_OFFSET;
  for(point_code_number = 1; point_code_number <= number_of_point_codes; point_code_number++) {
    cic_range_item = proto_tree_add_text(parameter_tree, parameter_tvb, point_code_offset + CIC_RANGE_MASK_OFFSET, CIC_RANGE_LENGTH, "CIC range");
    cic_range_tree = proto_item_add_subtree(cic_range_item, ett_parameter);

    proto_tree_add_item(cic_range_tree, hf_cic_range_mask,  parameter_tvb, point_code_offset + CIC_RANGE_MASK_OFFSET,  CIC_RANGE_MASK_LENGTH,  ENC_BIG_ENDIAN);

    pc = tvb_get_ntoh24(parameter_tvb, point_code_offset + CIC_RANGE_PC_OFFSET);
    pc_string = mtp3_pc_to_str(pc);
    pc_item = proto_tree_add_item(cic_range_tree, hf_cic_range_pc,    parameter_tvb, point_code_offset + CIC_RANGE_PC_OFFSET,    CIC_RANGE_PC_LENGTH,    ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(pc_item, " (%s)", pc_string);

    cic_low = tvb_get_ntohs(parameter_tvb, point_code_offset + CIC_RANGE_LOWER_OFFSET);
    proto_tree_add_item(cic_range_tree, hf_cic_range_lower, parameter_tvb, point_code_offset + CIC_RANGE_LOWER_OFFSET, CIC_RANGE_LOWER_LENGTH, ENC_BIG_ENDIAN);
    cic_high = tvb_get_ntohs(parameter_tvb, point_code_offset + CIC_RANGE_UPPER_OFFSET);
    proto_tree_add_item(cic_range_tree, hf_cic_range_upper, parameter_tvb, point_code_offset + CIC_RANGE_UPPER_OFFSET, CIC_RANGE_UPPER_LENGTH, ENC_BIG_ENDIAN);

    proto_item_append_text(cic_range_item, " (%s: %d-%d)", pc_string, cic_low, cic_high);
    point_code_offset += CIC_RANGE_LENGTH;
  };
  proto_item_append_text(parameter_item, " (%u range%s)", number_of_point_codes, plurality(number_of_point_codes, "", "s"));
}

#define DATA_OPC_LENGTH   4
#define DATA_DPC_LENGTH   4
#define DATA_SI_LENGTH    1
#define DATA_NI_LENGTH    1
#define DATA_MP_LENGTH    1
#define DATA_SLS_LENGTH   1
#define DATA_HDR_LENGTH   (DATA_OPC_LENGTH + DATA_DPC_LENGTH + DATA_SI_LENGTH + DATA_NI_LENGTH + DATA_MP_LENGTH + DATA_SLS_LENGTH)

#define DATA_OPC_OFFSET   PARAMETER_VALUE_OFFSET
#define DATA_DPC_OFFSET   (DATA_OPC_OFFSET + DATA_OPC_LENGTH)
#define DATA_SI_OFFSET    (DATA_DPC_OFFSET + DATA_DPC_LENGTH)
#define DATA_NI_OFFSET    (DATA_SI_OFFSET  + DATA_SI_LENGTH)
#define DATA_MP_OFFSET    (DATA_NI_OFFSET  + DATA_NI_LENGTH)
#define DATA_SLS_OFFSET   (DATA_MP_OFFSET  + DATA_MP_LENGTH)
#define DATA_ULP_OFFSET   (DATA_SLS_OFFSET + DATA_SLS_LENGTH)

static void
dissect_protocol_data_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 ulp_length;
  tvbuff_t *payload_tvb;
  proto_item *item;
  mtp3_tap_rec_t* mtp3_tap = ep_alloc0(sizeof(mtp3_tap_rec_t));
  proto_tree *q708_tree;


  mtp3_tap->addr_dpc.type = mtp3_standard;
  mtp3_tap->addr_dpc.pc = tvb_get_ntohl(parameter_tvb,DATA_DPC_OFFSET);
  mtp3_tap->addr_dpc.ni = tvb_get_guint8(parameter_tvb, DATA_NI_OFFSET);
  SET_ADDRESS(&pinfo->dst, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) &mtp3_tap->addr_dpc);


  mtp3_tap->addr_opc.type = mtp3_standard;
  mtp3_tap->addr_opc.pc = tvb_get_ntohl(parameter_tvb,DATA_OPC_OFFSET);
  mtp3_tap->addr_opc.ni = tvb_get_guint8(parameter_tvb, DATA_NI_OFFSET);
  SET_ADDRESS(&pinfo->src, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) &mtp3_tap->addr_opc);

  mtp3_tap->si_code = tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET);
  mtp3_tap->size = 0;

  tap_queue_packet(m3ua_tap, pinfo, mtp3_tap);

  ulp_length  = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - DATA_HDR_LENGTH;

  if (parameter_tree) {
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_opc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntohl(parameter_tvb, DATA_OPC_OFFSET)));
    if(mtp3_tap->addr_opc.ni == 0)
    {
        q708_tree = proto_item_add_subtree(item,ett_q708_opc);
		/*  Q.708 (1984-10)  Numbering of International Signalling Point Codes  */
        analyze_q708_ispc(parameter_tvb, q708_tree, DATA_OPC_OFFSET, DATA_OPC_LENGTH, mtp3_tap->addr_opc.pc);
    }
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_dpc, parameter_tvb, DATA_DPC_OFFSET, DATA_DPC_LENGTH, ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(tvb_get_ntohl(parameter_tvb, DATA_DPC_OFFSET)));
    if(mtp3_tap->addr_dpc.ni == 0)
    {
        q708_tree = proto_item_add_subtree(item,ett_q708_dpc);
        analyze_q708_ispc(parameter_tvb, q708_tree, DATA_DPC_OFFSET, DATA_DPC_LENGTH, mtp3_tap->addr_dpc.pc);
    }

    proto_tree_add_item(parameter_tree, hf_protocol_data_si,  parameter_tvb, DATA_SI_OFFSET,  DATA_SI_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_ni,  parameter_tvb, DATA_NI_OFFSET,  DATA_NI_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_mp,  parameter_tvb, DATA_MP_OFFSET,  DATA_MP_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_sls, parameter_tvb, DATA_SLS_OFFSET, DATA_SLS_LENGTH, ENC_BIG_ENDIAN);

    proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", ulp_length, plurality(ulp_length, "", "s"));
    proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + DATA_HDR_LENGTH);

    item = proto_tree_add_text(parameter_tree,parameter_tvb,0,0,"MTP3 equivalents");
    PROTO_ITEM_SET_GENERATED(item);
    parameter_tree = proto_item_add_subtree(item,ett_mtp3_equiv);

    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_opc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_dpc, parameter_tvb, DATA_DPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_pc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_pc, parameter_tvb, DATA_DPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_ni,  parameter_tvb, DATA_NI_OFFSET,  DATA_NI_LENGTH,  ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_sls, parameter_tvb, DATA_SLS_OFFSET, DATA_SLS_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);

  }/* parameter_tree */

  payload_tvb = tvb_new_subset(parameter_tvb, DATA_ULP_OFFSET, ulp_length, ulp_length);
  if (!dissector_try_uint(si_dissector_table, tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET), payload_tvb, pinfo, tree))
    call_dissector(data_handle, payload_tvb, pinfo, tree);
}

#define CORR_ID_OFFSET PARAMETER_VALUE_OFFSET
#define CORR_ID_LENGTH 4

static void
dissect_correlation_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_correlation_identifier, parameter_tvb, CORR_ID_OFFSET, CORR_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, CORR_ID_OFFSET));
}

#define REG_STATUS_LENGTH  4
#define REG_STATUS_OFFSET  PARAMETER_VALUE_OFFSET

static const value_string registration_status_values[] = {
  {  0, "Successfully Registered" },
  {  1, "Error - Unknown" },
  {  2, "Error - Invalid DPC" },
  {  3, "Error - Invalid Network Appearance" },
  {  4, "Error - Invalid Routing Key" },
  {  5, "Error - Permission Denied" },
  {  6, "Error - Cannot Support Unique Routing" },
  {  7, "Error - Routing Key not Currently Provisioned" },
  {  8, "Error - Insufficient Resources" },
  {  9, "Error - Unsupported RK parameter Field" },
  { 10, "Error - Unsupported/Invalid Traffic Handling Mode" },
  { 11, "Error - Routing Key Change Refused" },
  { 12, "Error - Routing Key Already Registered" },
  {  0, NULL } };

static void
dissect_registration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_registration_status, parameter_tvb, REG_STATUS_OFFSET, REG_STATUS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, REG_STATUS_OFFSET), registration_status_values, "unknown"));
}

#define DEREG_STATUS_LENGTH  4
#define DEREG_STATUS_OFFSET  PARAMETER_VALUE_OFFSET

static const value_string deregistration_status_values[] = {
  { 0, "Successfully Deregistered" },
  { 1, "Error - Unknown" },
  { 2, "Error - Invalid Routing Context" },
  { 3, "Error - Permission Denied" },
  { 4, "Error - Not Registered" },
  { 5, "Error - ASP Currently Active for Routing Context" },
  { 0, NULL } };

static void
dissect_deregistration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_deregistration_status, parameter_tvb, DEREG_STATUS_OFFSET, DEREG_STATUS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, DEREG_STATUS_OFFSET), deregistration_status_values, "unknown"));
}

static void
dissect_registration_results_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 parameters_length;

  parameters_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

static void
dissect_deregistration_results_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 parameters_length;

  parameters_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 tag, parameter_value_length;

  tag                    = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);
  proto_item_append_text(parameter_item, " (tag %u and %u byte%s value)", tag, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define V5_NETWORK_APPEARANCE_PARAMETER_TAG       1
#define V5_PROTOCOL_DATA_PARAMETER_TAG            3
#define V5_INFO_PARAMETER_TAG                     4
#define V5_AFFECTED_DESTINATIONS_PARAMETER_TAG    5
#define V5_ROUTING_CONTEXT_PARAMETER_TAG          6
#define V5_DIAGNOSTIC_INFORMATION_PARAMETER_TAG   7
#define V5_HEARTBEAT_DATA_PARAMETER_TAG           8
#define V5_USER_CAUSE_PARAMETER_TAG               9
#define V5_REASON_PARAMETER_TAG                   10
#define V5_TRAFFIC_MODE_TYPE_PARAMETER_TAG        11
#define V5_ERROR_CODE_PARAMETER_TAG               12
#define V5_STATUS_PARAMETER_TAG                   13
#define V5_CONGESTION_INDICATION_PARAMETER_TAG    14

static const value_string v5_parameter_tag_values[] = {
  { V5_NETWORK_APPEARANCE_PARAMETER_TAG,     "Network appearance" },
  { V5_PROTOCOL_DATA_PARAMETER_TAG,          "Protocol data" },
  { V5_INFO_PARAMETER_TAG,                   "Info" },
  { V5_AFFECTED_DESTINATIONS_PARAMETER_TAG,  "Affected destinations" },
  { V5_ROUTING_CONTEXT_PARAMETER_TAG,        "Routing context" },
  { V5_DIAGNOSTIC_INFORMATION_PARAMETER_TAG, "Diagnostic information" },
  { V5_HEARTBEAT_DATA_PARAMETER_TAG,         "Heartbeat data" },
  { V5_USER_CAUSE_PARAMETER_TAG,             "User / Cause" },
  { V5_REASON_PARAMETER_TAG,                 "Reason" },
  { V5_TRAFFIC_MODE_TYPE_PARAMETER_TAG,      "Traffic mode type" },
  { V5_ERROR_CODE_PARAMETER_TAG,             "Error code" },
  { V5_STATUS_PARAMETER_TAG,                 "Status" },
  { V5_CONGESTION_INDICATION_PARAMETER_TAG,  "Congestion indication" },
  { 0,                                       NULL } };

static void
dissect_v5_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (!tree && tag != V5_PROTOCOL_DATA_PARAMETER_TAG)
    return;    /* Nothing to do here */

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, v5_parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_parameter);

  /* add tag and length to the parameter tree */
  proto_tree_add_item(parameter_tree, hf_v5_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case V5_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_PROTOCOL_DATA_PARAMETER_TAG:
    dissect_v5_protocol_data_parameter(parameter_tvb, pinfo, tree, parameter_item);
    break;
  case V5_INFO_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_AFFECTED_DESTINATIONS_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_REASON_PARAMETER_TAG:
    dissect_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_v5_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_ERROR_CODE_PARAMETER_TAG:
    dissect_v5_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_STATUS_PARAMETER_TAG:
    dissect_v567_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V5_CONGESTION_INDICATION_PARAMETER_TAG:
    dissect_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

#define V6_NETWORK_APPEARANCE_PARAMETER_TAG            1
#define V6_PROTOCOL_DATA_1_PARAMETER_TAG               2
#define V6_PROTOCOL_DATA_2_PARAMETER_TAG               3
#define V6_INFO_PARAMETER_TAG                          4
#define V6_AFFECTED_DESTINATIONS_PARAMETER_TAG         5
#define V6_ROUTING_CONTEXT_PARAMETER_TAG               6
#define V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG        7
#define V6_HEARTBEAT_DATA_PARAMETER_TAG                8
#define V6_USER_CAUSE_PARAMETER_TAG                    9
#define V6_REASON_PARAMETER_TAG                       10
#define V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG            11
#define V6_ERROR_CODE_PARAMETER_TAG                   12
#define V6_STATUS_PARAMETER_TAG                       13
#define V6_CONGESTION_INDICATION_PARAMETER_TAG        14
#define V6_CONCERNED_DESTINATION_PARAMETER_TAG        15
#define V6_ROUTING_KEY_PARAMETER_TAG                  16
#define V6_REGISTRATION_RESULT_PARAMETER_TAG          17
#define V6_DEREGISTRATION_RESULT_PARAMETER_TAG        18
#define V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG 19
#define V6_DESTINATION_POINT_CODE_PARAMETER_TAG       20
#define V6_SERVICE_INDICATORS_PARAMETER_TAG           21
#define V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG            22
#define V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG  23
#define V6_CIRCUIT_RANGE_PARAMETER_TAG                24
#define V6_REGISTRATION_RESULTS_PARAMETER_TAG         25
#define V6_DEREGISTRATION_RESULTS_PARAMETER_TAG       26

static const value_string v6_parameter_tag_values[] = {
  { V6_NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { V6_PROTOCOL_DATA_1_PARAMETER_TAG,              "Protocol data 1" },
  { V6_PROTOCOL_DATA_2_PARAMETER_TAG,              "Protocol data 2" },
  { V6_INFO_PARAMETER_TAG,                         "Info" },
  { V6_AFFECTED_DESTINATIONS_PARAMETER_TAG,        "Affected destinations" },
  { V6_ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic information" },
  { V6_HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { V6_USER_CAUSE_PARAMETER_TAG,                   "User / Cause" },
  { V6_REASON_PARAMETER_TAG,                       "Reason" },
  { V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { V6_ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { V6_STATUS_PARAMETER_TAG,                       "Status" },
  { V6_CONGESTION_INDICATION_PARAMETER_TAG,        "Congestion indication" },
  { V6_CONCERNED_DESTINATION_PARAMETER_TAG,        "Concerned destination" },
  { V6_ROUTING_KEY_PARAMETER_TAG,                  "Routing Key" },
  { V6_REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" },
  { V6_DEREGISTRATION_RESULT_PARAMETER_TAG,        "De-registration result" },
  { V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" },
  { V6_DESTINATION_POINT_CODE_PARAMETER_TAG,       "Destination point code" },
  { V6_SERVICE_INDICATORS_PARAMETER_TAG,           "Service indicators" },
  { V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG,            "Subsystem numbers" },
  { V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG,  "Originating point code list" },
  { V6_CIRCUIT_RANGE_PARAMETER_TAG,                "Circuit range" },
  { V6_REGISTRATION_RESULTS_PARAMETER_TAG,         "Registration results" },
  { V6_DEREGISTRATION_RESULTS_PARAMETER_TAG,       "De-registration results" },
  { 0,                           NULL } };

static void
dissect_v6_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (!tree && tag != V6_PROTOCOL_DATA_1_PARAMETER_TAG && tag != V6_PROTOCOL_DATA_2_PARAMETER_TAG)
    return;    /* Nothing to do here */

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, v6_parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_parameter);

  /* add tag and length to the parameter tree */
  proto_tree_add_item(parameter_tree, hf_v6_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case V6_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_PROTOCOL_DATA_1_PARAMETER_TAG:
    dissect_protocol_data_1_parameter(parameter_tvb, pinfo, tree, parameter_item);
    break;
  case V6_PROTOCOL_DATA_2_PARAMETER_TAG:
    dissect_protocol_data_2_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V6_INFO_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_AFFECTED_DESTINATIONS_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_REASON_PARAMETER_TAG:
    dissect_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_v6_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ERROR_CODE_PARAMETER_TAG:
    dissect_v6_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_STATUS_PARAMETER_TAG:
    dissect_v567_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CONGESTION_INDICATION_PARAMETER_TAG:
    dissect_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CONCERNED_DESTINATION_PARAMETER_TAG:
    dissect_concerned_destination_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ROUTING_KEY_PARAMETER_TAG:
    dissect_routing_key_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case V6_REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_v67_registration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V6_DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_v67_deregistration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_DESTINATION_POINT_CODE_PARAMETER_TAG:
    dissect_destination_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_SERVICE_INDICATORS_PARAMETER_TAG:
    dissect_service_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG:
    dissect_subsystem_numbers_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG:
    dissect_originating_point_code_list_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CIRCUIT_RANGE_PARAMETER_TAG:
    dissect_circuit_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_REGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_registration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case V6_DEREGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_deregistration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

#define V7_NETWORK_APPEARANCE_PARAMETER_TAG            0x80
#define V7_PROTOCOL_DATA_1_PARAMETER_TAG               0x81
#define V7_PROTOCOL_DATA_2_PARAMETER_TAG               0x82
#define V7_INFO_PARAMETER_TAG                          0x04
#define V7_AFFECTED_DESTINATIONS_PARAMETER_TAG         0x83
#define V7_ROUTING_CONTEXT_PARAMETER_TAG               0x06
#define V7_DIAGNOSTIC_INFORMATION_PARAMETER_TAG        0x07
#define V7_HEARTBEAT_DATA_PARAMETER_TAG                0x09
#define V7_USER_CAUSE_PARAMETER_TAG                    0x84
#define V7_REASON_PARAMETER_TAG                        0x0a
#define V7_TRAFFIC_MODE_TYPE_PARAMETER_TAG             0x0b
#define V7_ERROR_CODE_PARAMETER_TAG                    0x0c
#define V7_STATUS_PARAMETER_TAG                        0x0d
#define V7_CONGESTION_INDICATION_PARAMETER_TAG         0x85
#define V7_CONCERNED_DESTINATION_PARAMETER_TAG         0x86
#define V7_ROUTING_KEY_PARAMETER_TAG                   0x87
#define V7_REGISTRATION_RESULT_PARAMETER_TAG           0x88
#define V7_DEREGISTRATION_RESULT_PARAMETER_TAG         0x89
#define V7_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG  0x8a
#define V7_DESTINATION_POINT_CODE_PARAMETER_TAG        0x8b
#define V7_SERVICE_INDICATORS_PARAMETER_TAG            0x8c
#define V7_SUBSYSTEM_NUMBERS_PARAMETER_TAG             0x8d
#define V7_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG   0x8e
#define V7_CIRCUIT_RANGE_PARAMETER_TAG                 0x8f
#define V7_REGISTRATION_RESULTS_PARAMETER_TAG          0x90
#define V7_DEREGISTRATION_RESULTS_PARAMETER_TAG        0x91

static const value_string v7_parameter_tag_values[] = {
  { V7_NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { V7_PROTOCOL_DATA_1_PARAMETER_TAG,              "Protocol data 1" },
  { V7_PROTOCOL_DATA_2_PARAMETER_TAG,              "Protocol data 2" },
  { V7_INFO_PARAMETER_TAG,                         "Info" },
  { V7_AFFECTED_DESTINATIONS_PARAMETER_TAG,        "Affected destinations" },
  { V7_ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { V7_DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic information" },
  { V7_HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { V7_USER_CAUSE_PARAMETER_TAG,                   "User / Cause" },
  { V7_REASON_PARAMETER_TAG,                       "Reason" },
  { V7_TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { V7_ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { V7_STATUS_PARAMETER_TAG,                       "Status" },
  { V7_CONGESTION_INDICATION_PARAMETER_TAG,        "Congestion indication" },
  { V7_CONCERNED_DESTINATION_PARAMETER_TAG,        "Concerned destination" },
  { V7_ROUTING_KEY_PARAMETER_TAG,                  "Routing Key" },
  { V7_REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" },
  { V7_DEREGISTRATION_RESULT_PARAMETER_TAG,        "De-registration result" },
  { V7_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" },
  { V7_DESTINATION_POINT_CODE_PARAMETER_TAG,       "Destination point code" },
  { V7_SERVICE_INDICATORS_PARAMETER_TAG,           "Service indicators" },
  { V7_SUBSYSTEM_NUMBERS_PARAMETER_TAG,            "Subsystem numbers" },
  { V7_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG,  "Originating point code list" },
  { V7_CIRCUIT_RANGE_PARAMETER_TAG,                "Circuit range" },
  { V7_REGISTRATION_RESULTS_PARAMETER_TAG,         "Registration results" },
  { V7_DEREGISTRATION_RESULTS_PARAMETER_TAG,       "De-registration results" },
  { 0,                           NULL } };

static void
dissect_v7_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (!tree && tag != V7_PROTOCOL_DATA_1_PARAMETER_TAG && tag != V7_PROTOCOL_DATA_2_PARAMETER_TAG)
    return;    /* Nothing to do here */

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, v7_parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_parameter);

  /* add tag and length to the parameter tree */
  proto_tree_add_item(parameter_tree, hf_v7_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case V7_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_PROTOCOL_DATA_1_PARAMETER_TAG:
    dissect_protocol_data_1_parameter(parameter_tvb, pinfo, tree, parameter_item);
    break;
  case V7_PROTOCOL_DATA_2_PARAMETER_TAG:
    dissect_protocol_data_2_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V7_INFO_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_AFFECTED_DESTINATIONS_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_REASON_PARAMETER_TAG:
    dissect_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_v7_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_ERROR_CODE_PARAMETER_TAG:
    dissect_v7_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_STATUS_PARAMETER_TAG:
    dissect_v567_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_CONGESTION_INDICATION_PARAMETER_TAG:
    dissect_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_CONCERNED_DESTINATION_PARAMETER_TAG:
    dissect_concerned_destination_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_ROUTING_KEY_PARAMETER_TAG:
    dissect_routing_key_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case V7_REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_v67_registration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V7_DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_v67_deregistration_result_parameter(parameter_tvb, parameter_tree);
    break;
  case V7_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_DESTINATION_POINT_CODE_PARAMETER_TAG:
    dissect_destination_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_SERVICE_INDICATORS_PARAMETER_TAG:
    dissect_service_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_SUBSYSTEM_NUMBERS_PARAMETER_TAG:
    dissect_subsystem_numbers_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG:
    dissect_originating_point_code_list_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_CIRCUIT_RANGE_PARAMETER_TAG:
    dissect_circuit_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V7_REGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_registration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case V7_DEREGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_deregistration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

#define INFO_STRING_PARAMETER_TAG                  0x0004
#define ROUTING_CONTEXT_PARAMETER_TAG              0x0006
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG       0x0007
#define HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define ERROR_CODE_PARAMETER_TAG                   0x000c
#define STATUS_PARAMETER_TAG                       0x000d
#define ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define AFFECTED_POINT_CODE_PARAMETER_TAG          0x0012
#define CORRELATION_IDENTIFIER_PARAMETER_TAG       0x0013

#define NETWORK_APPEARANCE_PARAMETER_TAG           0x0200
#define USER_CAUSE_PARAMETER_TAG                   0x0204
#define CONGESTION_INDICATIONS_PARAMETER_TAG       0x0205
#define CONCERNED_DESTINATION_PARAMETER_TAG        0x0206
#define ROUTING_KEY_PARAMETER_TAG                  0x0207
#define REGISTRATION_RESULT_PARAMETER_TAG          0x0208
#define DEREGISTRATION_RESULT_PARAMETER_TAG        0x0209
#define LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG 0x020a
#define DESTINATION_POINT_CODE_PARAMETER_TAG       0x020b
#define SERVICE_INDICATORS_PARAMETER_TAG           0x020c
#define ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG  0x020e
#define CIRCUIT_RANGE_PARAMETER_TAG                0x020f
#define PROTOCOL_DATA_PARAMETER_TAG                0x0210
#define REGISTRATION_STATUS_PARAMETER_TAG          0x0212
#define DEREGISTRATION_STATUS_PARAMETER_TAG        0x0213

static const value_string parameter_tag_values[] = {
  { INFO_STRING_PARAMETER_TAG,                  "Info string" } ,
  { ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" } ,
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic Information" } ,
  { HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" } ,
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" } ,
  { ERROR_CODE_PARAMETER_TAG,                   "Error code" } ,
  { STATUS_PARAMETER_TAG,                       "Status" } ,
  { ASP_IDENTIFIER_PARAMETER_TAG,               "ASP identifier" } ,
  { AFFECTED_POINT_CODE_PARAMETER_TAG,          "Affected point code" } ,
  { CORRELATION_IDENTIFIER_PARAMETER_TAG,       "Correlation identifier" } ,
  { NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" } ,
  { USER_CAUSE_PARAMETER_TAG,                   "User / cause" } ,
  { CONGESTION_INDICATIONS_PARAMETER_TAG,       "Congestion indications" } ,
  { CONCERNED_DESTINATION_PARAMETER_TAG,        "Concerned destination" } ,
  { ROUTING_KEY_PARAMETER_TAG,                  "Routing key" } ,
  { REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" } ,
  { DEREGISTRATION_RESULT_PARAMETER_TAG,        "Deregistration result" } ,
  { LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" } ,
  { DESTINATION_POINT_CODE_PARAMETER_TAG,       "Destination point code" } ,
  { SERVICE_INDICATORS_PARAMETER_TAG,           "Service indicators" } ,
  { ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG,  "Originating point code list" } ,
  { CIRCUIT_RANGE_PARAMETER_TAG,                "Circuit range" } ,
  { PROTOCOL_DATA_PARAMETER_TAG,                "Protocol data" } ,
  { REGISTRATION_STATUS_PARAMETER_TAG,          "Registration status" } ,
  { DEREGISTRATION_STATUS_PARAMETER_TAG,        "Deregistration status" } ,
  { 0,                           NULL } };

static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;


  if (!tree && tag != PROTOCOL_DATA_PARAMETER_TAG)
    return;    /* Nothing to do here */

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(tag, parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_parameter);

  /* add tag and length to the parameter tree */
  proto_tree_add_item(parameter_tree, hf_parameter_tag,    parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case INFO_STRING_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
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
    dissect_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case AFFECTED_POINT_CODE_PARAMETER_TAG:
    dissect_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case USER_CAUSE_PARAMETER_TAG:
    dissect_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CONGESTION_INDICATIONS_PARAMETER_TAG:
    dissect_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CONCERNED_DESTINATION_PARAMETER_TAG:
    dissect_concerned_destination_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_KEY_PARAMETER_TAG:
    dissect_routing_key_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_registration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_deregistration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DESTINATION_POINT_CODE_PARAMETER_TAG:
    dissect_destination_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SERVICE_INDICATORS_PARAMETER_TAG:
    dissect_service_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG:
    dissect_originating_point_code_list_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CIRCUIT_RANGE_PARAMETER_TAG:
    dissect_circuit_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_DATA_PARAMETER_TAG:
    dissect_protocol_data_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case CORRELATION_IDENTIFIER_PARAMETER_TAG:
    dissect_correlation_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case REGISTRATION_STATUS_PARAMETER_TAG:
    dissect_registration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DEREGISTRATION_STATUS_PARAMETER_TAG:
    dissect_deregistration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

static void
dissect_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
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
    parameter_tvb    = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    switch(version) {
      case M3UA_V5:
        dissect_v5_parameter(parameter_tvb, pinfo, tree, m3ua_tree);
        break;
      case M3UA_V6:
        dissect_v6_parameter(parameter_tvb, pinfo, tree, m3ua_tree);
        break;
      case M3UA_V7:
        dissect_v7_parameter(parameter_tvb, pinfo, tree, m3ua_tree);
        break;
      case M3UA_RFC:
        dissect_parameter(parameter_tvb, pinfo, tree, m3ua_tree);
        break;
    }
    /* get rid of the handled parameter */
    offset += total_length;
  }
}


static void
dissect_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  tvbuff_t *common_header_tvb, *parameters_tvb;

  common_header_tvb = tvb_new_subset(message_tvb, 0, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  parameters_tvb    = tvb_new_subset_remaining(message_tvb, COMMON_HEADER_LENGTH);
  if (version == M3UA_V5)
    dissect_v5_common_header(common_header_tvb, pinfo, m3ua_tree);
  else
    dissect_common_header(common_header_tvb, pinfo, m3ua_tree);

  /*  Need to dissect (certain) parameters even when !tree, so subdissectors
   *  (e.g., MTP3) are always called.
   */
  dissect_parameters(parameters_tvb, pinfo, tree, m3ua_tree);
}

static void
dissect_m3ua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m3ua_item;
  proto_tree *m3ua_tree;


  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    switch(version) {
      case M3UA_V5:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "M3UA (ID 05)");
        break;
      case M3UA_V6:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "M3UA (ID 06)");
        break;
      case M3UA_V7:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "M3UA (ID 07)");
        break;
      case M3UA_RFC:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "M3UA (RFC 3332)");
        break;
      };

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m3ua protocol tree */
    m3ua_item = proto_tree_add_item(tree, proto_m3ua, message_tvb, 0, -1, ENC_NA);
    m3ua_tree = proto_item_add_subtree(m3ua_item, ett_m3ua);
  } else {
    m3ua_tree = NULL;
  };

  /* dissect the message */
  dissect_message(message_tvb, pinfo, tree, m3ua_tree);

}

/* Register the protocol with Wireshark */
void
proto_register_m3ua(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_version,                          { "Version",                      "m3ua.version",                               FT_UINT8,  BASE_DEC,  VALS(protocol_version_values),                0x0, NULL,				HFILL } },
    { &hf_reserved,                         { "Reserved",                     "m3ua.reserved",                              FT_UINT8,  BASE_HEX,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_v5_message_class,                 { "Message class",                "m3ua.message_class",                         FT_UINT8,  BASE_DEC,  VALS(v5_message_class_values),                0x0, NULL,				HFILL } },
    { &hf_message_class,                    { "Message class",                "m3ua.message_class",                         FT_UINT8,  BASE_DEC,  VALS(message_class_values),                   0x0, NULL,				HFILL } },
    { &hf_message_type,                     { "Message Type",                 "m3ua.message_type",                          FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_message_length,                   { "Message length",               "m3ua.message_length",                        FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_v5_parameter_tag,                 { "Parameter Tag",                "m3ua.parameter_tag",                         FT_UINT16, BASE_DEC,  VALS(v5_parameter_tag_values),                0x0, NULL,				HFILL } },
    { &hf_v6_parameter_tag,                 { "Parameter Tag",                "m3ua.parameter_tag",                         FT_UINT16, BASE_DEC,  VALS(v6_parameter_tag_values),                0x0, NULL,				HFILL } },
    { &hf_v7_parameter_tag,                 { "Parameter Tag",                "m3ua.parameter_tag",                         FT_UINT16, BASE_DEC,  VALS(v7_parameter_tag_values),                0x0, NULL,				HFILL } },
    { &hf_parameter_tag,                    { "Parameter Tag",                "m3ua.parameter_tag",                         FT_UINT16, BASE_DEC,  VALS(parameter_tag_values),                   0x0, NULL,				HFILL } },
    { &hf_parameter_length,                 { "Parameter length",             "m3ua.parameter_length",                      FT_UINT16, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_parameter_value,                  { "Parameter value",              "m3ua.parameter_value",                       FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_parameter_padding,                { "Padding",                      "m3ua.parameter_padding",                     FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_parameter_trailer,                { "Trailer",                      "m3ua.paramter_trailer",                      FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_network_appearance,               { "Network appearance",           "m3ua.network_appearance",                    FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_info_string,                      { "Info string",                  "m3ua.info_string",                           FT_STRING, BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_routing_context,                  { "Routing context",              "m3ua.routing_context",                       FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_diagnostic_information,           { "Diagnostic information",       "m3ua.diagnostic_information",                FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_heartbeat_data,                   { "Heartbeat data",               "m3ua.heartbeat_data",                        FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_v5_error_code,                    { "Error code",                   "m3ua.error_code",                            FT_UINT32, BASE_DEC,  VALS(v5_error_code_values),                   0x0, NULL,				HFILL } },
    { &hf_v6_error_code,                    { "Error code",                   "m3ua.error_code",                            FT_UINT32, BASE_DEC,  VALS(v6_error_code_values),                   0x0, NULL,				HFILL } },
    { &hf_v7_error_code,                    { "Error code",                   "m3ua.error_code",                            FT_UINT32, BASE_DEC,  VALS(v7_error_code_values),                   0x0, NULL,				HFILL } },
    { &hf_error_code,                       { "Error code",                   "m3ua.error_code",                            FT_UINT32, BASE_DEC,  VALS(error_code_values),                      0x0, NULL,				HFILL } },
    { &hf_status_type,                      { "Status type",                  "m3ua.status_type",                           FT_UINT16, BASE_DEC,  VALS(status_type_values),                     0x0, NULL,				HFILL } },
    { &hf_status_info,                      { "Status info",                  "m3ua.status_info",                           FT_UINT16, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_asp_identifier,                   { "ASP identifier",               "m3ua.asp_identifier",                        FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_affected_point_code_mask,         { "Mask",                         "m3ua.affected_point_code_mask",              FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_affected_point_code_pc,           { "Affected point code",          "m3ua.affected_point_code_pc",                FT_UINT24, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_cause,                            { "Unavailability cause",         "m3ua.unavailability_cause",                  FT_UINT16, BASE_DEC,  VALS(unavailability_cause_values),            0x0, NULL,				HFILL } },
    { &hf_user,                             { "User Identity",                "m3ua.user_identity",                         FT_UINT16, BASE_DEC,  VALS(user_identity_values),                   0x0, NULL,				HFILL } },
    { &hf_reason,                           { "Reason",                       "m3ua.reason",                                FT_UINT32, BASE_DEC,  VALS(reason_values),                          0x0, NULL,				HFILL } },
    { &hf_v5_traffic_mode_type,             { "Traffic mode Type",            "m3ua.traffic_mode_type",                     FT_UINT32, BASE_DEC,  VALS(v5_traffic_mode_type_values),            0x0, NULL,				HFILL } },
    { &hf_v6_traffic_mode_type,             { "Traffic mode Type",            "m3ua.traffic_mode_type",                     FT_UINT32, BASE_DEC,  VALS(v6_traffic_mode_type_values),            0x0, NULL,				HFILL } },
    { &hf_v7_traffic_mode_type,             { "Traffic mode Type",            "m3ua.traffic_mode_type",                     FT_UINT32, BASE_DEC,  VALS(v7_traffic_mode_type_values),            0x0, NULL,				HFILL } },
    { &hf_traffic_mode_type,                { "Traffic mode Type",            "m3ua.traffic_mode_type",                     FT_UINT32, BASE_DEC,  VALS(traffic_mode_type_values),               0x0, NULL,				HFILL } },
    { &hf_congestion_reserved,              { "Reserved",                     "m3ua.congestion_reserved",                   FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_congestion_level,                 { "Congestion level",             "m3ua.congestion_level",                      FT_UINT8,  BASE_DEC,  VALS(congestion_level_values),                0x0, NULL,				HFILL } },
    { &hf_concerned_dest_reserved,          { "Reserved",                     "m3ua.concerned_reserved",                    FT_BYTES,  BASE_NONE, NULL,                                         0x0, NULL,				HFILL } },
    { &hf_concerned_dest_pc,                { "Concerned DPC",                "m3ua.concerned_dpc",                         FT_UINT24, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_local_rk_identifier,              { "Local routing key identifier", "m3ua.local_rk_identifier",                   FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_dpc_mask,                         { "Mask",                         "m3ua.dpc_mask",                              FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_dpc_pc,                           { "Destination point code",       "m3ua.dpc_pc",                                FT_UINT24, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_si,                               { "Service indicator",            "m3ua.si",                                    FT_UINT8,  BASE_DEC,  VALS(user_identity_values),                   0x0, NULL,				HFILL } },
    { &hf_ssn,                              { "Subsystem number",             "m3ua.ssn",                                   FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_opc_list_mask,                    { "Mask",                         "m3ua.opc_list_mask",                         FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_opc_list_pc,                      { "Originating point code",       "m3ua.opc_list_pc",                           FT_UINT24, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_cic_range_mask,                   { "Mask",                         "m3ua.cic_range_mask",                        FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_cic_range_pc,                     { "Originating point code",       "m3ua.cic_range_pc",                          FT_UINT24, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_cic_range_lower,                  { "Lower CIC value",              "m3ua.cic_range_lower",                       FT_UINT16, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_cic_range_upper,                  { "Upper CIC value",              "m3ua.cic_range_upper",                       FT_UINT16, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_li,                               { "Length indicator",             "m3ua.protocol_data_2_li",                    FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_protocol_data_opc,                { "OPC",                          "m3ua.protocol_data_opc",                     FT_UINT32, BASE_DEC,  NULL,                                         0x0, "Originating Point Code",		HFILL } },
    { &hf_protocol_data_dpc,                { "DPC",                          "m3ua.protocol_data_dpc",                     FT_UINT32, BASE_DEC,  NULL,                                         0x0, "Destination Point Code",		HFILL } },
    { &hf_protocol_data_mtp3_opc,           { "OPC",                          "mtp3.opc",                                   FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_protocol_data_mtp3_dpc,           { "DPC",                          "mtp3.dpc",                                   FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_protocol_data_mtp3_pc,            { "PC",                           "mtp3.pc",                                    FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_protocol_data_si,                 { "SI",                           "m3ua.protocol_data_si",                      FT_UINT8,  BASE_DEC,  VALS(mtp3_service_indicator_code_short_vals), 0x0, "Service Indicator",		HFILL } },
    { &hf_protocol_data_ni,                 { "NI",                           "m3ua.protocol_data_ni",                      FT_UINT8,  BASE_DEC,  NULL,                                         0x0, "Network Indicator",		HFILL } },
    { &hf_protocol_data_mtp3_ni,            { "NI",                           "mtp3.ni",                                    FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_protocol_data_mp,                 { "MP",                           "m3ua.protocol_data_mp",                      FT_UINT8,  BASE_DEC,  NULL,                                         0x0, "Message Priority",		HFILL } },
    { &hf_protocol_data_sls,                { "SLS",                          "m3ua.protocol_data_sls",                     FT_UINT8,  BASE_DEC,  NULL,                                         0x0, "Signalling Link Selection",	HFILL } },
    { &hf_protocol_data_mtp3_sls,           { "SLS",                          "mtp3.sls",                                   FT_UINT8,  BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_correlation_identifier,           { "Correlation Identifier",       "m3ua.correlation_identifier",                FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_registration_status,              { "Registration status",          "m3ua.registration_status",                   FT_UINT32, BASE_DEC,  VALS(registration_status_values),             0x0, NULL,				HFILL } },
    { &hf_deregistration_status,            { "Deregistration status",        "m3ua.deregistration_status",                 FT_UINT32, BASE_DEC,  VALS(deregistration_status_values),           0x0, NULL,				HFILL } },
    { &hf_registration_result_identifier,   { "Local RK-identifier value",    "m3ua.registration_result_identifier",        FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_registration_result_status,       { "Registration status",          "m3ua.registration_results_status",           FT_UINT32, BASE_DEC,  VALS(registration_result_status_values),      0x0, NULL,				HFILL } },
    { &hf_registration_result_context,      { "Routing context",              "m3ua.registration_result_routing_context",   FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
    { &hf_v6_deregistration_result_status,  { "De-Registration status",       "m3ua.deregistration_results_status",         FT_UINT32, BASE_DEC,  VALS(v6_deregistration_result_status_values), 0x0, NULL,				HFILL } },
    { &hf_v6_deregistration_result_context, { "Routing context",              "m3ua.deregistration_result_routing_context", FT_UINT32, BASE_DEC,  NULL,                                         0x0, NULL,				HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m3ua,
    &ett_parameter,
    &ett_mtp3_equiv,
    &ett_q708_opc,
    &ett_q708_dpc,
  };

  static enum_val_t options[] = {
    { "draft-5", "Internet Draft version 5",        M3UA_V5  },
    { "draft-6", "Internet Draft version 6",        M3UA_V6  },
    { "draft-7", "Internet Draft version 7",        M3UA_V7  },
    { "rfc3332", "RFC 3332",                        M3UA_RFC },
    { NULL, NULL, 0 }
  };

  /* Register the protocol name and description */
  proto_m3ua = proto_register_protocol("MTP 3 User Adaptation Layer", "M3UA",  "m3ua");
  register_dissector("m3ua", dissect_m3ua, proto_m3ua);

  m3ua_module = prefs_register_protocol(proto_m3ua, NULL);
  prefs_register_enum_preference(m3ua_module, "version", "M3UA Version", "Version used by Wireshark", &version, options, FALSE);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m3ua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  m3ua_tap = register_tap("m3ua");

}

void
proto_reg_handoff_m3ua(void)
{
  dissector_handle_t m3ua_handle;

  /*
   * Get a handle for the MTP3 dissector.
   */
  mtp3_handle = find_dissector("mtp3");
  data_handle = find_dissector("data");
  m3ua_handle = find_dissector("m3ua");
  dissector_add_uint("sctp.ppi",  M3UA_PAYLOAD_PROTOCOL_ID, m3ua_handle);
  dissector_add_uint("sctp.port", SCTP_PORT_M3UA, m3ua_handle);

  si_dissector_table = find_dissector_table("mtp3.service_indicator");
}
