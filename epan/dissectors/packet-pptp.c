/* packet-pptp.c
 * Routines for the Point-to-Point Tunnelling Protocol (PPTP) (RFC 2637)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * 10/2010 - Rework PPTP Dissector
 * Alexis La Goutte <alexis.lagoutte at gmail dot com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

static int proto_pptp = -1;
static int hf_pptp_length = -1;
static int hf_pptp_message_type = -1;
static int hf_pptp_magic_cookie = -1;
static int hf_pptp_control_message_type = -1;
static int hf_pptp_reserved = -1;
static int hf_pptp_protocol_version = -1;
static int hf_pptp_framing_capabilities = -1;
static int hf_pptp_bearer_capabilities = -1;
static int hf_pptp_maximum_channels = -1;
static int hf_pptp_firmware_revision = -1;
static int hf_pptp_host_name = -1;
static int hf_pptp_vendor_name = -1;
static int hf_pptp_control_result = -1;
static int hf_pptp_error = -1;
static int hf_pptp_reason = -1;
static int hf_pptp_stop_result = -1;
static int hf_pptp_identifier = -1;
static int hf_pptp_echo_result = -1;
static int hf_pptp_call_id = -1;
static int hf_pptp_call_serial_number = -1;
static int hf_pptp_minimum_bps = -1;
static int hf_pptp_maximum_bps = -1;
static int hf_pptp_bearer_type = -1;
static int hf_pptp_framing_type = -1;
static int hf_pptp_packet_receive_window_size = -1;
static int hf_pptp_packet_processing_delay = -1;
static int hf_pptp_phone_number_length = -1;
static int hf_pptp_phone_number = -1;
static int hf_pptp_subaddress = -1;
static int hf_pptp_peer_call_id = -1;
static int hf_pptp_out_result = -1;
static int hf_pptp_cause = -1;
static int hf_pptp_connect_speed = -1;
static int hf_pptp_physical_channel_id = -1;
static int hf_pptp_dialed_number_length = -1;
static int hf_pptp_dialed_number = -1;
static int hf_pptp_dialing_number_length = -1;
static int hf_pptp_dialing_number = -1;
static int hf_pptp_in_result = -1;
static int hf_pptp_disc_result = -1;
static int hf_pptp_call_statistics = -1;
static int hf_pptp_crc_errors = -1;
static int hf_pptp_framing_errors = -1;
static int hf_pptp_hardware_overruns = -1;
static int hf_pptp_buffer_overruns = -1;
static int hf_pptp_timeout_errors = -1;
static int hf_pptp_alignment_errors = -1;
static int hf_pptp_send_accm = -1;
static int hf_pptp_receive_accm = -1;

static gint ett_pptp = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_PPTP		1723

#define MAGIC_COOKIE		0x1A2B3C4D

#define CNTRL_REQ 	0x01
#define CNTRL_REPLY	0x02
#define STOP_REQ	0x03
#define STOP_REPLY	0x04
#define ECHO_REQ	0x05
#define ECHO_REPLY	0x06
#define OUT_REQ		0x07
#define OUT_REPLY	0x08
#define IN_REQ		0x09
#define IN_REPLY 	0x0A
#define IN_CONNECTED	0x0B
#define CLEAR_REQ	0x0C
#define DISC_NOTIFY	0x0D
#define ERROR_NOTIFY	0x0E
#define SET_LINK	0x0F

static const value_string control_message_type_vals[] = {
  { CNTRL_REQ,	  "Start-Control-Connection-Request" },
  { CNTRL_REPLY,  "Start-Control-Connection-Reply" },
  { STOP_REQ,	  "Stop-Control-Connection-Request" },
  { STOP_REPLY,	  "Stop-Control-Connection-Reply" },
  { ECHO_REQ,	  "Echo-Request" },
  { ECHO_REPLY,	  "Echo-Reply" },
  { OUT_REQ,	  "Outgoing-Call-Request" },
  { OUT_REPLY,	  "Outgoing-Call-Reply" },
  { IN_REQ,	  "Incoming-Call-Request" },
  { IN_REPLY,	  "Incoming-Call-Reply" },
  { IN_CONNECTED, "Incoming-Call-Connected" },
  { CLEAR_REQ,	  "Call-Clear-Request" },
  { DISC_NOTIFY,  "Call-Disconnect-Notify" },
  { ERROR_NOTIFY, "WAN-Error-Notify" },
  { SET_LINK,     "Set-Link-Info" },
  { 0,	NULL },
};
static const value_string msgtype_vals[] = {
  { 1, "Control Message" },
  { 2, "Management Message" },
  { 0, NULL }
};

static const value_string frametype_vals[] = {
  { 1, "Asynchronous Framing supported" },
  { 2, "Synchronous Framing supported"},
  { 3, "Either Framing supported" },
  { 0, NULL }
};

static const value_string bearertype_vals[] = {
  { 1, "Analog access supported" },
  { 2, "Digital access supported" },
  { 3, "Either access supported" },
  { 0, NULL }
};

static const value_string control_resulttype_vals[] = {
  { 1, "Successful channel establishment" },
  { 2, "General error" },
  { 3, "Command channel already exists" },
  { 4, "Requester not authorized" },
  { 5, "Protocol version not supported" },
  { 0, NULL }
};

static const value_string errortype_vals[] = {
  { 0, "None" },
  { 1, "Not-Connected" },
  { 2, "Bad-Format" },
  { 3, "Bad-Value" },
  { 4, "No-Resource" },
  { 5, "Bad-Call ID" },
  { 6, "PAC-Error" },
  { 0, NULL }
};

static const value_string reasontype_vals[] = {
  { 1, "None" },
  { 2, "Stop-Protocol" },
  { 3, "Stop-Local-Shutdown" },
  { 0, NULL }
};

static const value_string stop_resulttype_vals[] = {
  { 1, "OK" },
  { 2, "General error" },
  { 0, NULL }
};

static const value_string echo_resulttype_vals[] = {
  { 1, "OK" },
  { 2, "General error" },
  { 0, NULL }
};

static const value_string out_resulttype_vals[] = {
  { 1, "Connected" },
  { 2, "General Error" },
  { 3, "No Carrier" },
  { 4, "Busy" },
  { 5, "No Dial Tone" },
  { 6, "Time-out" },
  { 7, "Do Not Accept" },
  { 0, NULL }
};

static const value_string in_resulttype_vals[] = {
  { 1, "Connect" },
  { 2, "General error" },
  { 3, "Do Not Accept" },
  { 0, NULL }
};

static const value_string disc_resulttype_vals[] = {
  { 1, "Lost Carrier" },
  { 2, "General Error" },
  { 3, "Admin Shutdown" },
  { 4, "Request" },
  { 0, NULL }
};

static void
dissect_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
  call_dissector(data_handle,tvb_new_subset_remaining(tvb, offset), pinfo, tree);
}

static void
dissect_cntrl_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_uint_format(tree, hf_pptp_protocol_version, tvb, offset,
                               2, tvb_get_ntohs(tvb, offset), "Protocol version: %u.%u",
                               tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,             tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_framing_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_bearer_capabilities,  tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_maximum_channels,     tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_firmware_revision,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_host_name,            tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_pptp_vendor_name,          tvb, offset, 64, ENC_ASCII|ENC_NA);
}

static void
dissect_cntrl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_uint_format(tree, hf_pptp_protocol_version, tvb, offset,
                               2, tvb_get_ntohs(tvb, offset), "Protocol version: %u.%u",
                               tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_control_result,       tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,                tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_framing_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_bearer_capabilities,  tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_maximum_channels,     tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_firmware_revision,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_host_name,            tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_pptp_vendor_name,          tvb, offset, 64, ENC_ASCII|ENC_NA);

}

static void
dissect_stop_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_reason,   tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_reserved, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_reserved, tvb, offset, 2, ENC_NA);
}

static void
dissect_stop_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_stop_result, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,       tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_reserved,    tvb, offset, 2, ENC_NA);

}

static void
dissect_echo_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_echo_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_identifier,  tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_echo_result, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,       tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_reserved,    tvb, offset, 2, ENC_NA);
}

static void
dissect_out_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,	proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,                    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_call_serial_number,         tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_minimum_bps,                tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_maximum_bps,                tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_bearer_type,                tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_framing_type,               tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_packet_receive_window_size, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_packet_processing_delay,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_phone_number_length,        tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,                   tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_phone_number,               tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_pptp_subaddress,                 tvb, offset, 64, ENC_ASCII|ENC_NA);
}

static void
dissect_out_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,                    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_peer_call_id,               tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_out_result,                 tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_cause,                      tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_connect_speed,              tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_packet_receive_window_size, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_packet_processing_delay,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_physical_channel_id,        tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_in_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,               tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_call_serial_number,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_bearer_type,           tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_physical_channel_id,   tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_dialed_number_length,  tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_dialing_number_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_dialed_number,         tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_pptp_dialing_number,        tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_pptp_subaddress,            tvb, offset, 64, ENC_ASCII|ENC_NA);
}

static void
dissect_in_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,                    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_peer_call_id,               tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_in_result,                  tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_packet_receive_window_size, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_packet_processing_delay,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,                   tvb, offset, 2, ENC_NA);
}

static void
dissect_in_connected(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_peer_call_id,               tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,                   tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_connect_speed,              tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_packet_receive_window_size, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_packet_processing_delay,    tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_framing_type,               tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_clear_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,  tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved, tvb, offset, 2, ENC_NA);
}

static void
dissect_disc_notify(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_call_id,         tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_disc_result,     tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_error,           tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_pptp_cause,           tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,        tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_call_statistics, tvb, offset, 64, ENC_ASCII|ENC_NA);
}

static void
dissect_error_notify(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
    return;

  proto_tree_add_item(tree, hf_pptp_peer_call_id,      tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,          tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_crc_errors,        tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_framing_errors,    tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_hardware_overruns, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_buffer_overruns,   tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_timeout_errors,    tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_alignment_errors,  tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_set_link(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
  if (!tree)
      return;

  proto_tree_add_item(tree, hf_pptp_peer_call_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_reserved,     tvb, offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_pptp_send_accm,    tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_pptp_receive_accm, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_pptp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *pptp_tree = NULL;
  proto_item *item      = NULL;
  int	      offset    = 0;
  guint16     len;
  guint16     control_message_type;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPTP");
  col_clear(pinfo->cinfo, COL_INFO);

  len	     = tvb_get_ntohs(tvb, offset);
  control_message_type = tvb_get_ntohs(tvb, offset + 8);

  col_add_str(pinfo->cinfo, COL_INFO,
	      val_to_str(control_message_type, control_message_type_vals,
			 "Unknown control type (%d)"));

  if (tree) {
    proto_item *ti;

    ti = proto_tree_add_item(tree, proto_pptp, tvb, offset, len, ENC_NA);
    pptp_tree = proto_item_add_subtree(ti, ett_pptp);

    proto_tree_add_item(pptp_tree, hf_pptp_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(pptp_tree, hf_pptp_message_type, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    item = proto_tree_add_item(pptp_tree, hf_pptp_magic_cookie, tvb, offset+4, 4, ENC_BIG_ENDIAN);
  }

  if (tvb_get_ntohl(tvb, offset+4) == MAGIC_COOKIE)
    proto_item_append_text(item," (correct)");
  else {
    proto_item_append_text(item," (incorrect)");
    expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Incorrect Magic Cookie");
  }

  if (tree) {
    proto_tree_add_item(pptp_tree, hf_pptp_control_message_type, tvb, offset+8, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(pptp_tree, hf_pptp_reserved, tvb, offset+10, 2, ENC_NA);
  }

  offset += offset + 12;

  switch(control_message_type){
    case CNTRL_REQ: /* Start-Control-Connection-Request */
      dissect_cntrl_req(tvb, offset, pinfo, pptp_tree);
      break;
    case CNTRL_REPLY: /* Start-Control-Connection-Reply */
      dissect_cntrl_reply(tvb, offset, pinfo, pptp_tree);
      break;
    case STOP_REQ: /* Stop-Control-Connection-Request */
      dissect_stop_req(tvb, offset, pinfo, pptp_tree);
      break;
    case STOP_REPLY: /* Stop-Control-Connection-Reply */
      dissect_stop_reply(tvb, offset, pinfo, pptp_tree);
      break;
    case ECHO_REQ: /* Echo-Request */
      dissect_echo_req(tvb, offset, pinfo, pptp_tree);
      break;
    case ECHO_REPLY: /* Echo-Reply */
      dissect_echo_reply(tvb, offset, pinfo, pptp_tree);
      break;
    case OUT_REQ: /* Outgoing-Call-Request */
      dissect_out_req(tvb, offset, pinfo, pptp_tree);
      break;
    case OUT_REPLY: /* Outgoing-Call-Reply */
      dissect_out_reply(tvb, offset, pinfo, pptp_tree);
      break;
    case IN_REQ: /* Incoming-Call-Request */
      dissect_in_req(tvb, offset, pinfo, pptp_tree);
      break;
    case IN_REPLY: /* Incoming-Call-Reply */
      dissect_in_reply(tvb, offset, pinfo, pptp_tree);
      break;
    case IN_CONNECTED: /* Incoming-Call-Connected */
      dissect_in_connected(tvb, offset, pinfo, pptp_tree);
      break;
    case CLEAR_REQ: /* Call-Clear-Request */
      dissect_clear_req(tvb, offset, pinfo, pptp_tree);
      break;
    case DISC_NOTIFY: /* Call-Disconnect-Notify */
      dissect_disc_notify(tvb, offset, pinfo, pptp_tree);
      break;
    case ERROR_NOTIFY: /* WAN-Error-Notify */
      dissect_error_notify(tvb, offset, pinfo, pptp_tree);
      break;
    case SET_LINK: /* Set-Link-Info */
      dissect_set_link(tvb, offset, pinfo, pptp_tree);
      break;
    default: /* Unknown Type... */
      dissect_unknown(tvb, offset, pinfo, pptp_tree);
      break;
  }
}

void
proto_register_pptp(void)
{
  static gint *ett[] = {
    &ett_pptp,
  };

  static hf_register_info hf[] = {
    { &hf_pptp_length,
      { "Length", "pptp.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Total length in octets of this PPTP message", HFILL }
    },
    { &hf_pptp_message_type,
      { "Message type", "pptp.type",
        FT_UINT16, BASE_DEC, VALS(msgtype_vals), 0x0,
        "PPTP message type", HFILL }
    },
    { &hf_pptp_magic_cookie,
      { "Magic Cookie", "pptp.magic_cookie",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "This constant value is used as a sanity check on received messages", HFILL }
    },
    { &hf_pptp_control_message_type,
      { "Control Message Type", "pptp.control_message_type",
        FT_UINT16, BASE_DEC, VALS(control_message_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pptp_reserved,
      { "Reserved", "pptp.reserved",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "This field MUST be 0", HFILL }
    },
    { &hf_pptp_protocol_version,
      { "Protocol version", "pptp.protocol_version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "The version of the PPTP protocol", HFILL }
    },
    { &hf_pptp_framing_capabilities,
      { "Framing Capabilities", "pptp.framing_capabilities",
        FT_UINT32, BASE_DEC, VALS(frametype_vals), 0x0,
        "A set of bits indicating the type of framing", HFILL }
    },
    { &hf_pptp_bearer_capabilities,
      { "Bearer Capabilities", "pptp.bearer_capabilities",
        FT_UINT32, BASE_DEC, VALS(bearertype_vals), 0x0,
        "A set of bits indicating the type of bearer", HFILL }
    },
    { &hf_pptp_maximum_channels,
      { "Maximum Channels", "pptp.maximum_channels",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "The total number of individual PPP sessions this PAC can support", HFILL }
    },
    { &hf_pptp_firmware_revision,
      { "Firmware Revision", "pptp.firmware_revision",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "This field contains the firmware revision", HFILL }
    },
    { &hf_pptp_host_name,
      { "Host Name", "pptp.host_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "A 64 octet field containing the DNS name", HFILL }
    },
    { &hf_pptp_vendor_name,
      { "Vendor Name", "pptp.vendor_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "A 64 octet field containing a vendor", HFILL }
    },
    { &hf_pptp_control_result,
      { "Result Code", "pptp.control_result",
        FT_UINT8, BASE_DEC, VALS(control_resulttype_vals), 0x0,
        "Indicates the result of the command channel establishment attempt", HFILL }
    },
    { &hf_pptp_error,
      { "Error Code", "pptp.error",
        FT_UINT8, BASE_DEC, VALS(errortype_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pptp_reason,
      { "Reason", "pptp.reason",
        FT_UINT8, BASE_DEC, VALS(reasontype_vals), 0x0,
        "Indicates the reason for the control connection being close", HFILL }
    },
    { &hf_pptp_stop_result,
      { "Result Code", "pptp.stop_result",
        FT_UINT8, BASE_DEC, VALS(stop_resulttype_vals), 0x0,
        "Indicates the result of the attempt to close the control connection", HFILL }
    },
    { &hf_pptp_identifier,
      { "Identifier", "pptp.identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pptp_echo_result,
      { "Result Code", "pptp.echo_result",
        FT_UINT8, BASE_DEC, VALS(echo_resulttype_vals), 0x0,
        "Indicates the result of the receipt of the Echo-Request", HFILL }
    },
    { &hf_pptp_call_id,
      { "Call ID", "pptp.call_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "A unique identifier, unique to a particular PAC-PNS pair assigned by the PNS", HFILL }
    },
    { &hf_pptp_call_serial_number,
      { "Call Serial Number", "pptp.call_serial_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "An identifier assigned by the PNS to this session for the purpose of identifying this particular session in logged session information", HFILL }
    },
   { &hf_pptp_minimum_bps,
     { "Minimum BPS", "pptp.minimum_bps",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       "The lowest acceptable line speed (in bits/second) for this session", HFILL }
   },
   { &hf_pptp_maximum_bps,
     { "Maximum BPS", "pptp.maximum_bps",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       "The highest acceptable line speed (in bits/second) for this session", HFILL }
   },
    { &hf_pptp_framing_type,
      { "Framing Type", "pptp.framing_type",
        FT_UINT32, BASE_DEC, VALS(frametype_vals), 0x0,
        "A value indicating the type of PPP framing to be used for this outgoing call", HFILL }
    },
    { &hf_pptp_bearer_type,
      { "Bearer Type", "pptp.bearer_type",
        FT_UINT32, BASE_DEC, VALS(bearertype_vals), 0x0,
        "A value indicating the bearer capability required for this outgoing call", HFILL }
    },
    { &hf_pptp_packet_receive_window_size,
      { "Packet Receive Window Size", "pptp.packet_receive_window_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "A unique identifier, unique to a particular PAC-PNS pair assigned by the PNS", HFILL }
    },
    { &hf_pptp_packet_processing_delay,
      { "Packet Processing Delay", "pptp.packet_processing_delay",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "A measure of the packet processing delay that might be imposed on data sent to the PNS from the PAC", HFILL }
    },
    { &hf_pptp_phone_number_length,
      { "Phone Number Length", "pptp.phone_number_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "The actual number of valid digits in the Phone Number field", HFILL }
    },
    { &hf_pptp_phone_number,
      { "Phone Number", "pptp.phone_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The number to be dialed to establish the outgoing session", HFILL }
    },
    { &hf_pptp_subaddress,
      { "Subaddress", "pptp.subaddress",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "A 64 octet field used to specify additional dialing information.", HFILL }
    },
    { &hf_pptp_peer_call_id,
      { "Peer Call ID", "pptp.peer_call_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "This field is set to the value received in the Call ID field of the corresponding Outgoing-Call-Request message", HFILL }
    },
    { &hf_pptp_out_result,
      { "Result Code", "pptp.out_result",
        FT_UINT8, BASE_DEC, VALS(out_resulttype_vals), 0x0,
        "Indicates the result of the receipt of the Outgoing-Call-Request attempt", HFILL }
    },
    { &hf_pptp_cause,
      { "Cause Code", "pptp.cause",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "This field gives additional information", HFILL }
    },
    { &hf_pptp_connect_speed,
      { "Connect Speed", "pptp.connect_speed",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The actual connection speed used, in bits/second.", HFILL }
    },
    { &hf_pptp_physical_channel_id,
      { "Physical Channel ID", "pptp.physical_channel_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "This field is set by the PAC in a vendor-specific manner to the physical channel number used to place this call", HFILL }
    },
    { &hf_pptp_dialed_number_length,
      { "Dialed Number Length", "pptp.dialed_number_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "The actual number of valid digits in the Dialed Number field", HFILL }
    },
    { &hf_pptp_dialed_number,
      { "Dialed Number", "pptp.dialed_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The number that was dialed by the caller", HFILL }
    },

    { &hf_pptp_dialing_number_length,
      { "Dialing Number Length", "pptp.dialing_number_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "The actual number of valid digits in the Dialing Number field", HFILL }
    },
    { &hf_pptp_dialing_number,
      { "Dialing Number", "pptp.dialing_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The number from which the call was placed", HFILL }
    },
    { &hf_pptp_in_result,
      { "Result Code", "pptp.in_result",
        FT_UINT8, BASE_DEC, VALS(in_resulttype_vals), 0x0,
        "This value indicates the result of the Incoming-Call-Request attempt", HFILL }
    },
    { &hf_pptp_disc_result,
      { "Result Code", "pptp.disc_result",
        FT_UINT8, BASE_DEC, VALS(disc_resulttype_vals), 0x0,
        "This value indicates the reason for the disconnect", HFILL }
    },
    { &hf_pptp_call_statistics,
      { "Call Statistics", "pptp.call_Statistics",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "This field is an ASCII string containing vendor-specific call statistics that can be logged for diagnostic purpose", HFILL }
    },
    { &hf_pptp_crc_errors,
      { "CRC Errors", "pptp.crc_errors",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of PPP frames received with CRC errors since session was established", HFILL }
    },
    { &hf_pptp_framing_errors,
      { "Framing Errors", "pptp.framing_errors",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of improperly framed PPP packets received", HFILL }
    },
    { &hf_pptp_hardware_overruns,
      { "Hardware overruns", "pptp.hardware_overruns",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of receive buffer over-runs since session was established", HFILL }
    },
    { &hf_pptp_buffer_overruns,
      { "Buffer overruns", "pptp.buffer_overruns",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of buffer over-runs detected since session was established", HFILL }
    },
    { &hf_pptp_timeout_errors,
      { "Time-out Errors", "pptp.timeout_errors",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of time-outs since call was established", HFILL }
    },
    { &hf_pptp_alignment_errors,
      { "Alignment Errors", "pptp.alignment_errors",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Alignment errors since call was established", HFILL }
    },
    { &hf_pptp_send_accm,
      { "Send ACCM", "pptp.send_accm",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "The send ACCM value the client should use to process outgoing PPP packets", HFILL }
    },
    { &hf_pptp_receive_accm,
      { "Receive ACCM", "pptp.receive_accm",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "The Receive ACCM value the client should use to process incoming PPP packets", HFILL }
    },
  };

  proto_pptp = proto_register_protocol("Point-to-Point Tunnelling Protocol",
				       "PPTP", "pptp");
  proto_register_field_array(proto_pptp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pptp(void)
{
  dissector_handle_t pptp_handle;

  pptp_handle = create_dissector_handle(dissect_pptp, proto_pptp);
  dissector_add_uint("tcp.port", TCP_PORT_PPTP, pptp_handle);
  data_handle = find_dissector("data");
}
