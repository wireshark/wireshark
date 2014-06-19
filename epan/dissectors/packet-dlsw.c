/* packet-dlsw.c
 * Routines for DLSw packet dissection (Data Link Switching)
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
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

/* DLSw dissector ( RFC 1434, RFC 1795, RFC 2166) */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>

#include "packet-tcp.h"

void proto_register_dlsw(void);
void proto_reg_handoff_dlsw(void);

static int proto_dlsw = -1;
static int hf_dlsw_flow_control_indication = -1;
static int hf_dlsw_flow_control_ack = -1;
static int hf_dlsw_flow_control_operator = -1;
static int hf_dlsw_flags_explorer_msg = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_dlsw_vector_length = -1;
static int hf_dlsw_dlc_header_sa = -1;
static int hf_dlsw_dlc_header_fc_byte = -1;
static int hf_dlsw_target_transport_id = -1;
static int hf_dlsw_error_pointer = -1;
static int hf_dlsw_capabilities_length = -1;
static int hf_dlsw_multicast_version_number = -1;
static int hf_dlsw_frame_direction = -1;
static int hf_dlsw_circuit_priority = -1;
static int hf_dlsw_origin_dlc_port_id = -1;
static int hf_dlsw_protocol_id = -1;
static int hf_dlsw_mac_address_list = -1;
static int hf_dlsw_origin_link_sap = -1;
static int hf_dlsw_header_length = -1;
static int hf_dlsw_dlc_header_ctrl = -1;
static int hf_dlsw_target_dlc_port_id = -1;
static int hf_dlsw_vector_type = -1;
static int hf_dlsw_largest_frame_size = -1;
static int hf_dlsw_error_cause = -1;
static int hf_dlsw_dlc_header_length = -1;
static int hf_dlsw_oui = -1;
static int hf_dlsw_target_dlc = -1;
static int hf_dlsw_dlc_header_ac_byte = -1;
static int hf_dlsw_tcp_connections = -1;
static int hf_dlsw_initial_pacing_window = -1;
static int hf_dlsw_old_message_type = -1;
static int hf_dlsw_capex_type = -1;
static int hf_dlsw_ssp_flags = -1;
static int hf_dlsw_target_mac_address = -1;
static int hf_dlsw_origin_mac_address = -1;
static int hf_dlsw_dlc_header_rif = -1;
static int hf_dlsw_message_type = -1;
static int hf_dlsw_header_number = -1;
static int hf_dlsw_message_length = -1;
static int hf_dlsw_remote_dlc_pid = -1;
static int hf_dlsw_vendor_oui = -1;
static int hf_dlsw_flow_ctrl_byte = -1;
static int hf_dlsw_version_string = -1;
static int hf_dlsw_version = -1;
static int hf_dlsw_remote_dlc = -1;
static int hf_dlsw_origin_dlc = -1;
static int hf_dlsw_origin_transport_id = -1;
static int hf_dlsw_dlc_header_ssap = -1;
static int hf_dlsw_target_link_sap = -1;
static int hf_dlsw_dlc_header_da = -1;
static int hf_dlsw_netbios_name = -1;
static int hf_dlsw_dlc_header_dsap = -1;

static gint ett_dlsw = -1;
static gint ett_dlsw_header = -1;
static gint ett_dlsw_fc = -1;
static gint ett_dlsw_sspflags = -1;
static gint ett_dlsw_data = -1;
static gint ett_dlsw_vector = -1;

static expert_field ei_dlsw_dlc_header_length = EI_INIT;

#define  CANUREACH               0x03
#define  ICANREACH               0x04
#define  REACH_ACK               0x05
#define  DGRMFRAME               0x06
#define  XIDFRAME                0x07
#define  CONTACT                 0x08
#define  CONTACTED               0x09
#define  RESTART_DL              0x10
#define  DL_RESTARTED            0x11
#define  ENTER_BUSY              0x0C
#define  EXIT_BUSY               0x0D
#define  INFOFRAME               0x0A
#define  HALT_DL                 0x0E
#define  DL_HALTED               0x0F
#define  NETBIOS_NQ              0x12
#define  NETBIOS_NR              0x13
#define  DATAFRAME               0x14
#define  HALT_DL_NOACK           0x19
#define  NETBIOS_ANQ             0x1A
#define  NETBIOS_ANR             0x1B
#define  KEEPALIVE               0x1D
#define  CAP_EXCHANGE            0x20
#define  IFCM                    0x21
#define  TEST_CIRCUIT_REQ        0x7A
#define  TEST_CIRCUIT_RSP        0x7B

static const value_string dlsw_type_vals[] = {
  { CANUREACH        , "Can U Reach Station-circuit start" },
  { ICANREACH        , "I Can Reach Station-circuit start" },
  { REACH_ACK        , "Reach Acknowledgment" },
  { DGRMFRAME        , "Datagram Frame" },
  { XIDFRAME         , "XID Frame" },
  { CONTACT          , "Contact Remote Station" },
  { CONTACTED        , "Remote Station Contacted" },
  { RESTART_DL       , "Restart Data Link" },
  { DL_RESTARTED     , "Data Link Restarted" },
  { ENTER_BUSY       , "Enter Busy" },
  { EXIT_BUSY        , "Exit Busy" },
  { INFOFRAME        , "Information (I) Frame" },
  { HALT_DL          , "Halt Data Link" },
  { DL_HALTED        , "Data Link Halted" },
  { NETBIOS_NQ       , "NETBIOS Name Query-circuit setup" },
  { NETBIOS_NR       , "NETBIOS Name Recog-circuit setup" },
  { DATAFRAME        , "Data Frame" },
  { HALT_DL_NOACK    , "Halt Data Link with no Ack" },
  { NETBIOS_ANQ      , "NETBIOS Add Name Query" },
  { NETBIOS_ANR      , "NETBIOS Add Name Response" },
  { KEEPALIVE        , "Transport Keepalive Message" },
  { CAP_EXCHANGE     , "Capabilities Exchange" },
  { IFCM             , "Independent Flow Control Message" },
  { TEST_CIRCUIT_REQ , "Test Circuit Request" },
  { TEST_CIRCUIT_RSP , "Test Circuit Response" },
  { 0 , NULL }
};
static const value_string dlsw_version_vals[] = {
  { 0x31        , "Version 1 (RFC 1795)" },
  { 0x32        , "Version 2 (RFC 2166)" },
  { 0x33        , "Vendor Specific" },
  { 0x34        , "Vendor Specific" },
  { 0x35        , "Vendor Specific" },
  { 0x36        , "Vendor Specific" },
  { 0x37        , "Vendor Specific" },
  { 0x38        , "Vendor Specific" },
  { 0x39        , "Vendor Specific" },
  { 0x3A        , "Vendor Specific" },
  { 0x3B        , "Vendor Specific" },
  { 0x3C        , "Vendor Specific" },
  { 0x3D        , "Vendor Specific" },
  { 0x3E        , "Vendor Specific" },
  { 0x3F        , "Vendor Specific" },
  { 0x4B        , "Pre 1 (RFC 1434)" },
  { 0x00        , NULL }
};

static const value_string dlsw_fc_cmd_vals[] = {
  { 0x00        , "Repeat Window" },
  { 0x01        , "Increment Window" },
  { 0x02        , "Decrement Window" },
  { 0x03        , "Reset Window" },
  { 0x04        , "Halve Window" },
  { 0x00        , NULL }
};

static const value_string dlsw_capex_type_vals[] = {
  { 0x01        , "Capabilities request" },
  { 0x02        , "Capabilities response" },
  { 0x00        , NULL }
};

static const value_string dlsw_frame_direction_vals[] = {
  { 0x01        , "Origin DLSw to target DLSw" },
  { 0x02        , "Target DLSw to origin DLSw" },
  { 0x00        , NULL }
};

static const value_string dlsw_vector_vals[] = {
  { 0x81        , "Vendor ID Control Vector" },
  { 0x82        , "DLSw Version Control Vector" },
  { 0x83        , "Initial Pacing Window Control Vector" },
  { 0x84        , "Version String Control Vector" },
  { 0x85        , "Mac Address Exclusivity Control Vector" },
  { 0x86        , "Supported SAP List Control Vector" },
  { 0x87        , "TCP Connections Control Vector" },
  { 0x88        , "NetBIOS Name Exclusivity Control Vector" },
  { 0x89        , "MAC Address List Control Vector" },
  { 0x8a        , "NetBIOS Name List Control Vector" },
  { 0x8b        , "Vendor Context Control Vector" },
  { 0x8c        , "Multicast Capabilities Control Vector" },
  { 0x8d        , "Reserved for future use" },
  { 0x8e        , "Reserved for future use" },
  { 0x8f        , "Reserved for future use" },
  { 0x90        , "Reserved for future use" },
  { 0x91        , " Control Vector" },
  { 0x92        , " Control Vector" },
  { 0x93        , " Control Vector" },
  { 0x94        , " Control Vector" },
  { 0x95        , " Control Vector" },
  { 0x96        , " Control Vector" },
  { 0x00        , NULL }
};

static const value_string dlsw_pri_vals[] = {
  { 0        , "Unsupported" },
  { 1        , "Low Priority" },
  { 2        , "Medium Priority" },
  { 3        , "High Priority" },
  { 4        , "Highest Priority" },
  { 5        , "Reserved" },
  { 6        , "Reserved" },
  { 7        , "Reserved" },
  { 0, NULL }
};




#define DLSW_GDSID_SEND         0x1520
#define DLSW_GDSID_ACK          0x1521
#define DLSW_GDSID_REF          0x1522

static const value_string dlsw_gds_vals[] = {
  { DLSW_GDSID_SEND , "Request Capabilities GDS" },
  { DLSW_GDSID_ACK  , "Response Capabilities GDS" },
  { DLSW_GDSID_REF  , "Refuse Capabilities GDS" },
  { 0               , NULL }
};

static const value_string dlsw_refuse_vals[] = {
  { 0x1 , "invalid GDS length for a DLWs Capabilities Exchange Request"},
  { 0x2 , "invalid GDS id for a DLSw Capabilities Exchange Request"},
  { 0x3 , "vendor Id control vector is missing"},
  { 0x4 , "DLSw Version control vector is missing"},
  { 0x5 , "initial Pacing Window control vector is missing"},
  { 0x6 , "length of control vectors doesn't correlate to the length of the GDS variable"},
  { 0x7 , "invalid control vector id"},
  { 0x8 , "length of control vector invalid"},
  { 0x9 , "invalid control vector data value"},
  { 0xa , "duplicate control vector"},
  { 0xb , "out-of-sequence control vector"},
  { 0xc , "DLSw Supported SAP List control vector is missing"},
  { 0xd , "inconsistent DLSw Version, Multicast Capabilities, and TCP Connections CV received on the inbound Capabilities exchange"},
  { 0x0 , NULL }
};

#define UDP_PORT_DLSW           2067
#define TCP_PORT_DLSW           2065
#define DLSW_INFO_HEADER          16
#define DLSW_CMD_HEADER           72

static void
dissect_dlsw_capex(tvbuff_t *tvb, proto_tree *tree, proto_tree *ti);

static int
dissect_dlsw_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint version,hlen = 0,mlen = 0,mtype,dlchlen = 0,flags;
  proto_tree      *dlsw_tree = NULL, *dlsw_header_tree = NULL;
  proto_item      *ti,*ti2;
  proto_tree      *dlsw_flags_tree,*dlsw_data_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLSw");

  version=tvb_get_guint8(tvb,0);

  col_add_fstr(pinfo->cinfo, COL_INFO, "DLSw %s",val_to_str_const(version , dlsw_version_vals, "Unknown Version"));

  if (tree)
  {
    ti = proto_tree_add_item(tree, proto_dlsw, tvb, 0, -1, ENC_NA);
    dlsw_tree = proto_item_add_subtree(ti, ett_dlsw);

    hlen=tvb_get_guint8(tvb,1);

    ti2 = proto_tree_add_text (dlsw_tree, tvb, 0, hlen,"DLSw header, %s",
                               val_to_str_const(version , dlsw_version_vals, "Unknown Version"));
    dlsw_header_tree = proto_item_add_subtree(ti2, ett_dlsw_header);

    proto_tree_add_item(dlsw_header_tree, hf_dlsw_version, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(dlsw_header_tree, hf_dlsw_header_length, tvb, 1, 1, ENC_NA);
    mlen=tvb_get_ntohs(tvb,2);
    proto_tree_add_item(dlsw_header_tree, hf_dlsw_message_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dlsw_header_tree, hf_dlsw_remote_dlc, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(dlsw_header_tree, hf_dlsw_remote_dlc_pid, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_text (dlsw_header_tree,tvb,12,2,"Reserved") ;
  } ;

  mtype=tvb_get_guint8(tvb,14);
  col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",val_to_str_const(mtype , dlsw_type_vals, "Unknown message Type"));
  if (tree)
  {
    proto_tree_add_item(dlsw_header_tree, hf_dlsw_message_type, tvb, 14, 1, ENC_NA);
    if (mtype==CAP_EXCHANGE)
    {
      proto_tree_add_text (dlsw_header_tree,tvb, 15,1,"Not used for CapEx") ;
    }
    else
    {
      flags = tvb_get_guint8(tvb,15);
      ti2 = proto_tree_add_item(dlsw_header_tree, hf_dlsw_flow_ctrl_byte, tvb, 15, 1, ENC_NA);
      dlsw_flags_tree = proto_item_add_subtree(ti2, ett_dlsw_fc);
      proto_tree_add_item(dlsw_flags_tree, hf_dlsw_flow_control_indication, tvb, 15, 1, ENC_BIG_ENDIAN);
      if (flags & 0x80)
      {
        proto_tree_add_item(dlsw_flags_tree, hf_dlsw_flow_control_ack, tvb, 15, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_flags_tree, hf_dlsw_flow_control_operator, tvb, 15, 1, ENC_BIG_ENDIAN);
      }
    }
    if (hlen != DLSW_INFO_HEADER)
    {
      if (mtype==CAP_EXCHANGE)
      {
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_protocol_id, tvb, 16, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_header_number, tvb, 17, 1, ENC_NA);
        proto_tree_add_text (dlsw_header_tree,tvb, 18,5,"Not used for CapEx") ;
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_old_message_type, tvb, 23, 1, ENC_NA);
        proto_tree_add_text (dlsw_header_tree,tvb, 24,14,"Not used for CapEx") ;
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_capex_type, tvb, 38, 1, ENC_NA);
        proto_tree_add_text (dlsw_header_tree,tvb, 39,33,"Not used for CapEx") ;
      }
      else
      {
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_protocol_id, tvb, 16, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_header_number, tvb, 17, 1, ENC_NA);
        proto_tree_add_text (dlsw_header_tree,tvb, 18,2,"Reserved") ;
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_largest_frame_size, tvb, 20, 1, ENC_NA);
        ti2 = proto_tree_add_item(dlsw_header_tree, hf_dlsw_ssp_flags, tvb, 21, 1, ENC_NA);
        dlsw_flags_tree = proto_item_add_subtree(ti2, ett_dlsw_sspflags);
        proto_tree_add_item (dlsw_flags_tree, hf_dlsw_flags_explorer_msg, tvb, 21, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_circuit_priority, tvb, 22, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_old_message_type, tvb, 23, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_target_mac_address, tvb, 24, 6, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_origin_mac_address, tvb, 30, 6, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_origin_link_sap, tvb, 36, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_target_link_sap, tvb, 37, 1, ENC_NA);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_frame_direction, tvb, 38, 1, ENC_NA);
        proto_tree_add_text (dlsw_header_tree,tvb, 39,3,"Reserved") ;
        dlchlen=tvb_get_ntohs(tvb,42);
        ti = proto_tree_add_item(dlsw_header_tree, hf_dlsw_dlc_header_length, tvb, 42, 2, ENC_BIG_ENDIAN);
        if ( dlchlen > mlen )
        {
          expert_add_info_format(pinfo, ti, &ei_dlsw_dlc_header_length,
              "DLC Header Length = %u (bogus, must be <= message length %u)",dlchlen, mlen) ;
          return 44;
        }
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_origin_dlc_port_id, tvb, 44, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_origin_dlc, tvb, 48, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_origin_transport_id, tvb, 52, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_target_dlc_port_id, tvb, 56, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_target_dlc, tvb, 60, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dlsw_header_tree, hf_dlsw_target_transport_id, tvb, 64, 4, ENC_BIG_ENDIAN);
        proto_tree_add_text (dlsw_header_tree,tvb, 68,4,"Reserved") ;
      }
    }

/* end of header dissector */

    ti2 = proto_tree_add_text (dlsw_tree, tvb, hlen, mlen,"DLSw data");
    dlsw_data_tree = proto_item_add_subtree(ti2, ett_dlsw_data);

    switch (mtype)
    {
      case CAP_EXCHANGE:
        dissect_dlsw_capex(tvb_new_subset(tvb, hlen, mlen, -1), dlsw_data_tree,ti2);
        break;
      case IFCM:
      case INFOFRAME:
      case KEEPALIVE:
        proto_tree_add_text (dlsw_data_tree,tvb,hlen,mlen,"Data") ;
        break;

      default:
        if (dlchlen!=0)
        {
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_ac_byte, tvb, hlen, 1, ENC_NA);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_fc_byte, tvb, hlen+1, 1, ENC_NA);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_da, tvb, hlen+2, 6, ENC_NA|ENC_ASCII);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_sa, tvb, hlen+8, 6, ENC_NA|ENC_ASCII);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_rif, tvb, hlen+14, 18, ENC_NA|ENC_ASCII);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_dsap, tvb, hlen+32, 1, ENC_NA);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_ssap, tvb, hlen+33, 1, ENC_NA);
          proto_tree_add_item(dlsw_data_tree, hf_dlsw_dlc_header_ctrl, tvb, hlen+34, 1, ENC_NA);
        }
        proto_tree_add_text (dlsw_data_tree,tvb,hlen+dlchlen,mlen-dlchlen,"Data") ;
    }

  }

  return tvb_length(tvb);
}

static void
dissect_dlsw_capex(tvbuff_t *tvb, proto_tree *tree, proto_tree *ti2)
{
  int mlen,vlen,vtype,offset=4,gdsid,sap,i=0;
  proto_tree *ti,*dlsw_vector_tree;
  mlen=tvb_get_ntohs(tvb,0);
  gdsid=tvb_get_ntohs(tvb,2);
  proto_tree_add_item(tree, hf_dlsw_capabilities_length, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_text (tree,tvb,2,2,"%s",val_to_str_const( gdsid, dlsw_gds_vals, "Invalid GDS ID"));
  proto_item_append_text(ti2," - %s",val_to_str_const( gdsid, dlsw_gds_vals, "Invalid GDS ID"));
  switch (gdsid) {
    case DLSW_GDSID_ACK:
      break;
    case DLSW_GDSID_REF:
      proto_tree_add_item(tree, hf_dlsw_error_pointer, tvb, 4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_dlsw_error_cause, tvb, 6, 2, ENC_BIG_ENDIAN);
      break;
    case DLSW_GDSID_SEND:
      while (offset < mlen){
        vlen=tvb_get_guint8(tvb,offset);
        if (vlen < 3) THROW(ReportedBoundsError);
        vtype=tvb_get_guint8(tvb,offset+1);
        ti=proto_tree_add_text (tree,tvb,offset,vlen,"%s",
                                val_to_str_const(vtype,dlsw_vector_vals,"Unknown vector type"));
        dlsw_vector_tree = proto_item_add_subtree(ti, ett_dlsw_vector);
        proto_tree_add_item(dlsw_vector_tree, hf_dlsw_vector_length, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(dlsw_vector_tree, hf_dlsw_vector_type, tvb, offset+1, 1, ENC_NA);
        switch (vtype){
          case 0x81:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_oui, tvb, offset+2, vlen-2, ENC_BIG_ENDIAN);
            break;
          case 0x82:
            proto_tree_add_text (dlsw_vector_tree,tvb,offset+2,vlen-2,
                                 "DLSw Version = %d.%d",tvb_get_guint8(tvb,offset+2),tvb_get_guint8(tvb,offset+3));
            break;
          case 0x83:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_initial_pacing_window, tvb, offset+2, vlen-2, ENC_BIG_ENDIAN);
            break;
          case 0x84:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_version_string, tvb, offset+2, vlen-2, ENC_NA|ENC_ASCII);
            break;
          case 0x85:
            proto_tree_add_text (dlsw_vector_tree,tvb,offset+2,vlen-2,
                                 "MAC Address Exclusivity = %s",tvb_get_guint8(tvb,offset+2)==1?"On":"Off");
            break;
          case 0x86:
            while (i<vlen-2)
            {
              sap=tvb_get_guint8(tvb,offset+2+i);
              proto_tree_add_text (dlsw_vector_tree,tvb,offset+2+i,1,
                                   "SAP List Support = 0x%x0=%s 0x%x2=%s 0x%x4=%s 0x%x6=%s 0x%x8=%s 0x%xa=%s 0x%xc=%s 0x%xe=%s",
                                   i,sap&0x80?"on ":"off",i,sap&0x40?"on ":"off",i,sap&0x20?"on ":"off",i,sap&0x10?"on ":"off",
                                   i,sap&0x08?"on ":"off",i,sap&0x04?"on ":"off",i,sap&0x02?"on ":"off",i,sap&0x01?"on ":"off");
              i++;
            }
            break;
          case 0x87:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_tcp_connections, tvb, offset+2, vlen-2, ENC_NA);
            break;
          case 0x88:
            proto_tree_add_text (dlsw_vector_tree,tvb,offset+2,vlen-2,
                                 "NetBIOS Name Exclusivity = %s",tvb_get_guint8(tvb,offset+2)==1?"On":"Off");
            break;
          case 0x89:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_mac_address_list, tvb, offset+2, 6, ENC_NA);
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_mac_address_list, tvb, offset+8, 6, ENC_NA);
            break;
          case 0x8a:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_netbios_name, tvb, offset+2, vlen-2, ENC_NA|ENC_ASCII);
            break;
          case 0x8b:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_vendor_oui, tvb, offset+2, vlen-2, ENC_BIG_ENDIAN);
            break;
          case 0x8c:
            proto_tree_add_item(dlsw_vector_tree, hf_dlsw_multicast_version_number, tvb, offset+2, vlen-2, ENC_NA);
            break;
          default:
            proto_tree_add_text (dlsw_vector_tree,tvb,offset+2,vlen-2,"Vector Data = ???");
        }
        offset+=vlen;
      };
      break;
    default:
      proto_tree_add_text (tree,tvb,4,mlen - 4,"Unknown data");
  }

}

static int
dissect_dlsw_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  if (try_val_to_str(tvb_get_guint8(tvb, 0), dlsw_version_vals) == NULL)
  {
    /* Probably not a DLSw packet. */
    return 0;
  }

  return dissect_dlsw_pdu(tvb, pinfo, tree, data);
}

static guint
get_dlsw_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint hlen, mlen;

  /*
   * Get the length of the DLSw header.
   */
  hlen=tvb_get_guint8(tvb,offset+1);

  /*
   * Get the length of the DLSw message.
   */
  mlen = tvb_get_ntohs(tvb,offset+2);

  /*
   * The total length is the sum of those.
   */
  return hlen + mlen;
}

static int
dissect_dlsw_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  if (try_val_to_str(tvb_get_guint8(tvb, 0), dlsw_version_vals) == NULL)
  {
    /* Probably not a DLSw packet. */
    return 0;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_dlsw_pdu_len, dissect_dlsw_pdu, data);
  return tvb_length(tvb);
}

void
proto_register_dlsw(void)
{
  static hf_register_info hf[] = {
	{&hf_dlsw_flow_control_indication,
	 {"Flow Control Indication", "dlsw.flow_control_indication", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
	  NULL, HFILL}},
	{&hf_dlsw_flow_control_ack,
	 {"Flow Control Acknowledgment", "dlsw.flow_control_ack", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
	  NULL, HFILL}},
	{&hf_dlsw_flow_control_operator,
     {"Flow Control Operator", "dlsw.flow_control_operator", FT_UINT8, BASE_DEC, VALS(dlsw_fc_cmd_vals), 0x07,
	  NULL, HFILL}},
	{&hf_dlsw_flags_explorer_msg,
     {"Explorer message", "dlsw.flags.explorer_msg", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
	  NULL, HFILL}},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_dlsw_version, { "Version", "dlsw.version", FT_UINT8, BASE_DEC, VALS(dlsw_version_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_header_length, { "Header Length", "dlsw.header_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_message_length, { "Message Length", "dlsw.message_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_remote_dlc, { "Remote DLC", "dlsw.remote_dlc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_remote_dlc_pid, { "Remote DLC PID", "dlsw.remote_dlc_pid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_message_type, { "Message Type", "dlsw.message_type", FT_UINT8, BASE_HEX, VALS(dlsw_type_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_flow_ctrl_byte, { "Flow ctrl byte", "dlsw.flow_ctrl_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_protocol_id, { "Protocol ID", "dlsw.protocol_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_header_number, { "Header Number", "dlsw.header_number", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_old_message_type, { "Old message type", "dlsw.old_message_type", FT_UINT8, BASE_HEX, VALS(dlsw_type_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_capex_type, { "Capability exchange type", "dlsw.capex_type", FT_UINT8, BASE_HEX, VALS(dlsw_capex_type_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_largest_frame_size, { "Largest Frame size", "dlsw.largest_frame_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_ssp_flags, { "SSP Flags", "dlsw.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_circuit_priority, { "Circuit priority", "dlsw.circuit_priority", FT_UINT8, BASE_DEC, VALS(dlsw_pri_vals), 0x7, NULL, HFILL }},
      { &hf_dlsw_target_mac_address, { "Target MAC Address", "dlsw.target_mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_origin_mac_address, { "Origin MAC Address", "dlsw.origin_mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_origin_link_sap, { "Origin Link SAP", "dlsw.origin_link_sap", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_target_link_sap, { "Target Link SAP", "dlsw.target_link_sap", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_frame_direction, { "Frame direction", "dlsw.frame_direction", FT_UINT8, BASE_HEX, VALS(dlsw_frame_direction_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_length, { "DLC Header Length", "dlsw.dlc_header_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_origin_dlc_port_id, { "Origin DLC Port ID", "dlsw.origin_dlc_port_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_origin_dlc, { "Origin DLC", "dlsw.origin_dlc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_origin_transport_id, { "Origin Transport ID", "dlsw.origin_transport_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_target_dlc_port_id, { "Target DLC Port ID", "dlsw.target_dlc_port_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_target_dlc, { "Target DLC", "dlsw.target_dlc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_target_transport_id, { "Target Transport ID", "dlsw.target_transport_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_ac_byte, { "DLC Header - AC byte", "dlsw.dlc_header.ac_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_fc_byte, { "DLC Header - FC byte", "dlsw.dlc_header.fc_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_da, { "DLC Header - DA", "dlsw.dlc_header.da", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_sa, { "DLC Header - SA", "dlsw.dlc_header.sa", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_rif, { "DLC Header - RIF", "dlsw.dlc_header.rif", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_dsap, { "DLC Header - DSAP", "dlsw.dlc_header.dsap", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_ssap, { "DLC Header - SSAP", "dlsw.dlc_header.ssap", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_dlc_header_ctrl, { "DLC Header - Ctrl", "dlsw.dlc_header.ctrl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_capabilities_length, { "Capabilities Length", "dlsw.capabilities_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_error_pointer, { "Error pointer", "dlsw.error_pointer", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_error_cause, { "Error cause", "dlsw.error_cause", FT_UINT16, BASE_HEX, VALS(dlsw_refuse_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_vector_length, { "Vector Length", "dlsw.vector_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_vector_type, { "Vector Type", "dlsw.vector_type", FT_UINT8, BASE_HEX, VALS(dlsw_vector_vals), 0x0, NULL, HFILL }},
      { &hf_dlsw_oui, { "OUI", "dlsw.oui", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_initial_pacing_window, { "Initial Pacing Window", "dlsw.initial_pacing_window", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_version_string, { "Version String", "dlsw.version_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_tcp_connections, { "TCP connections", "dlsw.tcp_connections", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_mac_address_list, { "MAC Address List", "dlsw.mac_address_list", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_netbios_name, { "NetBIOS name", "dlsw.netbios_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_vendor_oui, { "Vendor OUI", "dlsw.vendor_oui", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_dlsw_multicast_version_number, { "Multicast Version Number", "dlsw.multicast_version_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_dlsw,
    &ett_dlsw_header,
    &ett_dlsw_fc,
    &ett_dlsw_sspflags,
    &ett_dlsw_data,
    &ett_dlsw_vector,
  };

  static ei_register_info ei[] = {
    { &ei_dlsw_dlc_header_length, { "dlsw.dlc_header_length.bogus", PI_PROTOCOL, PI_WARN, "DLC Header Length bogus", EXPFILL }},
  };

  expert_module_t* expert_dlsw;

  proto_dlsw = proto_register_protocol("Data Link SWitching", "DLSw", "dlsw");
  proto_register_field_array(proto_dlsw, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dlsw = expert_register_protocol(proto_dlsw);
  expert_register_field_array(expert_dlsw, ei, array_length(ei));

}

void
proto_reg_handoff_dlsw(void)
{
  dissector_handle_t dlsw_udp_handle, dlsw_tcp_handle;

  dlsw_udp_handle = new_create_dissector_handle(dissect_dlsw_udp, proto_dlsw);
  dissector_add_uint("udp.port", UDP_PORT_DLSW, dlsw_udp_handle);

  dlsw_tcp_handle = new_create_dissector_handle(dissect_dlsw_tcp, proto_dlsw);
  dissector_add_uint("tcp.port", TCP_PORT_DLSW, dlsw_tcp_handle);
}
