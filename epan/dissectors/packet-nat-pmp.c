/* packet-nat-pmp.c
 * Routines for NAT Port Mapping Protocol packet disassembly.
 * RFC 6886
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Routines for Port Control Protocol packet disassembly
 * (backwards compatible with NAT Port Mapping protocol)
 * RFC6887: Port Control Protocol (PCP) https://tools.ietf.org/html/rfc6887
 *
 * Copyright 2012, Michael Mann
 *
 * Description Option for the Port Control Protocol
 * RFC 7220
 * Discovering NAT64 IPv6 Prefixes Using the Port Control Protocol (PCP)
 * RFC 7225
 *
 * Alexis La Goutte
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_nat_pmp(void);
void proto_reg_handoff_nat_pmp(void);

static dissector_handle_t nat_pmp_handle;
static dissector_handle_t pcp_handle;

#define PCP_PORT_RANGE  "5350-5351"

/* NAT Port opcodes */
#define EXTERNAL_ADDRESS_REQUEST      0
#define MAP_UDP_REQUEST               1
#define MAP_TCP_REQUEST               2
#define EXTERNAL_ADDRESS_RESPONSE   128
#define MAP_UDP_RESPONSE            129
#define MAP_TCP_RESPONSE            130

/* Port Control opcodes */
#define ANNOUNCE_REQUEST        0
#define MAP_REQUEST             1
#define PEER_REQUEST            2
#define ANNOUNCE_RESPONSE       128
#define MAP_RESPONSE            129
#define PEER_RESPONSE           130

/* Port Control options */
#define OPT_THIRD_PARTY         1
#define OPT_PREFER_FAILURE      2
#define OPT_FILTER              3
#define OPT_DESCRIPTION         128
#define OPT_PREFIX64            129
#define OPT_PORT_SET            130

static int proto_nat_pmp;
static int proto_pcp;

static int hf_version;
static int hf_opcode;
static int hf_result_code;
static int hf_sssoe;
static int hf_external_ip;
static int hf_reserved;
static int hf_internal_port;
static int hf_external_port_requested;
static int hf_external_port_mapped;
static int hf_rpmlis;
static int hf_pmlis;

static int ett_nat_pmp;

/* Port Control Protocol */
static int hf_pcp_version;
static int hf_request;
static int hf_response;
static int hf_pcp_r;
static int hf_pcp_opcode;
static int hf_pcp_result_code;
static int hf_reserved1;
static int hf_reserved2;
static int hf_reserved12;
static int hf_req_lifetime;
static int hf_rsp_lifetime;
static int hf_client_ip;
static int hf_epoch_time;
static int hf_map_nonce;
static int hf_map_protocol;
static int hf_map_reserved1;
static int hf_map_internal_port;
static int hf_map_req_sug_external_port;
static int hf_map_req_sug_ext_ip;
static int hf_map_rsp_assigned_external_port;
static int hf_map_rsp_assigned_ext_ip;
static int hf_peer_nonce;
static int hf_peer_protocol;
static int hf_peer_reserved;
static int hf_peer_internal_port;
static int hf_peer_req_sug_external_port;
static int hf_peer_req_sug_ext_ip;
static int hf_peer_remote_peer_port;
static int hf_peer_remote_peer_ip;
static int hf_peer_rsp_assigned_external_port;
static int hf_peer_rsp_assigned_ext_ip;
static int hf_options;
static int hf_option;
static int hf_option_code;
static int hf_option_reserved;
static int hf_option_length;
static int hf_option_third_party_internal_ip;
static int hf_option_filter_reserved;
static int hf_option_filter_prefix_length;
static int hf_option_filter_remote_peer_port;
static int hf_option_filter_remote_peer_ip;
static int hf_option_description;
static int hf_option_p64_length;
static int hf_option_p64_prefix64;
static int hf_option_p64_suffix;
static int hf_option_p64_ipv4_prefix_count;
static int hf_option_p64_ipv4_prefix_length;
static int hf_option_p64_ipv4_address;
static int hf_option_portset_size;
static int hf_option_portset_first_suggested_port;
static int hf_option_portset_first_assigned_port;
static int hf_option_portset_reserved;
static int hf_option_portset_parity;
static int hf_option_padding;

static int ett_pcp;
static int ett_opcode;
static int ett_option;
static int ett_suboption;

static expert_field ei_natpmp_opcode_unknown;
static expert_field ei_pcp_opcode_unknown;
static expert_field ei_pcp_option_unknown;

static const value_string opcode_vals[] = {
  { EXTERNAL_ADDRESS_REQUEST,  "External Address Request"   },
  { EXTERNAL_ADDRESS_RESPONSE, "External Address Response"  },
  { MAP_UDP_REQUEST,           "Map UDP Request"            },
  { MAP_UDP_RESPONSE,          "Map UDP Response"           },
  { MAP_TCP_REQUEST,           "Map TCP Request"            },
  { MAP_TCP_RESPONSE,          "Map TCP Response"           },
  { 0, NULL }
};

static const value_string result_vals[] = {
  { 0, "Success"                },
  { 1, "Unsupported Version"    },
  { 2, "Not Authorized/Refused" },
  { 3, "Network Failure"        },
  { 4, "Out of resources"       },
  { 5, "Unsupported opcode"     },
  { 0, NULL }
};

static const value_string pcp_opcode_vals[] = {
  { 0,  "Announce" },
  { 1,  "Map" },
  { 2,  "Peer" },
  { 0, NULL }
};

static const value_string pcp_ropcode_vals[] = {
  { ANNOUNCE_REQUEST,  "Announce Request" },
  { MAP_REQUEST,       "Map Request" },
  { PEER_REQUEST,      "Peer Request" },
  { ANNOUNCE_RESPONSE, "Announce Response" },
  { MAP_RESPONSE,      "Map Response" },
  { PEER_RESPONSE,     "Peer Response" },
  { 0, NULL }
};

static const value_string pcp_result_vals[] = {
  { 0,  "Success" },
  { 1,  "Unsupported Version" },
  { 2,  "Not Authorized/Refused" },
  { 3,  "Malformed Request" },
  { 4,  "Unsupported opcode" },
  { 5,  "Unsupported option" },
  { 6,  "Malformed option" },
  { 7,  "Network failure" },
  { 8,  "No resources" },
  { 9,  "Unsupported protocol" },
  { 10, "User exceeds quota" },
  { 11, "Cannot provide external port" },
  { 12, "Address mismatch" },
  { 13, "Excessive remote peers" },
  { 0, NULL }
};

static const value_string pcp_option_vals[] = {
  { 0,                  "Reserved" },
  { OPT_THIRD_PARTY,    "Third Party" },
  { OPT_PREFER_FAILURE, "Prefer Failure" },
  { OPT_FILTER,         "Filter" },
  { OPT_DESCRIPTION,    "Description" },
  { OPT_PREFIX64,       "Prefix64" },
  { OPT_PORT_SET,       "Port Set" },
  { 0, NULL }
};

static const value_string pcp_protocol_vals[] = {
  {0, "All Protocols"},
  {6, "TCP"},
  {17, "UDP"},
  { 0, NULL }
};

static int
dissect_nat_pmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *nat_pmp_tree;
  proto_item *ti, *op_ti;
  int start_offset, offset = 0;
  uint8_t opcode;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "NAT-PMP");
  col_clear (pinfo->cinfo, COL_INFO);

  start_offset = offset;
  ti = proto_tree_add_item(tree, proto_nat_pmp, tvb, offset, -1, ENC_NA);
  nat_pmp_tree = proto_item_add_subtree(ti, ett_nat_pmp);

  proto_tree_add_item(nat_pmp_tree, hf_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  opcode = tvb_get_uint8 (tvb, offset);
  proto_item_append_text (ti, ", %s", val_to_str(opcode, opcode_vals, "Unknown opcode: %d"));
  op_ti = proto_tree_add_item(nat_pmp_tree, hf_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  col_add_str (pinfo->cinfo, COL_INFO, val_to_str(opcode, opcode_vals, "Unknown opcode: %d"));

  switch(opcode) {

  case EXTERNAL_ADDRESS_REQUEST:
    /* No more data */
    break;

  case EXTERNAL_ADDRESS_RESPONSE:
    proto_tree_add_item(nat_pmp_tree, hf_result_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_sssoe, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(nat_pmp_tree, hf_external_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  case MAP_UDP_REQUEST:
  case MAP_TCP_REQUEST:
    proto_tree_add_item(nat_pmp_tree, hf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_external_port_requested, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_rpmlis, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  case MAP_UDP_RESPONSE:
  case MAP_TCP_RESPONSE:
    proto_tree_add_item(nat_pmp_tree, hf_result_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_sssoe, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(nat_pmp_tree, hf_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_external_port_mapped, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(nat_pmp_tree, hf_pmlis, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  default:
    /* Unknown OP */
    expert_add_info_format(pinfo, op_ti, &ei_natpmp_opcode_unknown, "Unknown opcode: %d", opcode);
    break;
  }

  return (offset-start_offset);
}

static int
dissect_portcontrol_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version)
{
  proto_tree *pcp_tree, *opcode_tree = NULL, *option_tree, *option_sub_tree;
  proto_item *ti, *opcode_ti, *option_ti, *suboption_ti;
  int offset = 0, start_offset, start_opcode_offset, start_option_offset;
  uint8_t ropcode, option;
  uint16_t option_length;
  int mod_option_length = 0;
  int option_padding_length = 0;
  bool is_response;
  const char* op_str;

  if(version == 1)
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCP v1");
  else
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCP v2");
  col_clear(pinfo->cinfo, COL_INFO);

  start_offset = offset;
  ti = proto_tree_add_item(tree, proto_pcp, tvb, offset, -1, ENC_NA);
  pcp_tree = proto_item_add_subtree(ti, ett_pcp);

  proto_tree_add_item(pcp_tree, hf_pcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  ropcode = tvb_get_uint8(tvb, offset);
  is_response = ropcode & 0x80;
  op_str = val_to_str(ropcode, pcp_ropcode_vals, "Unknown opcode: %d");
  proto_item_append_text(ti, ", %s", op_str);
  proto_tree_add_item(pcp_tree, hf_pcp_r, tvb, offset, 1, ENC_BIG_ENDIAN);
  opcode_ti = proto_tree_add_item(pcp_tree, hf_pcp_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  col_add_str(pinfo->cinfo, COL_INFO, op_str);

  if(!is_response)
  {
    ti = proto_tree_add_boolean(pcp_tree, hf_request, tvb, offset-1, 1, is_response == false);
    proto_item_set_hidden(ti);

    proto_tree_add_item(pcp_tree, hf_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(pcp_tree, hf_req_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(pcp_tree, hf_client_ip, tvb, offset, 16, ENC_NA);
    offset+=16;
  }
  else
  {
    ti = proto_tree_add_boolean(pcp_tree, hf_response, tvb, offset-1, 1, is_response == true);
    proto_item_set_hidden(ti);

    proto_tree_add_item(pcp_tree, hf_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(pcp_tree, hf_pcp_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(pcp_tree, hf_rsp_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(pcp_tree, hf_epoch_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(pcp_tree, hf_reserved12, tvb, offset, 12, ENC_NA);
    offset+=12;
  }

  start_opcode_offset = offset;
  if(try_val_to_str(ropcode, pcp_ropcode_vals) != NULL)
  {
    opcode_tree = proto_tree_add_subtree(pcp_tree, tvb, offset, 0, ett_opcode, &opcode_ti, op_str);
  }

  uint32_t protocol = 0;
  uint32_t internal_port = 0;
  uint32_t external_port = 0;
  uint32_t port_set_size = 0;

  switch(ropcode) {

  case ANNOUNCE_REQUEST:
  case ANNOUNCE_RESPONSE:
    /* No data */
    break;
  case MAP_REQUEST:
  case MAP_RESPONSE:
    {
      if(version > 1) {
        proto_tree_add_item(opcode_tree, hf_map_nonce, tvb, offset, 12, ENC_NA);
        offset+=12;
      }

      proto_tree_add_item_ret_uint(opcode_tree, hf_map_protocol, tvb, offset, 1, ENC_BIG_ENDIAN, &protocol);
      offset++;
      proto_tree_add_item(opcode_tree, hf_map_reserved1, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
      proto_tree_add_item_ret_uint(opcode_tree, hf_map_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN, &internal_port);
      offset += 2;

      if (ropcode == MAP_REQUEST) {
        proto_tree_add_item_ret_uint(opcode_tree, hf_map_req_sug_external_port, tvb, offset, 2, ENC_BIG_ENDIAN, &external_port);
        offset += 2;
        proto_tree_add_item(opcode_tree, hf_map_req_sug_ext_ip, tvb, offset, 16, ENC_NA);
        offset += 16;
      } else {
        proto_tree_add_item_ret_uint(opcode_tree, hf_map_rsp_assigned_external_port, tvb, offset, 2, ENC_BIG_ENDIAN, &external_port);
        offset += 2;
        proto_tree_add_item(opcode_tree, hf_map_rsp_assigned_ext_ip, tvb, offset, 16, ENC_NA);
        offset += 16;
      }

      break;
    }
  case PEER_REQUEST:
  case PEER_RESPONSE:
    if(version > 1)
    {
      proto_tree_add_item(opcode_tree, hf_peer_nonce, tvb, offset, 12, ENC_NA);
      offset+=12;
    }

    proto_tree_add_item(opcode_tree, hf_peer_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opcode_tree, hf_peer_reserved, tvb, offset, 3, ENC_NA);
    offset+=3;
    proto_tree_add_item(opcode_tree, hf_peer_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    if(ropcode == PEER_REQUEST)
    {
      proto_tree_add_item(opcode_tree, hf_peer_req_sug_external_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset+=2;
      proto_tree_add_item(opcode_tree, hf_peer_req_sug_ext_ip, tvb, offset, 16, ENC_NA);
      offset+=16;
    }
    else
    {
      proto_tree_add_item(opcode_tree, hf_peer_rsp_assigned_external_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset+=2;
      proto_tree_add_item(opcode_tree, hf_peer_rsp_assigned_ext_ip, tvb, offset, 16, ENC_NA);
      offset+=16;
    }

    proto_tree_add_item(opcode_tree, hf_peer_remote_peer_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(opcode_tree, hf_peer_reserved, tvb, offset, 2, ENC_NA);
    offset+=2;
    proto_tree_add_item(opcode_tree, hf_peer_remote_peer_ip, tvb, offset, 16, ENC_NA);
    offset+=16;
    break;
  default:
    /* Unknown OP */
    expert_add_info_format(pinfo, opcode_ti, &ei_pcp_opcode_unknown, "Unknown opcode: %d", ropcode);
    break;
  }

  /* Now see if there are any options for the supported opcodes */
  if((tvb_reported_length_remaining(tvb, offset) > 0) &&
      (try_val_to_str(ropcode, pcp_ropcode_vals) != NULL))
  {
    start_option_offset = offset;
    option_ti = proto_tree_add_item(opcode_tree, hf_options, tvb, offset, 0, ENC_NA);
    option_tree = proto_item_add_subtree(option_ti, ett_option);

    while(tvb_reported_length_remaining(tvb, offset) > 0)
    {
      suboption_ti = proto_tree_add_item(option_tree, hf_option, tvb, offset, 1, ENC_NA);
      option_sub_tree = proto_item_add_subtree(suboption_ti, ett_suboption);

      proto_tree_add_item(option_sub_tree, hf_option_code, tvb, offset, 1, ENC_BIG_ENDIAN);
      option = tvb_get_uint8(tvb, offset);
      proto_item_append_text(suboption_ti, ": %s", val_to_str(option, pcp_option_vals, "Unknown option: %d"));
      offset++;

      proto_tree_add_item(option_sub_tree, hf_option_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;

      proto_tree_add_item(option_sub_tree, hf_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
      option_length = tvb_get_ntohs(tvb, offset);
      offset+=2;

      mod_option_length = option_length % 4;
      if( mod_option_length != 0 )
      {
        option_padding_length = 4 - mod_option_length;
      }

      proto_item_set_len(suboption_ti, option_length+4+option_padding_length);

      if(option_length > 0)
      {
        switch(option) {

        case OPT_THIRD_PARTY:
          proto_tree_add_item(option_sub_tree, hf_option_third_party_internal_ip, tvb, offset, 16, ENC_NA);
          break;

        case OPT_PREFER_FAILURE:
          /* No data */
          break;

        case OPT_FILTER:
          proto_tree_add_item(option_sub_tree, hf_option_filter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(option_sub_tree, hf_option_filter_prefix_length, tvb, offset+1, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(option_sub_tree, hf_option_filter_remote_peer_port, tvb, offset+2, 2, ENC_BIG_ENDIAN);
          proto_tree_add_item(option_sub_tree, hf_option_filter_remote_peer_ip, tvb, offset+4, 16, ENC_NA);
          break;

        case OPT_DESCRIPTION:
          proto_tree_add_item(option_sub_tree, hf_option_description, tvb, offset, option_length, ENC_UTF_8);
          break;

        case OPT_PREFIX64:
          {
            uint32_t p64_length;
            int optoffset = 0;

            if(option_length-optoffset < 2)
            {
              /*TODO: report an error here*/
              break;
            }
            proto_tree_add_item_ret_uint(option_sub_tree, hf_option_p64_length, tvb, offset+optoffset, 2, ENC_BIG_ENDIAN, &p64_length);
            optoffset += 2;
            if(option_length-optoffset < 12)
            {
              /*TODO: report an error here*/
              break;
            }
            if(p64_length <= 12)
            {
              /*TODO: Fix display of Prefix64 and Suffix*/
              proto_tree_add_item(option_sub_tree, hf_option_p64_prefix64, tvb, offset+optoffset, p64_length, ENC_NA);
              optoffset += p64_length;

              proto_tree_add_item(option_sub_tree, hf_option_p64_suffix, tvb, offset+optoffset, 12-p64_length, ENC_NA);
              optoffset += (12-p64_length);
            } else {
              /*TODO: report an error here*/
              optoffset += 12;
            }

            if(option_length-optoffset > 0)
            {
              uint32_t ipv4_prefix_count;

              if(option_length-optoffset < 2)
              {
                /*TODO: report an error here*/
                break;
              }
              proto_tree_add_item_ret_uint(option_sub_tree, hf_option_p64_ipv4_prefix_count, tvb, offset+optoffset, 2, ENC_BIG_ENDIAN, &ipv4_prefix_count);
              optoffset += 2;

              while(ipv4_prefix_count)
              {
                if(option_length-optoffset < 2)
                {
                  /*TODO: report an error here*/
                  break;
                }
                proto_tree_add_item(option_sub_tree, hf_option_p64_ipv4_prefix_length, tvb, offset+optoffset, 2, ENC_BIG_ENDIAN);
                optoffset += 2;
                if(option_length-optoffset < 4)
                {
                  /*TODO: report an error here*/
                  break;
                }
                proto_tree_add_item(option_sub_tree, hf_option_p64_ipv4_address, tvb, offset+optoffset, 4, ENC_BIG_ENDIAN);
                optoffset += 4;
                ipv4_prefix_count--;
              }
            }
          }
          break;

        case OPT_PORT_SET:
          proto_tree_add_item_ret_uint(option_sub_tree, hf_option_portset_size, tvb, offset, 2, ENC_BIG_ENDIAN, &port_set_size);
          if (!is_response) {
            proto_tree_add_item_ret_uint(option_sub_tree, hf_option_portset_first_suggested_port, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &external_port);
          } else {
            proto_tree_add_item_ret_uint(option_sub_tree, hf_option_portset_first_assigned_port, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &external_port);
          }
          proto_tree_add_item(option_sub_tree, hf_option_portset_reserved, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(option_sub_tree, hf_option_portset_parity, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
          break;

        default:
          /* Unknown option */
          expert_add_info_format(pinfo, option_ti, &ei_pcp_option_unknown, "Unknown option: %d", option);
          break;
        }
      }

      offset+=option_length;

      if( option_padding_length > 0 )
      {
        proto_tree_add_item(option_sub_tree, hf_option_padding, tvb, offset, option_padding_length, ENC_NA);
        offset+=option_padding_length;
      }
    }

    proto_item_set_len(option_ti, offset-start_option_offset);
  }

  proto_item_set_len(opcode_ti, offset-start_opcode_offset);

  bool is_map_opcode = (ropcode == MAP_REQUEST || ropcode == MAP_RESPONSE);
  if (is_map_opcode && port_set_size != 0) {
    col_add_fstr(
      pinfo->cinfo,
      COL_INFO,
      "%s: %d-%d -> %d-%d [%s]",
      op_str,
      internal_port,
      internal_port + port_set_size,
      external_port,
      external_port + port_set_size,
      val_to_str(protocol, pcp_protocol_vals, "Unknown Protocol %d")
    );
  } else if (is_map_opcode) {
    col_add_fstr(
      pinfo->cinfo,
      COL_INFO,
      "%s: %d -> %d [%s]",
      op_str,
      internal_port,
      external_port,
      val_to_str(protocol, pcp_protocol_vals, "Unknown Protocol %d")
    );
  }

  return (offset-start_offset);
}

static int
dissect_portcontrol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint8_t version = tvb_get_uint8(tvb, 0);

    switch(version)
    {
    case 0:
        /* NAT-PMP protocol */
        return dissect_nat_pmp(tvb, pinfo, tree, data);
    case 1:
    case 2:
        return dissect_portcontrol_pdu(tvb, pinfo, tree, version);
    }

    return 0;
}

void proto_register_nat_pmp(void)
{
  static hf_register_info hf[] = {
    { &hf_version,
      { "Version", "nat-pmp.version", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_opcode,
      { "Opcode", "nat-pmp.opcode", FT_UINT8, BASE_DEC,
        VALS(opcode_vals), 0x0, NULL, HFILL } },
    { &hf_result_code,
      { "Result Code", "nat-pmp.result_code", FT_UINT16, BASE_DEC,
        VALS(result_vals), 0x0, NULL, HFILL } },
    { &hf_sssoe,
      { "Seconds Since Start of Epoch", "nat-pmp.sssoe", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_ip,
      { "External IP Address", "nat-pmp.external_ip", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_reserved,
      { "Reserved", "nat-pmp.reserved", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Reserved (must be zero)", HFILL } },
    { &hf_internal_port,
      { "Internal Port", "nat-pmp.internal_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_port_requested,
      { "Requested External Port", "nat-pmp.external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_port_mapped,
      { "Mapped External Port", "nat-pmp.external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_rpmlis,
      { "Requested Port Mapping Lifetime", "nat-pmp.pml", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Requested Port Mapping Lifetime in Seconds", HFILL } },
    { &hf_pmlis,
      { "Port Mapping Lifetime", "nat-pmp.pml", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Port Mapping Lifetime in Seconds", HFILL } },
  };

  static hf_register_info pcp_hf[] = {
    { &hf_pcp_version,
      { "Version", "portcontrol.version", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_request,
      { "Request", "portcontrol.request", FT_BOOLEAN, 8,
        NULL, 0x01, NULL, HFILL } },
    { &hf_response,
      { "Response", "portcontrol.response", FT_BOOLEAN, 8,
        NULL, 0x01, NULL, HFILL } },
    { &hf_pcp_r,
      { "R", "portcontrol.r", FT_BOOLEAN, 8,
        TFS(&tfs_response_request), 0x80, "Indicates Request (0) or Response (1)", HFILL } },
    { &hf_pcp_opcode,
      { "Opcode", "portcontrol.opcode", FT_UINT8, BASE_DEC,
        VALS(pcp_opcode_vals), 0x7F, NULL, HFILL } },
    { &hf_pcp_result_code,
      { "Result Code", "portcontrol.result_code", FT_UINT16, BASE_DEC,
        VALS(pcp_result_vals), 0x0, NULL, HFILL } },
    { &hf_reserved1,
      { "Reserved", "portcontrol.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_reserved2,
      { "Reserved", "portcontrol.reserved", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_reserved12,
      { "Reserved", "portcontrol.rsp_reserved", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_req_lifetime,
      { "Requested Lifetime", "portcontrol.lifetime_req", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_rsp_lifetime,
      { "Lifetime", "portcontrol.lifetime_rsp", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_client_ip,
      { "Client IP Address", "portcontrol.client_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_epoch_time,
      { "Epoch Time", "portcontrol.epoch_time", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_nonce,
      { "Mapping Nonce", "portcontrol.map.nonce", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_protocol,
      { "Protocol", "portcontrol.map.protocol", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_reserved1,
      { "Reserved", "portcontrol.map.reserved", FT_UINT24, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_internal_port,
      { "Internal Port", "portcontrol.map.internal_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_req_sug_external_port,
      { "Suggested External Port", "portcontrol.map.req_sug_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_req_sug_ext_ip,
      { "Suggested External IP Address", "portcontrol.map.req_sug_external_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_rsp_assigned_external_port,
      { "Assigned External Port", "portcontrol.map.rsp_assigned_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_rsp_assigned_ext_ip,
      { "Assigned External IP Address", "portcontrol.map.rsp_assigned_ext_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_nonce,
      { "Mapping Nonce", "portcontrol.peer.nonce", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_protocol,
      { "Protocol", "portcontrol.peer.protocol", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_reserved,
      { "Reserved", "portcontrol.peer.reserved", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_internal_port,
      { "Internal Port", "portcontrol.peer.internal_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_req_sug_external_port,
      { "Suggested External Port", "portcontrol.peer.req_sug_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_req_sug_ext_ip,
      { "Suggested External IP Address", "portcontrol.peer.req_sug_external_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_remote_peer_port,
      { "Remote Peer Port", "portcontrol.peer.remote_peer_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_remote_peer_ip,
      { "Remote Peer IP Address", "portcontrol.peer.remote_peer_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_rsp_assigned_external_port,
      { "Assigned External Port", "portcontrol.peer.rsp_assigned_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_peer_rsp_assigned_ext_ip,
      { "Assigned External IP Address", "portcontrol.peer.rsp_assigned_ext_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_options,
      { "Options", "portcontrol.options", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option,
      { "Option", "portcontrol.option", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_code,
      { "Option", "portcontrol.option.code", FT_UINT8, BASE_DEC,
        VALS(pcp_option_vals), 0x0, NULL, HFILL } },
    { &hf_option_reserved,
      { "Reserved", "portcontrol.option.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_length,
      { "Option Length", "portcontrol.option.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_third_party_internal_ip,
      { "Internal IP Address", "portcontrol.option.third_party.internal_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_filter_reserved,
      { "Reserved", "portcontrol.option.filter.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_filter_prefix_length,
      { "Prefix Length", "portcontrol.option.filter.prefix_length", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_filter_remote_peer_port,
      { "Remote Peer Port", "portcontrol.option.filter.remote_peer_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_filter_remote_peer_ip,
      { "Remote Peer IP Address", "portcontrol.option.filter.remote_peer_ip", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_description,
      { "Description", "portcontrol.option.description", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_length,
      { "Length", "portcontrol.option.p64.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_prefix64,
      { "Prefix64", "portcontrol.option.p64.prefix64", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_suffix,
      { "Suffix", "portcontrol.option.p64.suffix", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_ipv4_prefix_count,
      { "IPv4 Prefix Count", "portcontrol.option.p64.ipv4_prefix_count", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_ipv4_prefix_length,
      { "IPv4 Prefix Length", "portcontrol.option.p64.ipv4_prefix_length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_p64_ipv4_address,
      { "IPv4 Address", "portcontrol.option.p64.ipv4_address", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_portset_size,
      { "Port Set Size", "portcontrol.option.portset.size", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_portset_first_suggested_port,
      { "Suggested First Port", "portcontrol.option.portset.req_sug_first_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_portset_first_assigned_port,
      { "Assigned First Port", "portcontrol.option.portset.rsp_assigned_first_external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_option_portset_reserved,
      { "Reserved", "portcontrol.option.portset.reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL } },
    { &hf_option_portset_parity,
      { "Parity Requested", "portcontrol.option.portset.parity", FT_BOOLEAN, 8,
        NULL, 0x01, NULL, HFILL } },
    { &hf_option_padding,
      { "Padding", "portcontrol.option.padding", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    };

  static int *pcp_ett[] = {
        &ett_pcp,
        &ett_opcode,
        &ett_option,
        &ett_suboption
    };

  static int *ett[] = {
    &ett_nat_pmp,
  };

  static ei_register_info natpmp_ei[] = {
     { &ei_natpmp_opcode_unknown, { "nat-pmp.opcode.unknown", PI_RESPONSE_CODE, PI_WARN, "Unknown opcode", EXPFILL }},
  };

  static ei_register_info pcp_ei[] = {
     { &ei_pcp_opcode_unknown, { "portcontrol.opcode.unknown", PI_RESPONSE_CODE, PI_WARN, "Unknown opcode", EXPFILL }},
     { &ei_pcp_option_unknown, { "portcontrol.option.unknown", PI_RESPONSE_CODE, PI_WARN, "Unknown option", EXPFILL }},
  };

  expert_module_t* expert_nat_pmp;
  expert_module_t* expert_pcp;

  proto_nat_pmp = proto_register_protocol("NAT Port Mapping Protocol", "NAT-PMP", "nat-pmp");

  proto_register_field_array(proto_nat_pmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_nat_pmp = expert_register_protocol(proto_nat_pmp);
  expert_register_field_array(expert_nat_pmp, natpmp_ei, array_length(natpmp_ei));

  nat_pmp_handle = register_dissector("nat-pmp", dissect_nat_pmp, proto_nat_pmp);

  proto_pcp = proto_register_protocol("Port Control Protocol", "Port Control", "portcontrol");

  proto_register_field_array(proto_pcp, pcp_hf, array_length(pcp_hf));
  proto_register_subtree_array(pcp_ett, array_length(pcp_ett));
  expert_pcp = expert_register_protocol(proto_pcp);
  expert_register_field_array(expert_pcp, pcp_ei, array_length(pcp_ei));

  pcp_handle = register_dissector("portcontrol", dissect_portcontrol, proto_pcp);
}

void proto_reg_handoff_nat_pmp(void)
{
  dissector_add_uint_range_with_preference("udp.port", PCP_PORT_RANGE, pcp_handle);

  /* Port Control Protocol (packet-portcontrol.c) shares the same UDP ports as
     NAT-PMP, but it backwards compatible.  However, still let NAT-PMP
     use Decode As
   */
  dissector_add_for_decode_as_with_preference("udp.port", nat_pmp_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
