/* packet-sstp.c
 * routines for sstp packet dissasembly
 * - http://msdn.microsoft.com/en-us/library/cc247338(v=prot.20).aspx
 *
 * Created as part of a semester project at the University of Applied Sciences Hagenberg
 * (http://www.fh-ooe.at/en/hagenberg-campus/)
 *
 * Copyright (c) 2013:
 *   Hofer Manuel (manuel@mnlhfr.at)
 *   Nemeth Franz
 *   Scheipner Alexander
 *   Stiftinger Thomas
 *   Werner Sebastian
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

#include <epan/packet.h>
#include "packet-tcp.h"

void proto_register_sstp(void);
void proto_reg_handoff_sstp(void);

#define SSTP_BITMASK_MAJORVERSION 0xF0
#define SSTP_BITMASK_MINORVERSION 0x0F
#define SSTP_BITMASK_CONTROLFLAG 0x01
#define SSTP_BITMASK_LENGTH_RESERVED 0xF000
#define SSTP_BITMASK_LENGTH_LENGTH 0x0FFF
#define SSTP_CERT_HASH_PROTOCOL_SHA1 0x01
#define SSTP_CERT_HASH_PROTOCOL_SHA256 0x02
#define SSTP_ENCAPSULATED_PPP 0x0001

/* bytewise offsets inside the paket buffer */
#define SSTP_OFFSET_ATTRIBUTES    8
#define SSTP_OFFSET_DATA          4
#define SSTP_OFFSET_RESERVED      1
#define SSTP_OFFSET_ISCONTROL     1
#define SSTP_OFFSET_LENGTH        2
#define SSTP_OFFSET_MAJORVERSION  0
#define SSTP_OFFSET_MINORVERSION  0
#define SSTP_OFFSET_MSGTYPE       4
#define SSTP_OFFSET_NUMATTRIB     6

/* fieldsize in byte */
#define SSTP_FSIZE_ATTRIBUTE              4
#define SSTP_FSIZE_ATTRIB_ID              1
#define SSTP_FSIZE_ATTRIB_LENGTH          2
#define SSTP_FSIZE_ATTRIB_RESERVED        1
#define SSTP_FSIZE_CERT_HASH_SHA1         20
#define SSTP_FSIZE_CERT_HASH_SHA256       32
#define SSTP_FSIZE_COMPOUND_MAC_SHA1      20
#define SSTP_FSIZE_COMPOUND_MAC_SHA256    32
#define SSTP_FSIZE_ENCAPSULATED_PROTOCOL  2
#define SSTP_FSIZE_HASH_PROTOCOL          1
#define SSTP_FSIZE_HASH_PROTOCOL_BITMASK  1
#define SSTP_FSIZE_ISCONTROL              1
#define SSTP_FSIZE_LENGTH                 2
#define SSTP_FSIZE_MAJORVERSION           1
#define SSTP_FSIZE_MINORVERSION           1
#define SSTP_FSIZE_MSGTYPE                2
#define SSTP_FSIZE_NONCE                  32
#define SSTP_FSIZE_NUMATTRIB              2
#define SSTP_FSIZE_PADDING_SHA1           12
#define SSTP_FSIZE_RESERVED               1
#define SSTP_FSIZE_RESERVED2              3
#define SSTP_FSIZE_STATUS                 4

/* Message types */
#define SSTP_MSG_CALL_ABORT 0x005
#define SSTP_MSG_CALL_CONNECTED 0x004
#define SSTP_MSG_CALL_CONNECT_ACK 0x002
#define SSTP_MSG_CALL_CONNECT_NAK 0x003
#define SSTP_MSG_CALL_CONNECT_REQUEST 0x001
#define SSTP_MSG_CALL_DISCONNECT 0x006
#define SSTP_MSG_CALL_DISCONNECT_ACK 0x007
#define SSTP_MSG_ECHO_REQUEST 0x008
#define SSTP_MSG_ECHO_RESPONSE 0x009

/* Attribute Types */
#define SSTP_ATTRIB_CRYPTO_BINDING 3
#define SSTP_ATTRIB_CRYPTO_BINDING_REQ 4
#define SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID 1
#define SSTP_ATTRIB_NO_ERROR 0
#define SSTP_ATTRIB_STATUS_INFO 2

/* Status Types */
#define SSTP_ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG 0x000009
#define SSTP_ATTRIB_STATUS_DUPLICATE_ATTRIBUTE 0x000001
#define SSTP_ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH 0x000003
#define SSTP_ATTRIB_STATUS_INVALID_FRAME_RECEIVED 0x000007
#define SSTP_ATTRIB_STATUS_NEGOTIATION_TIMEOUT 0x000008
#define SSTP_ATTRIB_STATUS_NO_ERROR 0x000000
#define SSTP_ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING 0x00000a
#define SSTP_ATTRIB_STATUS_RETRY_COUNT_EXCEEDED 0x000006
#define SSTP_ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG 0x00000b
#define SSTP_ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED 0x000005
#define SSTP_ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE 0x000002
#define SSTP_ATTRIB_STATUS_VALUE_NOT_SUPPORTED 0x000004

static dissector_handle_t ppp_handle = NULL;
static gint ett_sstp = -1;
static gint ett_sstp_attribute = -1;
static gint ett_sstp_version = -1;
static gint hf_sstp_attrib_id = -1;
static gint hf_sstp_attrib_length = -1;
static gint hf_sstp_attrib_length_reserved = -1;
static gint hf_sstp_attrib_reserved = -1;
static gint hf_sstp_attrib_value = -1;
static gint hf_sstp_cert_hash = -1;
static gint hf_sstp_compound_mac = -1;
static gint hf_sstp_control_flag = -1;
static gint hf_sstp_data_unknown = -1;
static gint hf_sstp_ecapsulated_protocol = -1;
static gint hf_sstp_hash_protocol = -1;
static gint hf_sstp_length = -1;
static gint hf_sstp_major = -1;
static gint hf_sstp_messagetype = -1;
static gint hf_sstp_minor = -1;
static gint hf_sstp_nonce = -1;
static gint hf_sstp_numattrib = -1;
static gint hf_sstp_padding = -1;
static gint hf_sstp_reserved = -1;
static gint hf_sstp_status = -1;
static gint proto_sstp = -1;

static const value_string sstp_messagetypes[] = {
  {SSTP_MSG_CALL_CONNECT_REQUEST, "SSTP_MSG_CALL_CONNECT_REQUEST"},
  {SSTP_MSG_CALL_CONNECT_ACK, "SSTP_MSG_CALL_CONNECT_ACK"},
  {SSTP_MSG_CALL_CONNECT_NAK, "SSTP_MSG_CALL_CONNECT_NAK"},
  {SSTP_MSG_CALL_CONNECTED, "SSTP_MSG_CALL_CONNECTED"},
  {SSTP_MSG_CALL_ABORT, "SSTP_MSG_CALL_ABORT"},
  {SSTP_MSG_CALL_DISCONNECT, "SSTP_MSG_CALL_DISCONNECT"},
  {SSTP_MSG_CALL_DISCONNECT_ACK, "SSTP_MSG_CALL_DISCONNECT_ACK"},
  {SSTP_MSG_ECHO_REQUEST, "SSTP_MSG_ECHO_REQUEST"},
  {SSTP_MSG_ECHO_RESPONSE, "SSTP_MSG_ECHO_RESPONSE"},
  {0, NULL}
};

static const value_string sstp_attributes[] = {
  {SSTP_ATTRIB_NO_ERROR, "SSTP_ATTRIB_NO_ERROR"},
  {SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID, "SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID"},
  {SSTP_ATTRIB_STATUS_INFO, "SSTP_ATTRIB_STATUS_INFO"},
  {SSTP_ATTRIB_CRYPTO_BINDING, "SSTP_ATTRIB_CRYPTO_BINDING"},
  {SSTP_ATTRIB_CRYPTO_BINDING_REQ, "SSTP_ATTRIB_CRYPTO_BINDING_REQ"},
  {0, NULL}
};

static const value_string encapsulated_protocols[] = {
  {SSTP_ENCAPSULATED_PPP, "PPP"},
  {0, NULL}
};

static const value_string hash_protocols[] = {
  {SSTP_CERT_HASH_PROTOCOL_SHA1, "SHA1"},
  {SSTP_CERT_HASH_PROTOCOL_SHA256, "SHA256"},
  {0, NULL}
};

static const value_string attrib_status[] = {
  {SSTP_ATTRIB_STATUS_NO_ERROR, "SSTP_ATTRIB_STATUS_NO_ERROR"},
  {SSTP_ATTRIB_STATUS_DUPLICATE_ATTRIBUTE, "SSTP_ATTRIB_STATUS_DUPLICATE_ATTRIBUTE"},
  {SSTP_ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE, "SSTP_ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE"},
  {SSTP_ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH , "SSTP_ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH"},
  {SSTP_ATTRIB_STATUS_VALUE_NOT_SUPPORTED, "SSTP_ATTRIB_STATUS_VALUE_NOT_SUPPORTED"},
  {SSTP_ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED, "SSTP_ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED"},
  {SSTP_ATTRIB_STATUS_RETRY_COUNT_EXCEEDED, "SSTP_ATTRIB_STATUS_RETRY_COUNT_EXCEEDED"},
  {SSTP_ATTRIB_STATUS_INVALID_FRAME_RECEIVED, "SSTP_ATTRIB_STATUS_INVALID_FRAME_RECEIVED"},
  {SSTP_ATTRIB_STATUS_NEGOTIATION_TIMEOUT, "SSTP_ATTRIB_STATUS_NEGOTIATION_TIMEOUT"},
  {SSTP_ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG, "SSTP_ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG"},
  {SSTP_ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING, "SSTP_ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING"},
  {SSTP_ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG, "SSTP_ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG"},
  {0, NULL}
};

static int
dissect_sstp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint16 sstp_control_flag;
  guint32 offset = 0;
  guint8 sstp_major;
  guint8 sstp_minor;
  proto_item *ti;
  proto_tree *sstp_tree;
  proto_tree *sstp_tree_attribute;
  proto_tree *sstp_tree_version;
  guint16 sstp_numattrib;
  tvbuff_t *tvb_next;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSTP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_sstp, tvb, 0, -1, ENC_NA);
  sstp_tree = proto_item_add_subtree(ti, ett_sstp);

  sstp_control_flag = tvb_get_guint8(tvb, SSTP_OFFSET_ISCONTROL) & SSTP_BITMASK_CONTROLFLAG;
  sstp_minor = (tvb_get_guint8(tvb, SSTP_OFFSET_MINORVERSION) & SSTP_BITMASK_MINORVERSION); /* leftmost 4 bit */
  sstp_major = (tvb_get_guint8(tvb, SSTP_OFFSET_MAJORVERSION) >> 4); /* rightmost 4 bit */
  col_append_fstr(pinfo->cinfo, COL_INFO, "SSTP-%u.%u ", sstp_major, sstp_minor);

  sstp_tree_version = proto_tree_add_subtree_format(sstp_tree, tvb, offset, SSTP_FSIZE_MAJORVERSION, ett_sstp_version,
      NULL, "Version %d.%d", sstp_major, sstp_minor);
  proto_tree_add_item(sstp_tree_version, hf_sstp_major, tvb, SSTP_OFFSET_MAJORVERSION, SSTP_FSIZE_MAJORVERSION, ENC_BIG_ENDIAN);
  proto_tree_add_item(sstp_tree_version, hf_sstp_minor, tvb, SSTP_OFFSET_MINORVERSION, SSTP_FSIZE_MINORVERSION, ENC_BIG_ENDIAN);
  proto_tree_add_item(sstp_tree, hf_sstp_reserved, tvb,      SSTP_OFFSET_RESERVED, SSTP_FSIZE_RESERVED, ENC_NA);
  proto_tree_add_item(sstp_tree, hf_sstp_control_flag, tvb,  SSTP_OFFSET_ISCONTROL, SSTP_FSIZE_ISCONTROL, ENC_BIG_ENDIAN);
  proto_tree_add_item(sstp_tree, hf_sstp_length, tvb,        SSTP_OFFSET_LENGTH, SSTP_FSIZE_LENGTH, ENC_BIG_ENDIAN);

  /* check wether we got a control or data packet */
  if (sstp_control_flag) {
    guint16 sstp_messagetype = tvb_get_guint16(tvb, SSTP_OFFSET_MSGTYPE, ENC_BIG_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: CONTROL, %s; ", val_to_str(sstp_messagetype, sstp_messagetypes, "Unknown Messagetype"));
    proto_tree_add_item(sstp_tree, hf_sstp_messagetype, tvb,  SSTP_OFFSET_MSGTYPE, SSTP_FSIZE_MSGTYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(sstp_tree, hf_sstp_numattrib, tvb,    SSTP_OFFSET_NUMATTRIB, SSTP_FSIZE_NUMATTRIB, ENC_BIG_ENDIAN);
    sstp_numattrib = tvb_get_ntohs(tvb, SSTP_OFFSET_NUMATTRIB);

    /* display attributes */
    if (sstp_numattrib > 0) {
      guint16 attrib_length = 0;
      guint8 attrib_id = 0;
      guint8 hashproto = 0;
      offset = SSTP_OFFSET_ATTRIBUTES;

      for(;sstp_numattrib > 0; sstp_numattrib--) {
        /* read attribute id and create subtree for attribute */
        attrib_id = tvb_get_guint8(tvb, offset+1);
        sstp_tree_attribute = proto_tree_add_subtree_format(sstp_tree, tvb, offset, SSTP_FSIZE_ATTRIB_RESERVED, ett_sstp_attribute,
            NULL, "Attribute %s", val_to_str(attrib_id, sstp_attributes, "Unknown Attribute"));
        proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_reserved, tvb, offset, SSTP_FSIZE_ATTRIB_RESERVED, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_id, tvb, offset, SSTP_FSIZE_ATTRIB_ID, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_length_reserved, tvb, offset, SSTP_FSIZE_ATTRIB_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_length, tvb, offset, SSTP_FSIZE_ATTRIB_LENGTH, ENC_BIG_ENDIAN);

        /* get length of attribute value */
        attrib_length = (tvb_get_ntohs(tvb, offset) & SSTP_BITMASK_LENGTH_LENGTH);

        /* if this attribute follows the specification, length should at least be 4 */
        if (attrib_length >= 4) {
          /* length field also contains the previously processed 4 bytes */
          attrib_length -= 4;
        }
        offset += 2;

        /* attributes that need special treatment... */
        switch(attrib_id) {

          case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_ecapsulated_protocol, tvb, offset, SSTP_FSIZE_ENCAPSULATED_PROTOCOL, ENC_BIG_ENDIAN);
            offset += SSTP_FSIZE_ENCAPSULATED_PROTOCOL;
          break;

          case SSTP_ATTRIB_STATUS_INFO:
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_reserved, tvb, offset, SSTP_FSIZE_RESERVED2, ENC_NA);
            offset += SSTP_FSIZE_RESERVED2;
            attrib_length -= SSTP_FSIZE_RESERVED2;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_id, tvb, offset, SSTP_FSIZE_ATTRIB_ID, ENC_BIG_ENDIAN);
            offset += SSTP_FSIZE_ATTRIB_ID;
            attrib_length -= SSTP_FSIZE_ATTRIB_ID;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_status, tvb, offset, SSTP_FSIZE_STATUS, ENC_BIG_ENDIAN);
            offset += SSTP_FSIZE_STATUS;
            attrib_length -= SSTP_FSIZE_STATUS;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_attrib_value, tvb, offset, attrib_length, ENC_NA);
            offset += attrib_length;
          break;

          case SSTP_ATTRIB_CRYPTO_BINDING:
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_reserved, tvb, offset, SSTP_FSIZE_RESERVED2, ENC_NA);
            offset += SSTP_FSIZE_RESERVED2;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_hash_protocol, tvb, offset, SSTP_FSIZE_HASH_PROTOCOL, ENC_BIG_ENDIAN);
            hashproto = tvb_get_guint8(tvb, offset);
            offset += SSTP_FSIZE_HASH_PROTOCOL;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_nonce, tvb, offset, SSTP_FSIZE_NONCE, ENC_NA);
            offset += SSTP_FSIZE_NONCE;

            if (hashproto == SSTP_CERT_HASH_PROTOCOL_SHA1) {
              proto_tree_add_item(sstp_tree_attribute, hf_sstp_cert_hash, tvb, offset, SSTP_FSIZE_CERT_HASH_SHA1, ENC_NA);
              offset += SSTP_FSIZE_CERT_HASH_SHA1;
              proto_tree_add_item(sstp_tree_attribute, hf_sstp_padding, tvb, offset, SSTP_FSIZE_PADDING_SHA1, ENC_NA);
              offset += SSTP_FSIZE_PADDING_SHA1;
              proto_tree_add_item(sstp_tree_attribute, hf_sstp_compound_mac, tvb, offset, SSTP_FSIZE_COMPOUND_MAC_SHA1, ENC_NA);
              offset += SSTP_FSIZE_COMPOUND_MAC_SHA1;
              proto_tree_add_item(sstp_tree_attribute, hf_sstp_padding, tvb, offset, SSTP_FSIZE_PADDING_SHA1, ENC_NA);
              offset += SSTP_FSIZE_PADDING_SHA1;
            }

            if (hashproto == SSTP_CERT_HASH_PROTOCOL_SHA256) {
              proto_tree_add_item(sstp_tree_attribute, hf_sstp_cert_hash, tvb, offset, SSTP_FSIZE_CERT_HASH_SHA256, ENC_NA);
              offset += SSTP_FSIZE_CERT_HASH_SHA256;
            }
          break;

          case SSTP_ATTRIB_CRYPTO_BINDING_REQ:
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_reserved, tvb, offset, SSTP_FSIZE_RESERVED2, ENC_NA);
            offset += SSTP_FSIZE_RESERVED2;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_hash_protocol, tvb, offset, SSTP_FSIZE_HASH_PROTOCOL, ENC_BIG_ENDIAN);
            offset += SSTP_FSIZE_HASH_PROTOCOL;
            proto_tree_add_item(sstp_tree_attribute, hf_sstp_nonce, tvb, offset, SSTP_FSIZE_NONCE, ENC_NA);
            offset += SSTP_FSIZE_NONCE;
          break;
        }
      }
    }

    /* While testing with different dumps, i noticed data in the buffer i couldnt find any documentation about */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_item(sstp_tree, hf_sstp_data_unknown, tvb, offset, -1, ENC_NA);
    }

  } else {
    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: DATA; ");
    /* our work here is done, since sstp encapsulates ppp, we hand the remaining buffer
       over to the ppp dissector for further analysis */
    tvb_next = tvb_new_subset_remaining(tvb, SSTP_OFFSET_DATA);
    call_dissector(ppp_handle, tvb_next, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

static guint
get_sstp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  return tvb_get_ntohs(tvb, offset+SSTP_OFFSET_LENGTH);
}

static int
dissect_sstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, SSTP_OFFSET_LENGTH+SSTP_FSIZE_LENGTH, get_sstp_pdu_len, dissect_sstp_pdu, data);
  return tvb_captured_length(tvb);
}

void
proto_register_sstp(void)
{
  /* Setting up header data structure */
  static hf_register_info hf[] = {
    /* sstp minor version (4 Bit) */
    { &hf_sstp_major,
      { "Major Version", "sstp.majorversion",
      FT_UINT8, BASE_DEC,
      NULL, SSTP_BITMASK_MAJORVERSION,
      NULL, HFILL }
    },
    /* sstp major version (4 Bit) */
    { &hf_sstp_minor,
      { "Minor Version", "sstp.minorversion",
      FT_UINT8, BASE_DEC,
      NULL, SSTP_BITMASK_MINORVERSION,
      NULL, HFILL }
    },
    /* Several Reserved Fields with different size */
    { &hf_sstp_reserved,
      { "Reserved", "sstp.reserved",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* C (1 Bit, set to 1 if control packet, 0 means data packet) */
    { &hf_sstp_control_flag,
      { "Control Packet", "sstp.iscontrol",
      FT_BOOLEAN, 8,
      NULL, SSTP_BITMASK_CONTROLFLAG,
      NULL, HFILL }
    },
    /* Length Packet (16 Bit) */
    { &hf_sstp_length,
      { "Length-Packet", "sstp.length",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Message Type (16 Bit) */
    { &hf_sstp_messagetype,
      { "Message Type", "sstp.messagetype",
      FT_UINT16, BASE_HEX,
      VALS(sstp_messagetypes), 0x0,
      NULL, HFILL }
    },
    /* Number of Attributes (16 Bit) */
    { &hf_sstp_numattrib,
      { "Number of Attributes", "sstp.numattrib",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Fields for Attributes */
    /* Attribute Reserved Field (8 Bit) */
    { &hf_sstp_attrib_reserved,
      { "Reserved", "sstp.attribreserved",
      FT_UINT8, BASE_HEX,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Attribute ID (8 Bit) */
    { &hf_sstp_attrib_id,
      { "ID", "sstp.attribid",
      FT_UINT8, BASE_DEC,
      VALS(sstp_attributes), 0x0,
      NULL, HFILL }
    },
    /* Attribute Length Reserved (4 Bit reserved for future use inside the 16 bit length field) */
    { &hf_sstp_attrib_length_reserved,
      { "Reserved", "sstp.attriblengthreserved",
      FT_UINT16, BASE_HEX,
      NULL, SSTP_BITMASK_LENGTH_RESERVED,
      NULL, HFILL }
    },
    /* Attribute Length Actual Length (12 Bit) */
    { &hf_sstp_attrib_length,
      { "Length", "sstp.attriblength",
      FT_UINT16, BASE_DEC,
      NULL, SSTP_BITMASK_LENGTH_LENGTH,
      NULL, HFILL }
    },
    /* Undocumented Data in SSTP_MSG_CALL_CONNECT_REQUEST
       see also: http://msdn.microsoft.com/en-us/library/cc247340.aspx */
    { &hf_sstp_data_unknown,
      { "Unknown Data", "sstp.dataunknown",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Hash Protocol (8 Bit) */
    { &hf_sstp_hash_protocol,
      { "Hash Protocol", "sstp.hash",
      FT_UINT8, BASE_HEX,
      VALS(hash_protocols), 0x0,
      NULL, HFILL }
    },
    /* Nonce (256 Bit) */
    { &hf_sstp_nonce,
      { "Nonce", "sstp.nonce",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Cert Hash (20 Bytes if SHA1 is used, 32 Bytes with SHA256) */
    { &hf_sstp_cert_hash,
      { "Cert Hash", "sstp.cert_hash",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Cert Padding (0 Bytes if SHA256 is used, 12 Bytes with SHA1) */
    { &hf_sstp_padding,
      { "Padding", "sstp.padding",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Compound MAC (20 Bytes if SHA1 is used, 32 Bytes with SHA1) */
    { &hf_sstp_compound_mac,
      { "Compound Mac", "sstp.compoundmac",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    /* Encapsulated Protocol (2 Bytes) */
    { &hf_sstp_ecapsulated_protocol,
      { "Encapsulated Procotol", "sstp.encapsulatedprotocol",
      FT_UINT16, BASE_HEX,
      VALS(encapsulated_protocols), 0x0,
      NULL, HFILL }
    },
    /* Attribute Status (4 Bytes) */
    { &hf_sstp_status,
      { "Status", "sstp.status",
      FT_UINT32, BASE_HEX,
      VALS(attrib_status), 0x0,
      NULL, HFILL }
    },
    /* Attribute Value (Variable Length) */
    { &hf_sstp_attrib_value,
      { "Attribute Value", "sstp.attribvalue",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sstp,
    &ett_sstp_attribute,
    &ett_sstp_version
  };

  proto_sstp = proto_register_protocol("Secure Socket Tunneling Protocol", "SSTP", "sstp");

  register_dissector("sstp", dissect_sstp, proto_sstp);
  proto_register_field_array(proto_sstp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sstp(void)
{
  ppp_handle = find_dissector_add_dependency("ppp", proto_sstp);
}

/*
* Editor modelines  -  http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 2
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=2 tabstop=8 expandtab:
* :indentSize=2:tabSize=8:noTabs=true:
*/
