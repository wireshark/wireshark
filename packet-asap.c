/* packet-asap.c
 * Routines for Aggregate Server Access Protocol
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-rserpool-asap-02.txt
 *
 * Copyright 2002, Michael Tuexen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-asap.c,v 1.3 2002/05/02 07:49:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <epan/packet.h>

#define ASAP_PAYLOAD_PROTO_ID 0xFAEEB5D1

/* Initialize the protocol and registered fields */
static int proto_asap = -1;
static int hf_asap_message_type = -1;
static int hf_asap_message_flags = -1;
static int hf_asap_message_length = -1;
#ifdef ASAP_UNUSED_HANDLES
static int hf_asap_message_value = -1;
#endif
static int hf_asap_parameter_type = -1;
static int hf_asap_parameter_length = -1;
static int hf_asap_parameter_value = -1;
static int hf_asap_parameter_padding = -1;
static int hf_asap_parameter_ipv4_address = -1;
static int hf_asap_parameter_ipv6_address = -1;
static int hf_asap_parameter_port = -1;
static int hf_asap_parameter_number_of_addr = -1;
static int hf_asap_parameter_load_policy = -1;
static int hf_asap_parameter_load_value = -1;
static int hf_asap_parameter_reg_life = -1;
static int hf_asap_parameter_pool_handle = -1;
static int hf_asap_parameter_signature = -1;
static int hf_asap_parameter_action_code = -1;
static int hf_asap_parameter_result_code = -1;
static int hf_asap_parameter_reserved = -1;

/* Initialize the subtree pointers */
static gint ett_asap = -1;
static gint ett_asap_parameter = -1;

static void
dissect_all_asap_parameters(tvbuff_t *, proto_tree *);

static gint
dissect_next_asap_parameters(guint, gint, tvbuff_t *, proto_tree *);

static guint 
nr_of_padding_bytes (guint length)
{
  guint remainder;

  remainder = length % 4;

  if (remainder == 0)
    return 0;
  else
    return 4 - remainder;
}

#define PARAMETER_TYPE_LENGTH   2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET 0
#define PARAMETER_TYPE_OFFSET   PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 ipv4_address;

  tvb_memcpy(parameter_tvb, (guint8 *)&ipv4_address, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH); 
  proto_tree_add_ipv4(parameter_tree, hf_asap_parameter_ipv4_address, parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH, ipv4_address);  
  proto_item_set_text(parameter_item, "IPV4 address parameter");
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_ipv6(parameter_tree, hf_asap_parameter_ipv6_address, parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH,
		              tvb_get_ptr(parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH));
  
  proto_item_set_text(parameter_item, "IPV6 address parameter");
}

#define PORT_LENGTH                2
#define NUMBER_OF_ADDRESSES_LENGTH 2
#define LOAD_POLICY_LENGTH         2
#define LOAD_VALUE_LENGTH          2
#define REGISTRATION_LIFE_LENGTH   4

#define PORT_OFFSET                PARAMETER_VALUE_OFFSET
#define NUMBER_OF_ADDRESSES_OFFSET (PORT_OFFSET + PORT_LENGTH)
#define ADDRESS_LIST_OFFSET        (NUMBER_OF_ADDRESSES_OFFSET + NUMBER_OF_ADDRESSES_LENGTH)
#define LOAD_POLICY_OFFSET         0
#define LOAD_VALUE_OFFSET          (LOAD_POLICY_OFFSET + LOAD_POLICY_LENGTH)
#define REGISTRATION_LIFE_OFFSET   (LOAD_VALUE_OFFSET + LOAD_VALUE_LENGTH)

static void
dissect_pool_element_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 port, number_of_addresses, load_policy, load_value;
  guint32 reg_life;
  gint offset;
  
  port                = tvb_get_ntohs(parameter_tvb, PORT_OFFSET);
  number_of_addresses = tvb_get_ntohs(parameter_tvb, NUMBER_OF_ADDRESSES_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_port, parameter_tvb, PORT_OFFSET, PORT_LENGTH, port);
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_number_of_addr, parameter_tvb, NUMBER_OF_ADDRESSES_OFFSET, NUMBER_OF_ADDRESSES_LENGTH, number_of_addresses);

  offset              = dissect_next_asap_parameters(number_of_addresses, ADDRESS_LIST_OFFSET, parameter_tvb, parameter_tree);  
  load_policy         = tvb_get_ntohs(parameter_tvb, offset + LOAD_POLICY_OFFSET);
  load_value          = tvb_get_ntohs(parameter_tvb, offset + LOAD_VALUE_OFFSET);
  reg_life            = tvb_get_ntohs(parameter_tvb, offset + REGISTRATION_LIFE_OFFSET);
  
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_load_policy, parameter_tvb, offset + LOAD_POLICY_OFFSET, LOAD_POLICY_LENGTH, load_policy);
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_load_value, parameter_tvb, offset + LOAD_VALUE_OFFSET, LOAD_VALUE_LENGTH, load_value);
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_reg_life, parameter_tvb, offset + REGISTRATION_LIFE_OFFSET, REGISTRATION_LIFE_LENGTH, reg_life);
  proto_item_set_text(parameter_item, "Pool element");

}

#define POOL_HANDLE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pool_handle_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, handle_length;
  char *handle;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  handle_length = length - PARAMETER_HEADER_LENGTH;
  handle        = (char *)tvb_get_ptr(parameter_tvb, POOL_HANDLE_OFFSET, handle_length);
  proto_tree_add_string(parameter_tree, hf_asap_parameter_pool_handle, parameter_tvb, POOL_HANDLE_OFFSET, handle_length, handle);
  proto_item_set_text(parameter_item, "Pool handle (%.*s)", handle_length, handle);
}

#define SIGNATURE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_authorization_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, signature_length;
  
  length           = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  signature_length = length - PARAMETER_HEADER_LENGTH;

  if (signature_length > 0) 
    proto_tree_add_bytes(parameter_tree, hf_asap_parameter_signature, parameter_tvb, SIGNATURE_OFFSET, signature_length,
      	                 tvb_get_ptr(parameter_tvb, SIGNATURE_OFFSET, signature_length));

  proto_item_set_text(parameter_item, "Authorization signature (%u byte%s)", signature_length, plurality(signature_length, "", "s"));
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 type, length, parameter_value_length;
  
  type   = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  if (parameter_value_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_asap_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, 
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length));

  proto_item_set_text(parameter_item, "Parameter with type %u and %u byte%s value", type, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define IPV4_ADDRESS_PARAMETER_TYPE  0x01
#define IPV6_ADDRESS_PARAMETER_TYPE  0x02
#define POOL_ELEMENT_PARAMETER_TYPE  0x03
#define POOL_HANDLE_PARAMETER_TYPE   0x04
#define AUTHORIZATION_PARAMETER_TYPE 0x05

static const value_string asap_parameter_type_values[] = {
  { IPV4_ADDRESS_PARAMETER_TYPE,  "IPV4 address" },
  { IPV6_ADDRESS_PARAMETER_TYPE,  "IPV6 address" },
  { POOL_ELEMENT_PARAMETER_TYPE,  "Pool element" },
  { POOL_HANDLE_PARAMETER_TYPE,   "Pool handle" },
  { AUTHORIZATION_PARAMETER_TYPE, "Authorization parameter" },
  { 0,                            NULL } };


static void
dissect_asap_parameter(tvbuff_t *parameter_tvb, proto_tree *asap_tree)
{
  guint16 type, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = tvb_length(parameter_tvb) - length;
  total_length   = length + padding_length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(asap_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_asap_parameter);

  /* add tag and length to the asap tree */
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_type, parameter_tvb, PARAMETER_TYPE_OFFSET, PARAMETER_TYPE_LENGTH, type);
  proto_tree_add_uint(parameter_tree, hf_asap_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, length);

  switch(type) {
  case IPV4_ADDRESS_PARAMETER_TYPE:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6_ADDRESS_PARAMETER_TYPE:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case POOL_ELEMENT_PARAMETER_TYPE:
    dissect_pool_element_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case POOL_HANDLE_PARAMETER_TYPE:
    dissect_pool_handle_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case AUTHORIZATION_PARAMETER_TYPE:
    dissect_authorization_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_asap_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, 
                         tvb_get_ptr(parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length));
}


static gint
dissect_next_asap_parameters(guint number_of_parameters, gint initial_offset, tvbuff_t *parameters_tvb, proto_tree *asap_tree)
{
  gint offset, length, padding_length, total_length;
  tvbuff_t *parameter_tvb;
  guint parameter_number;

  offset = initial_offset;
  for(parameter_number=1; parameter_number <= number_of_parameters; parameter_number++) {
    length         = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    dissect_asap_parameter(parameter_tvb, asap_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
  return(offset);
}

static void
dissect_all_asap_parameters(tvbuff_t *parameters_tvb, proto_tree *asap_tree)
{
  gint offset, length, padding_length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_reported_length_remaining(parameters_tvb, offset))) {
    length         = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    if (remaining_length >= length)
      total_length = MIN(length + padding_length, remaining_length);
    else
      total_length = length + padding_length;
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    dissect_asap_parameter(parameter_tvb, asap_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

#define ACTION_CODE_LENGTH 1
#define RESULT_CODE_LENGTH 1
#define RESERVED_LENGTH    2

#define ACTION_CODE_OFFSET 0
#define RESULT_CODE_OFFSET (ACTION_CODE_OFFSET + ACTION_CODE_LENGTH)
#define RESERVED_OFFSET    (RESULT_CODE_OFFSET + RESULT_CODE_LENGTH)

static void
dissect_registration_response_message(tvbuff_t *parameters_tvb, proto_tree *asap_tree)
{
  gint offset;
  guint8 action_code, result_code;
  guint16 reserved;
  tvbuff_t *last_parameter_tvb;

  offset      = dissect_next_asap_parameters(2, 0, parameters_tvb, asap_tree);
  action_code = tvb_get_guint8(parameters_tvb, offset + ACTION_CODE_OFFSET);
  result_code = tvb_get_guint8(parameters_tvb, offset + RESULT_CODE_OFFSET);
  reserved    = tvb_get_ntohs(parameters_tvb, offset + RESERVED_OFFSET);
  proto_tree_add_uint(asap_tree, hf_asap_parameter_action_code, parameters_tvb, offset + ACTION_CODE_OFFSET, ACTION_CODE_LENGTH, action_code);
  proto_tree_add_uint(asap_tree, hf_asap_parameter_result_code, parameters_tvb, offset + RESULT_CODE_OFFSET, RESULT_CODE_LENGTH, result_code);
  proto_tree_add_uint(asap_tree, hf_asap_parameter_reserved, parameters_tvb, offset + RESERVED_OFFSET, RESERVED_LENGTH, reserved);

  last_parameter_tvb = tvb_new_subset(parameters_tvb, offset + 4 , -1, -1);
  dissect_all_asap_parameters(last_parameter_tvb, asap_tree);
}

#define MESSAGE_TYPE_LENGTH   1
#define MESSAGE_FLAGS_LENGTH  1
#define MESSAGE_LENGTH_LENGTH 2

#define MESSAGE_TYPE_OFFSET   0
#define MESSAGE_FLAGS_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET (MESSAGE_FLAGS_OFFSET + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_VALUE_OFFSET  (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)

#define REGISTRATION_MESSAGE_TYPE             0x01
#define DEREGISTRATION_MESSAGE_TYPE           0x02
#define REGISTRATION_RESPONSE_MESSAGE_TYPE    0x03
#define NAME_RESOLUTION_MESSAGE_TYPE          0x04
#define NAME_RESOLUTION_RESPONSE_MESSAGE_TYPE 0x05
#define NAME_UNKNOWN_MESSAGE_TYPE             0x06
#define ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE      0x08
#define ENDPOINT_UNREACHABLE_MESSAGE_TYPE     0x09
#define SERVER_HUNT_MESSAGE_TYPE              0x0a
#define SERVER_HUNT_RESPONSE_MESSAGE_TYPE     0x0b

static const value_string asap_message_type_values[] = {
  { REGISTRATION_MESSAGE_TYPE,             "Registration" },
  { DEREGISTRATION_MESSAGE_TYPE,           "Deregistration" },
  { REGISTRATION_RESPONSE_MESSAGE_TYPE,    "Registration response" },
  { NAME_RESOLUTION_MESSAGE_TYPE,          "Name resolution" },
  { NAME_RESOLUTION_RESPONSE_MESSAGE_TYPE, "Name resolution response" },
  { NAME_UNKNOWN_MESSAGE_TYPE,             "Name unknown" },
  { ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE,      "Endpoint keep alive" },
  { ENDPOINT_UNREACHABLE_MESSAGE_TYPE,     "Endpoint unreachable" },
  { SERVER_HUNT_MESSAGE_TYPE,              "Server hunt" },
  { SERVER_HUNT_RESPONSE_MESSAGE_TYPE,     "Server hunt response" },
  { 0,                           NULL } };

static void
dissect_asap_message(tvbuff_t *message_tvb, proto_tree *asap_tree)
{
  tvbuff_t *parameters_tvb;
  guint8  type, flags;
  guint16 length;
  
  type   = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  flags  = tvb_get_guint8(message_tvb, MESSAGE_FLAGS_OFFSET);
  length = tvb_get_ntohs (message_tvb, MESSAGE_LENGTH_OFFSET);

  if (asap_tree) {
    proto_tree_add_uint(asap_tree, hf_asap_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   type);
    proto_tree_add_uint(asap_tree, hf_asap_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  flags);
    proto_tree_add_uint(asap_tree, hf_asap_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, length);
  }
  
  parameters_tvb    = tvb_new_subset(message_tvb, MESSAGE_VALUE_OFFSET, -1, -1);
  switch(type) {
  case REGISTRATION_RESPONSE_MESSAGE_TYPE:
    dissect_registration_response_message(parameters_tvb, asap_tree);
  	break;
  default:
    dissect_all_asap_parameters(parameters_tvb, asap_tree);
    break;
  }
  	
}

static void
dissect_asap(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *asap_item;
  proto_tree *asap_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASAP");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the asap protocol tree */
    asap_item = proto_tree_add_item(tree, proto_asap, message_tvb, 0, -1, FALSE);
    asap_tree = proto_item_add_subtree(asap_item, ett_asap);
  } else {
    asap_tree = NULL;
  };
  /* dissect the message */
  dissect_asap_message(message_tvb, asap_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_asap(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_asap_message_type,
      { "Type", "asap.message_type",
	    FT_UINT8, BASE_DEC, VALS(asap_message_type_values), 0x0,          
        "", HFILL }
    },
    { &hf_asap_message_flags,
      { "Flags", "asap.message_flags",
	    FT_UINT8, BASE_HEX, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_message_length,
      { "Length", "asap.message_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    },
    { &hf_asap_parameter_type,
      { "Parameter Type", "asap.parameter_type",
	    FT_UINT16, BASE_HEX, VALS(asap_parameter_type_values), 0x0,          
	    "", HFILL }
    },
    { &hf_asap_parameter_length,
      { "Parameter length", "asap.message_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_value,
      { "Parameter value", "asap.parameter_value",
	    FT_BYTES, BASE_NONE, NULL, 0x0,          
	    "", HFILL }
    },    
    { &hf_asap_parameter_padding,
      { "Padding", "asap.parameter_padding",
	    FT_BYTES, BASE_NONE, NULL, 0x0,          
	    "", HFILL }
    },    
    {&hf_asap_parameter_ipv4_address,
     { "IP Version 4 address", "asap.ipv4_address",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_asap_parameter_ipv6_address,
     { "IP Version 6 address", "asap.ipv6_address",
       FT_IPv6, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    { &hf_asap_parameter_port,
      { "SCTP port", "asap.message_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_number_of_addr,
      { "Number of IP addresses", "asap.message_number_of_addresses",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_load_policy,
      { "Load policy", "asap.message_load_policy",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_load_value,
      { "Load value", "asap.message_load_value",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_reg_life,
      { "Registration life", "asap.message_registration_life",
        FT_UINT32, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_pool_handle,
      { "Pool handle", "asap.pool_handle",
	    FT_STRING, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_signature,
      { "Signature", "asap.parameter_signature",
	    FT_BYTES, BASE_NONE, NULL, 0x0,          
	    "", HFILL }
	},
    { &hf_asap_parameter_action_code,
      { "Action code", "asap.message_action_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_result_code,
      { "Result code", "asap.message_result_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_asap_parameter_reserved,
      { "Reserved", "asap.message_reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,          
	    "", HFILL }
    }, 
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_asap,
    &ett_asap_parameter,
  };
  
  /* Register the protocol name and description */
  proto_asap = proto_register_protocol("Aggregate Server Access Protocol", "ASAP",  "asap");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_asap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

};

void
proto_reg_handoff_asap(void)
{
  dissector_handle_t asap_handle;
  
  asap_handle = create_dissector_handle(dissect_asap, proto_asap);
  dissector_add("sctp.ppi",  ASAP_PAYLOAD_PROTO_ID, asap_handle);
}
