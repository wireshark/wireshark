/* packet-fc-sp.c
 * Routines for Fibre Channel Security Protocol (FC-SP)
 * This decoder is for FC-SP version 1.1
 * Copyright 2003, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include "packet-fc.h"

/* Message Codes */
#define FC_AUTH_MSG_AUTH_REJECT        0x0A 
#define FC_AUTH_MSG_AUTH_NEGOTIATE     0x0B 
#define FC_AUTH_MSG_AUTH_DONE          0x0C 
#define FC_AUTH_DHCHAP_CHALLENGE       0x10 
#define FC_AUTH_DHCHAP_REPLY           0x11 
#define FC_AUTH_DHCHAP_SUCCESS         0x12 
#define FC_AUTH_FCAP_REQUEST           0x13 
#define FC_AUTH_FCAP_ACKNOWLEDGE       0x14 
#define FC_AUTH_FCAP_CONFIRM           0x15 
#define FC_AUTH_FCPAP_INIT             0x16 
#define FC_AUTH_FCPAP_ACCEPT           0x17 
#define FC_AUTH_FCPAP_COMPLETE         0x18

#define FC_AUTH_NAME_TYPE_WWN          0x1

#define FC_AUTH_PROTO_TYPE_DHCHAP      0x1
#define FC_AUTH_PROTO_TYPE_FCAP        0x2

#define FC_AUTH_DHCHAP_HASH_MD5        0x5
#define FC_AUTH_DHCHAP_HASH_SHA1       0x6

#define FC_AUTH_DHCHAP_PARAM_HASHLIST  0x1
#define FC_AUTH_DHCHAP_PARAM_DHgIDLIST 0x2

/* Initialize the protocol and registered fields */
static int proto_fcsp              = -1;
static int hf_auth_proto_ver       = -1;
static int hf_auth_msg_code        = -1;
static int hf_auth_flags           = -1;
static int hf_auth_len             = -1;
static int hf_auth_tid             = -1;
static int hf_auth_initiator_wwn   = -1;
static int hf_auth_initiator_name  = -1;
static int hf_auth_usable_proto    = -1;
static int hf_auth_rjt_code        = -1;
static int hf_auth_rjt_codedet     = -1;
static int hf_auth_responder_wwn   = -1;
static int hf_auth_responder_name  = -1;
static int hf_auth_dhchap_groupid  = -1;
static int hf_auth_dhchap_hashid   = -1;
static int hf_auth_dhchap_chal_len = -1;
static int hf_auth_dhchap_val_len  = -1;
static int hf_auth_dhchap_rsp_len  = -1;
static int hf_auth_initiator_name_type = -1;
static int hf_auth_initiator_name_len = -1;
static int hf_auth_responder_name_len = -1;
static int hf_auth_responder_name_type = -1;
static int hf_auth_proto_type = -1;
static int hf_auth_proto_param_len = -1;
static int hf_auth_dhchap_param_tag = -1;
static int hf_auth_dhchap_param_len = -1;
static int hf_auth_dhchap_hash_type = -1;
static int hf_auth_dhchap_group_type = -1;
static int hf_auth_dhchap_dhvalue = -1;
static int hf_auth_dhchap_chal_value = -1;
static int hf_auth_dhchap_rsp_value = -1;

/* Initialize the subtree pointers */
static gint ett_fcsp = -1;

static dissector_handle_t data_handle;

static const value_string fcauth_msgcode_vals[] = {
    {FC_AUTH_MSG_AUTH_REJECT, "AUTH_Reject"},
    {FC_AUTH_MSG_AUTH_NEGOTIATE, "AUTH_Negotiate"},
    {FC_AUTH_MSG_AUTH_DONE, "AUTH_Done"},
    {FC_AUTH_DHCHAP_CHALLENGE, "DHCHAP_Challenge"},
    {FC_AUTH_DHCHAP_REPLY, "DHCHAP_Reply"},
    {FC_AUTH_DHCHAP_SUCCESS, "DHCHAP_Success"},
    {FC_AUTH_FCAP_REQUEST, "FCAP_Request"},
    {FC_AUTH_FCAP_ACKNOWLEDGE, "FCAP_Acknowledge"},
    {FC_AUTH_FCAP_CONFIRM, "FCAP_Confirm"},
    {FC_AUTH_FCPAP_INIT, "FCPAP_Init"},
    {FC_AUTH_FCPAP_ACCEPT, "FCPAP_Accept"},
    {FC_AUTH_FCPAP_COMPLETE, "FCPAP_Complete"},
    {0, NULL},
};

static const value_string fcauth_rjtcode_vals[] = {
    {0x01, "Authentication Failure"},
    {0x02, "Logical Error"},
    {0, NULL},
};

static const value_string fcauth_rjtcode_detail_vals[] = {
    {0x01, "Authentication Mechanism Not Usable"},
    {0x02, "DH Group Not Usable"},
    {0x03, "Hash Algorithm Not Usable"},
    {0x04, "Authentication Protocol Instance Already Started"},
    {0x05, "Authentication Failed "},
    {0x06, "Incorrect Payload "},
    {0x07, "Incorrect Authentication Protocol Message"},
    {0x08, "Protocol Reset"},
    {0, NULL},
};

static const value_string fcauth_dhchap_param_vals[] = {
    {FC_AUTH_DHCHAP_PARAM_HASHLIST, "HashList"},
    {FC_AUTH_DHCHAP_PARAM_DHgIDLIST, "DHgIDList"},
    {0, NULL},
};

static const value_string fcauth_dhchap_hash_algo_vals[] = {
    {FC_AUTH_DHCHAP_HASH_MD5, "MD5"},
    {FC_AUTH_DHCHAP_HASH_SHA1, "SHA-1"},
    {0, NULL},
};

static const value_string fcauth_name_type_vals[] = {
    {FC_AUTH_NAME_TYPE_WWN, "WWN"},
    {0, NULL},
};

static const value_string fcauth_proto_type_vals[] = {
    {FC_AUTH_PROTO_TYPE_DHCHAP, "DHCHAP"},
    {FC_AUTH_PROTO_TYPE_FCAP, "FCAP"},
    {0, NULL},
};

static const value_string fcauth_dhchap_dhgid_vals[] = {
    {0, "DH NULL"},
    {1, "DH Group 1024"},
    {2, "DH Group 1280"},
    {3, "DH Group 1536"},
    {4, "DH Group 2048"},
    {0, NULL},
};

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

static void dissect_fcsp_dhchap_auth_param (tvbuff_t *tvb, proto_tree *tree,
                                     int offset, gint32 total_len)
{
    guint16 auth_param_tag;
    guint16 param_len = 0, i;
    
    if (tree) {
        auth_param_tag = tvb_get_ntohs (tvb, offset);
        total_len -= 4;
        
        while (total_len > 0) {
            proto_tree_add_item (tree, hf_auth_dhchap_param_tag, tvb, offset,
                                 2, 0);
            proto_tree_add_item (tree, hf_auth_dhchap_param_len, tvb, offset+2,
                                 2, 0);

            auth_param_tag = tvb_get_ntohs (tvb, offset);
            param_len = tvb_get_ntohs (tvb, offset+2)*4;

            switch (auth_param_tag) {
            case FC_AUTH_DHCHAP_PARAM_HASHLIST:
                offset += 4;
                total_len -= 4;
                for (i = 0; i < param_len; i += 4) {
                    proto_tree_add_item (tree, hf_auth_dhchap_hash_type, tvb,
                                         offset, 4, 0);
                    offset += 4;
                }
                break;
            case FC_AUTH_DHCHAP_PARAM_DHgIDLIST:
                offset += 4;
                total_len -= 4;
                for (i = 0; i < param_len; i += 4) {
                    proto_tree_add_item (tree, hf_auth_dhchap_group_type, tvb,
                                         offset, 4, 0);
                    offset += 4;
                }
                break;
            default:
                break;
            }

            total_len -= param_len;
        }
    }
}

static void dissect_fcsp_dhchap_challenge (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 12;
    guint16 name_type;
    guint16 param_len, name_len;
    
    if (tree) {
        proto_tree_add_item (tree, hf_auth_responder_name_type, tvb, offset,
                             2, 0);
        name_type = tvb_get_ntohs (tvb, offset);

        proto_tree_add_item (tree, hf_auth_responder_name_len, tvb, offset+2,
                             2, 0);

        name_len = tvb_get_ntohs (tvb, offset+2);
        
        if (name_type == FC_AUTH_NAME_TYPE_WWN) {
            proto_tree_add_string (tree, hf_auth_responder_wwn, tvb, offset+4,
                                   8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+4,
                                                              8)));
        }
        else {
            proto_tree_add_bytes (tree, hf_auth_responder_name, tvb, offset+4,
                                  name_len, tvb_get_ptr (tvb, offset+4, name_len));
        }
        offset += (4+name_len);
        
        proto_tree_add_item (tree, hf_auth_dhchap_hash_type, tvb, offset,
                             4, 0);
        proto_tree_add_item (tree, hf_auth_dhchap_group_type, tvb, offset+4,
                             4, 0);
        proto_tree_add_item (tree, hf_auth_dhchap_chal_len, tvb, offset+8,
                             4, 0);
        param_len = tvb_get_ntohl (tvb, offset+8);
        
        proto_tree_add_bytes (tree, hf_auth_dhchap_chal_value, tvb, offset+12,
                              param_len,
                              tvb_get_ptr (tvb, offset+12, param_len));
        offset += (param_len + 12);

        proto_tree_add_item (tree, hf_auth_dhchap_val_len, tvb, offset, 4, 0);
        param_len = tvb_get_ntohl (tvb, offset);
        
        proto_tree_add_bytes (tree, hf_auth_dhchap_dhvalue, tvb, offset+4,
                              param_len,
                              tvb_get_ptr (tvb, offset+4, param_len));
    }
}


static void dissect_fcsp_dhchap_reply (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 12;
    guint32 param_len;
    
    if (tree) {
        proto_tree_add_item (tree, hf_auth_dhchap_rsp_len, tvb, offset, 4, 0);
        param_len = tvb_get_ntohl (tvb, offset);

        proto_tree_add_bytes (tree, hf_auth_dhchap_rsp_value, tvb, offset+4,
                              param_len,
                              tvb_get_ptr (tvb, offset+4, param_len));
        offset += (param_len + 4);

        proto_tree_add_item (tree, hf_auth_dhchap_val_len, tvb, offset, 4, 0);
        param_len = tvb_get_ntohl (tvb, offset);

        proto_tree_add_bytes (tree, hf_auth_dhchap_dhvalue, tvb, offset+4,
                              param_len,
                              tvb_get_ptr (tvb, offset+4, param_len));
        offset += (param_len + 4);

        proto_tree_add_item (tree, hf_auth_dhchap_chal_len, tvb, offset, 4, 0);
        param_len = tvb_get_ntohl (tvb, offset);

        proto_tree_add_bytes (tree, hf_auth_dhchap_chal_value, tvb, offset+4,
                              param_len,
                              tvb_get_ptr (tvb, offset+4, param_len));
    }
}

static void dissect_fcsp_dhchap_success (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 12;
    guint32 param_len;
    
    if (tree) {
        proto_tree_add_item (tree, hf_auth_dhchap_rsp_len, tvb, offset, 4, 0);
        param_len = tvb_get_ntohl (tvb, offset);

        proto_tree_add_bytes (tree, hf_auth_dhchap_rsp_value, tvb, offset+4,
                              param_len,
                              tvb_get_ptr (tvb, offset+4, param_len));
    }
}


static void dissect_fcsp_auth_negotiate (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 12;
    guint16 name_type, name_len, proto_type, param_len;
    guint32 num_protos, i;

    if (tree) {
        proto_tree_add_item (tree, hf_auth_initiator_name_type, tvb, offset,
                             2, 0);
        name_type = tvb_get_ntohs (tvb, offset);

        proto_tree_add_item (tree, hf_auth_initiator_name_len, tvb, offset+2,
                             2, 0);
        name_len = tvb_get_ntohs (tvb, offset+2);

        if (name_type == FC_AUTH_NAME_TYPE_WWN) {
            proto_tree_add_string (tree, hf_auth_initiator_wwn, tvb, offset+4, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+4, 8)));
        }
        else {
            proto_tree_add_bytes (tree, hf_auth_initiator_name, tvb, offset+4,
                                  name_len, tvb_get_ptr (tvb, offset+4,
                                                         name_len));
        }

        offset += (4+name_len);

        proto_tree_add_item (tree, hf_auth_usable_proto, tvb, offset, 4, 0);
        num_protos = tvb_get_ntohl (tvb, offset);
        offset += 4;
        
        for (i = 0; i < num_protos; i++) {
            proto_tree_add_item (tree, hf_auth_proto_param_len, tvb, offset, 4, 0);
            param_len = tvb_get_ntohl (tvb, offset);
            offset += 4;
            
            if (tvb_bytes_exist (tvb, offset, param_len)) {
                proto_type = tvb_get_ntohl (tvb, offset);

                proto_tree_add_item (tree, hf_auth_proto_type, tvb, offset, 4, 0);
                switch (proto_type) {
                case FC_AUTH_PROTO_TYPE_DHCHAP:
                    dissect_fcsp_dhchap_auth_param (tvb, tree, offset+4, param_len);
                    break;
                case FC_AUTH_PROTO_TYPE_FCAP:
                    break;
                default:
                    break;
                }
            }
            offset += param_len;
        }
    }
}

static void dissect_fcsp_auth_done (tvbuff_t *tvb _U_, proto_tree *tree _U_)
{
}

static void dissect_fcsp_auth_rjt (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 12;
    
    if (tree) {
        proto_tree_add_item (tree, hf_auth_rjt_code, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_auth_rjt_codedet, tvb, offset+1, 1, 0);
    }
}

static void dissect_fcsp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    guint8 opcode;
    int offset = 0;
    proto_tree *fcsp_tree = NULL;

    /* Make entry in the Info column on summary display */
    opcode = tvb_get_guint8 (tvb, 2);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_set_str (pinfo->cinfo, COL_INFO,
                     val_to_str (opcode, fcauth_msgcode_vals, "0x%x"));
    }
    
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fcsp, tvb, 0,
                                             tvb_length (tvb), "FC-SP");
        fcsp_tree = proto_item_add_subtree (ti, ett_fcsp);

        proto_tree_add_item (fcsp_tree, hf_auth_flags, tvb, offset+1, 1, 0);
        proto_tree_add_item (fcsp_tree, hf_auth_msg_code, tvb, offset+2, 1, 0);
        proto_tree_add_item (fcsp_tree, hf_auth_proto_ver, tvb, offset+3, 1,
                             0);
        proto_tree_add_item (fcsp_tree, hf_auth_len, tvb, offset+4, 4, 0);
        proto_tree_add_item (fcsp_tree, hf_auth_tid, tvb, offset+8, 4, 0);

        switch (opcode) {
        case FC_AUTH_MSG_AUTH_REJECT:
            dissect_fcsp_auth_rjt (tvb, tree);
            break;
        case FC_AUTH_MSG_AUTH_NEGOTIATE:
            dissect_fcsp_auth_negotiate (tvb, tree);
            break;
        case FC_AUTH_MSG_AUTH_DONE:
            dissect_fcsp_auth_done (tvb, tree);
            break;
        case FC_AUTH_DHCHAP_CHALLENGE:
            dissect_fcsp_dhchap_challenge (tvb, tree);
            break;
        case FC_AUTH_DHCHAP_REPLY:
            dissect_fcsp_dhchap_reply (tvb, tree);
            break;
        case FC_AUTH_DHCHAP_SUCCESS:
            dissect_fcsp_dhchap_success (tvb, tree);
            break;
        case FC_AUTH_FCAP_REQUEST:
        case FC_AUTH_FCAP_ACKNOWLEDGE:
        case FC_AUTH_FCAP_CONFIRM:
        case FC_AUTH_FCPAP_INIT:
        case FC_AUTH_FCPAP_ACCEPT:
        case FC_AUTH_FCPAP_COMPLETE:
            proto_tree_add_text (fcsp_tree, tvb, offset+12, tvb_length (tvb),
                                 "FCAP Decoding Not Supported");
            break;
        default:
            break;
        }
    }
}

void
proto_register_fcsp (void)
{                 
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_auth_proto_ver,
          {"Protocol Version", "fcsp.version", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_auth_msg_code,
          {"Message Code", "fcsp.opcode", FT_UINT8, BASE_HEX,
           VALS (fcauth_msgcode_vals), 0x0, "", HFILL}},
        { &hf_auth_flags,
          {"Flags", "fcsp.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_auth_len,
          {"Packet Length", "fcsp.len", FT_UINT32, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_auth_tid,
          {"Transaction Identifier", "fcsp.tid", FT_UINT32, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_auth_initiator_wwn,
          {"Initiator Name (WWN)", "fcsp.initwwn", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_auth_initiator_name,
          {"Initiator Name (Unknown Type)", "fcsp.initname", FT_BYTES,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_auth_initiator_name_type,
          {"Initiator Name Type", "fcsp.initnametype", FT_UINT16, BASE_HEX,
           VALS (fcauth_name_type_vals), 0x0, "", HFILL}},
        { &hf_auth_initiator_name_len,
          {"Initiator Name Length", "fcsp.initnamelen", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_usable_proto,
          {"Number of Usable Protocols", "fcsp.usableproto", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_auth_rjt_code,
          {"Reason Code", "fcsp.rjtcode", FT_UINT8, BASE_DEC,
           VALS (fcauth_rjtcode_vals), 0x0, "", HFILL}},
        { &hf_auth_rjt_codedet,
          {"Reason Code Explanation", "fcsp.rjtcodet", FT_UINT8, BASE_DEC,
           VALS (fcauth_rjtcode_detail_vals), 0x0, "", HFILL}},
        { &hf_auth_responder_wwn,
          {"Responder Name (WWN)", "fcsp.rspwwn", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_auth_responder_name,
          {"Responder Name (Unknown Type)", "fcsp.rspname", FT_BYTES, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_responder_name_type,
          {"Responder Name Type", "fcsp.rspnametype", FT_UINT16, BASE_HEX,
           VALS (fcauth_name_type_vals), 0x0, "", HFILL}},
        { &hf_auth_responder_name_len,
          {"Responder Name Type", "fcsp.rspnamelen", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_dhchap_hashid,
          {"Hash Identifier", "fcsp.dhchap.hashid", FT_UINT32, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_auth_dhchap_groupid,
          {"DH Group Identifier", "fcsp.dhchap.groupid", FT_UINT32, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_auth_dhchap_chal_len,
          {"Challenge Value Length", "fcsp.dhchap.challen", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_dhchap_val_len,
          {"DH Value Length", "fcsp.dhchap.vallen", FT_UINT32, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_auth_dhchap_rsp_len,
          {"Response Value Length", "fcsp.dhchap.rsplen", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_proto_type,
          {"Authentication Protocol Type", "fcsp.proto", FT_UINT32, BASE_DEC,
           VALS (fcauth_proto_type_vals), 0x0, "", HFILL}},
        { &hf_auth_proto_param_len,
          {"Protocol Parameters Length", "fcsp.protoparamlen", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_auth_dhchap_param_tag,
          {"Parameter Tag", "fcsp.dhchap.paramtype", FT_UINT16, BASE_HEX,
           VALS (fcauth_dhchap_param_vals), 0x0, "", HFILL}},
        { &hf_auth_dhchap_param_len,
          {"Parameter Length", "fcsp.dhchap.paramlen", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_dhchap_hash_type,
          {"Hash Algorithm", "fcsp.dhchap.hashtype", FT_UINT32, BASE_DEC,
           VALS (fcauth_dhchap_hash_algo_vals), 0x0, "", HFILL}},
        { &hf_auth_dhchap_group_type,
          {"DH Group", "fcsp.dhchap.dhgid", FT_UINT32, BASE_DEC,
           VALS (fcauth_dhchap_dhgid_vals), 0x0, "", HFILL}},
        { &hf_auth_dhchap_chal_value,
          {"Challenge Value", "fcsp.dhchap.chalval", FT_BYTES, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_auth_dhchap_dhvalue,
          {"DH Value", "fcsp.dhchap.dhvalue", FT_BYTES, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_auth_dhchap_rsp_value,
          {"Response Value", "fcsp.dhchap.rspval", FT_BYTES, BASE_HEX, NULL,
           0x0, "", HFILL}},
          
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fcsp,
    };

    /* Register the protocol name and description */
    proto_fcsp = proto_register_protocol ("Fibre Channel Security Protocol",
                                           "FC-SP", "fcsp");

    register_dissector("fcsp", dissect_fcsp, proto_fcsp);
    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fcsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    data_handle = find_dissector("data");
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fcsp (void)
{
    dissector_handle_t fcsp_handle;

    fcsp_handle = create_dissector_handle (dissect_fcsp, proto_fcsp);

    data_handle = find_dissector ("data");
}

