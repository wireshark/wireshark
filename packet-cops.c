/* packet-cops.c
 * Routines for the COPS (Common Open Policy Service) protocol dissection
 * RFC2748
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-cops.c,v 1.3 2000/08/07 03:20:27 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <glib.h>
#include "packet.h"

#define TCP_PORT_COPS 3288

#define COPS_OBJECT_HDR_SIZE 4

static const value_string cops_flags_vals[] = {
        { 0x00,          "None" },
        { 0x01,          "Solicited Message Flag Bit" },
        { 0, NULL },
};

/* The different COPS message types */
enum cops_op_code {
        COPS_NO_MSG,          /* Not a COPS Message type     */ 

        COPS_MSG_REQ,         /* Request (REQ)               */
        COPS_MSG_DEC,         /* Decision (DEC)              */
        COPS_MSG_RPT,         /* Report State (RPT)          */
        COPS_MSG_DRQ,         /* Delete Request State (DRQ)  */
        COPS_MSG_SSQ,         /* Synchronize State Req (SSQ) */
        COPS_MSG_OPN,         /* Client-Open (OPN)           */
        COPS_MSG_CAT,         /* Client-Accept (CAT)         */
        COPS_MSG_CC,          /* Client-Close (CC)           */
        COPS_MSG_KA,          /* Keep-Alive (KA)             */
        COPS_MSG_SSC,         /* Synchronize Complete (SSC)  */

        COPS_LAST_OP_CODE     /* For error checking          */
};

static const value_string cops_op_code_vals[] = {
        { COPS_MSG_REQ,          "Request (REQ)" },
        { COPS_MSG_DEC,          "Decision (DEC)" },
        { COPS_MSG_RPT,          "Report State (RPT)" },
        { COPS_MSG_DRQ,          "Delete Request State (DRQ)" },
        { COPS_MSG_SSQ,          "Synchronize State Req (SSQ)" },
        { COPS_MSG_OPN,          "Client-Open (OPN)" },
        { COPS_MSG_CAT,          "Client-Accept (CAT)" },
        { COPS_MSG_CC,           "Client-Close (CC)" },
        { COPS_MSG_KA,           "Keep-Alive (KA)" },
        { COPS_MSG_SSC,          "Synchronize Complete (SSC)" },
        { 0, NULL },
};


/* The different objects in COPS messages */
enum cops_c_num {
        COPS_NO_OBJECT,        /* Not a COPS Object type               */

        COPS_OBJ_HANDLE,       /* Handle Object (Handle)               */
        COPS_OBJ_CONTEXT,      /* Context Object (Context)             */
        COPS_OBJ_IN_INT,       /* In-Interface Object (IN-Int)         */
        COPS_OBJ_OUT_INT,      /* Out-Interface Object (OUT-Int)       */
        COPS_OBJ_REASON,       /* Reason Object (Reason)               */
        COPS_OBJ_DECISION,     /* Decision Object (Decision)           */
        COPS_OBJ_LPDPDECISION, /* LPDP Decision Object (LPDPDecision)  */
        COPS_OBJ_ERROR,        /* Error Object (Error)                 */
        COPS_OBJ_CLIENTSI,     /* Client Specific Information Object (ClientSI) */
        COPS_OBJ_KATIMER,      /* Keep-Alive Timer Object (KATimer)    */
        COPS_OBJ_PEPID,        /* PEP Identification Object (PEPID)    */
        COPS_OBJ_REPORT_TYPE,  /* Report-Type Object (Report-Type)     */
        COPS_OBJ_PDPREDIRADDR, /* PDP Redirect Address Object (PDPRedirAddr) */
        COPS_OBJ_LASTPDPADDR,  /* Last PDP Address (LastPDPaddr)       */
        COPS_OBJ_ACCTTIMER,    /* Accounting Timer Object (AcctTimer)  */
        COPS_OBJ_INTEGRITY,    /* Message Integrity Object (Integrity) */

        COPS_LAST_C_NUM        /* For error checking                   */
};

static const value_string cops_c_num_vals[] = {
        { COPS_OBJ_HANDLE,       " Handle Object (Handle)" },
        { COPS_OBJ_CONTEXT,      " Context Object (Context)" },
        { COPS_OBJ_IN_INT,       " In-Interface Object (IN-Int)" },
        { COPS_OBJ_OUT_INT,      " Out-Interface Object (OUT-Int)" },
        { COPS_OBJ_REASON,       " Reason Object (Reason)" },
        { COPS_OBJ_DECISION,     " Decision Object (Decision)" },
        { COPS_OBJ_LPDPDECISION, " LPDP Decision Object (LPDPDecision)" },
        { COPS_OBJ_ERROR,        " Error Object (Error)" },
        { COPS_OBJ_CLIENTSI,     " Client Specific Information Object (ClientSI)" },
        { COPS_OBJ_KATIMER,      " Keep-Alive Timer Object (KATimer)" },
        { COPS_OBJ_PEPID,        " PEP Identification Object (PEPID)" },
        { COPS_OBJ_REPORT_TYPE,  " Report-Type Object (Report-Type)" },
        { COPS_OBJ_PDPREDIRADDR, " PDP Redirect Address Object (PDPRedirAddr)" },
        { COPS_OBJ_LASTPDPADDR,  " Last PDP Address (LastPDPaddr)" },
        { COPS_OBJ_ACCTTIMER,    " Accounting Timer Object (AcctTimer)" },
        { COPS_OBJ_INTEGRITY,    " Message Integrity Object (Integrity)" },
        { 0, NULL },

};

/* Initialize the protocol and registered fields */
static gint proto_cops = -1;
static gint hf_cops_ver_flags = -1;
static gint hf_cops_version = -1;
static gint hf_cops_flags = -1;

static gint hf_cops_op_code = -1;
static gint hf_cops_client_type = -1;
static gint hf_cops_msg_len = -1;

static gint hf_cops_obj_len = -1;
static gint hf_cops_obj_c_num = -1;
static gint hf_cops_obj_c_type = -1;

/* Initialize the subtree pointers */
static gint ett_cops = -1;
static gint ett_cops_ver_flags = -1;
static gint ett_cops_obj = -1;

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree);

/* Code to actually dissect the packets */
static void dissect_cops(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint8 op_code;

        pinfo->current_proto = "COPS";
        if (check_col(pinfo->fd, COL_PROTOCOL)) 
                col_add_str(pinfo->fd, COL_PROTOCOL, "COPS");
    
        op_code = tvb_get_guint8(tvb, 1);
        if (check_col(pinfo->fd, COL_INFO))
                col_add_fstr(pinfo->fd, COL_INFO, "COPS %s",
                             val_to_str(op_code, cops_op_code_vals, "Unknown Op Code"));

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *cops_tree, *ver_flags_tree;
                guint32 offset, msg_len, carbage;
                guint8 ver_flags;


                offset = 0;
                ti = proto_tree_add_item(tree, proto_cops, tvb, offset, tvb_length(tvb), FALSE);
                cops_tree = proto_item_add_subtree(ti, ett_cops);

                /* Version and flags share the same byte, put them in a subtree */
                ver_flags = tvb_get_guint8(tvb, offset);
                tv = proto_tree_add_uint_format(cops_tree, hf_cops_ver_flags, tvb, offset, 1,
                                                  ver_flags, "Version: %u, Flags: %s",
                                                  hi_nibble(ver_flags),
                                                  val_to_str(lo_nibble(ver_flags), cops_flags_vals, "Unknown"));
                ver_flags_tree = proto_item_add_subtree(tv, ett_cops_ver_flags);
                proto_tree_add_uint(ver_flags_tree, hf_cops_version, tvb, offset, 1, ver_flags);
                proto_tree_add_uint(ver_flags_tree, hf_cops_flags, tvb, offset, 1, ver_flags);
                offset++;

                proto_tree_add_uint(cops_tree, hf_cops_op_code, tvb, offset, 1, tvb_get_guint8(tvb, offset));
                offset ++;
                proto_tree_add_uint(cops_tree, hf_cops_client_type, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;

                msg_len = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(cops_tree, hf_cops_msg_len, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
                offset += 4;

                while (msg_len >= COPS_OBJECT_HDR_SIZE) {
                        int consumed;

                        consumed = dissect_cops_object(tvb, offset, cops_tree);
                        if (consumed == 0)
                                break;
                        msg_len -= consumed;
                        offset += consumed;
                }

                carbage = tvb_length_remaining(tvb, offset);
                if (carbage != 0)
                        proto_tree_add_text(cops_tree, tvb, offset, carbage,
                                            "Trailing carbage: %u byte%s", carbage,
                                            plurality(carbage, "", "s"));
        }

        return;
}

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree)
{
        guint16 object_len, contents_len;
        guint8 c_num, c_type;
        proto_item *ti;
        proto_tree *obj_tree;

        if (tvb_length_remaining(tvb, offset) < COPS_OBJECT_HDR_SIZE)
                return 0;

        object_len = tvb_get_ntohs(tvb, offset);
        c_num = tvb_get_guint8(tvb, offset + 2);
        c_type = tvb_get_guint8(tvb, offset + 3);

        ti = proto_tree_add_uint_format(tree, hf_cops_obj_c_num, tvb, offset, object_len, c_num,
                                          "Object Type: %s", val_to_str(c_num, cops_c_num_vals, "Unknown"));
        obj_tree = proto_item_add_subtree(ti, ett_cops_obj);

        proto_tree_add_uint(obj_tree, hf_cops_obj_len, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
        offset += 2;

        proto_tree_add_uint(obj_tree, hf_cops_obj_c_num, tvb, offset, 1, tvb_get_guint8(tvb, offset));
        offset++;

        proto_tree_add_uint(obj_tree, hf_cops_obj_c_type, tvb, offset, 1, tvb_get_guint8(tvb, offset));
        offset++;

        contents_len = object_len - COPS_OBJECT_HDR_SIZE;
        proto_tree_add_text(obj_tree, tvb, offset, contents_len,
                            "Object contents: %u bytes", contents_len);

        /* Pad to 32bit boundary */
        if (object_len % sizeof (guint32))
                object_len += (sizeof (guint32) - object_len % sizeof (guint32));

        return object_len;
        
}

/* Register the protocol with Ethereal */
void proto_register_cops(void)
{                 

        /* Setup list of header fields */
        static hf_register_info hf[] = {
                { &hf_cops_ver_flags,
                        { "Version and Flags",           "cops.ver_flags",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        "Version and Flags in COPS Common Header" }
                },
                { &hf_cops_version,
                        { "Version",           "cops.version",
                        FT_UINT8, BASE_DEC, NULL, 0xF0,
                        "Version in COPS Common Header" }
                },
                { &hf_cops_flags,
                        { "Flags",           "cops.flags",
                        FT_UINT8, BASE_HEX, VALS(cops_flags_vals), 0x0F,
                        "Flags in COPS Common Header" }
                },
                { &hf_cops_op_code,
                        { "Op Code",           "cops.op_code",
                        FT_UINT8, BASE_DEC, VALS(cops_op_code_vals), 0x0,
                        "Op Code in COPS Common Header" }
                },
                { &hf_cops_client_type,
                        { "Client Type",           "cops.client_type",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        "Client Type in COPS Common Header" }
                },
                { &hf_cops_msg_len,
                        { "Message Length",           "cops.msg_len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Message Length in COPS Common Header" }
                },
                { &hf_cops_obj_len,
                        { "Object Length",           "cops.obj.len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Object Length in COPS Object Header" }
                },
                { &hf_cops_obj_c_num,
                        { "C-Num",           "cops.obj.c_num",
                        FT_UINT8, BASE_DEC, VALS(cops_c_num_vals), 0x0,
                        "C-Num in COPS Object Header" }
                },
                { &hf_cops_obj_c_type,
                        { "C-Type",           "cops.obj.c_type",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        "C-Type in COPS Object Header" }
                },
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_cops,
                &ett_cops_ver_flags,
                &ett_cops_obj,
        };

        /* Register the protocol name and description */
        proto_cops = proto_register_protocol("Common Open Policy Service", "cops");

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_cops, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_cops(void)
{
        dissector_add("tcp.port", TCP_PORT_COPS, dissect_cops);
}
