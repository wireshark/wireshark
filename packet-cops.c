/* packet-cops.c
 * Routines for the COPS (Common Open Policy Service) protocol dissection
 * RFC2748
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-cops.c,v 1.7 2000/12/27 12:38:08 guy Exp $
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
#include "packet-ipv6.h"

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
        { COPS_OBJ_HANDLE,       "Handle Object (Handle)" },
        { COPS_OBJ_CONTEXT,      "Context Object (Context)" },
        { COPS_OBJ_IN_INT,       "In-Interface Object (IN-Int)" },
        { COPS_OBJ_OUT_INT,      "Out-Interface Object (OUT-Int)" },
        { COPS_OBJ_REASON,       "Reason Object (Reason)" },
        { COPS_OBJ_DECISION,     "Decision Object (Decision)" },
        { COPS_OBJ_LPDPDECISION, "LPDP Decision Object (LPDPDecision)" },
        { COPS_OBJ_ERROR,        "Error Object (Error)" },
        { COPS_OBJ_CLIENTSI,     "Client Specific Information Object (ClientSI)" },
        { COPS_OBJ_KATIMER,      "Keep-Alive Timer Object (KATimer)" },
        { COPS_OBJ_PEPID,        "PEP Identification Object (PEPID)" },
        { COPS_OBJ_REPORT_TYPE,  "Report-Type Object (Report-Type)" },
        { COPS_OBJ_PDPREDIRADDR, "PDP Redirect Address Object (PDPRedirAddr)" },
        { COPS_OBJ_LASTPDPADDR,  "Last PDP Address (LastPDPaddr)" },
        { COPS_OBJ_ACCTTIMER,    "Accounting Timer Object (AcctTimer)" },
        { COPS_OBJ_INTEGRITY,    "Message Integrity Object (Integrity)" },
        { 0, NULL },

};

/* R-Type is carried within the Context Object */
static const value_string cops_r_type_vals[] = {
        { 0x01, "Incoming-Message/Admission Control request" },
        { 0x02, "Resource-Allocation request" },
        { 0x04, "Outgoing-Message request" },
        { 0x08, "Configuration request" },
        { 0, NULL },
};

/* Reason-Code is carried within the Reason object */
static const value_string cops_reason_vals[] = {
        { 1,  "Unspecified" },
        { 2,  "Management" },
        { 3,  "Preempted (Another request state takes precedence)" },
        { 4,  "Tear (Used to communicate a signaled state removal)" },
        { 5,  "Timeout (Local state has timed-out)" },
        { 6,  "Route Change (Change invalidates request state)" },
        { 7,  "Insufficient Resources (No local resource available)" },
        { 8,  "PDP's Directive (PDP decision caused the delete)" },
        { 9,  "Unsupported decision (PDP decision not supported)" },
        { 10, "Synchronize Handle Unknown" },
        { 11, "Transient Handle (stateless event)" },
        { 12, "Malformed Decision (could not recover)" },
        { 13, "Unknown COPS Object from PDP" },
        { 0, NULL },
};

/* Command-Code is carried within the Decision object if C-Type is 1 */
static const value_string cops_dec_cmd_code_vals[] = {
        { 0, "NULL Decision (No configuration data available)" },
        { 1, "Install (Admit request/Install configuration)" },
        { 2, "Remove (Remove request/Remove configuration)" },
        { 0, NULL },
};

/* Decision flags are also carried with the Decision object if C-Type is 1 */
static const value_string cops_dec_cmd_flag_vals[] = {
        { 0x00, "<None set>" },
        { 0x01, "Trigger Error (Trigger error message if set)" },
        { 0, NULL },
};

/* Error-Code from Error object */
static const value_string cops_error_vals[] = {
        {1,  "Bad handle" },
        {2,  "Invalid handle reference" },
        {3,  "Bad message format (Malformed Message)" },
        {4,  "Unable to process (server gives up on query)" },
        {5,  "Mandatory client-specific info missing" },
        {6,  "Unsupported client" },
        {7,  "Mandatory COPS object missing" },
        {8,  "Client Failure" },
        {9,  "Communication Failure" },
        {10, "Unspecified" },
        {11, "Shutting down" },
        {12, "Redirect to Preferred Server" },
        {13, "Unknown COPS Object" },
        {14, "Authentication Failure" },
        {15, "Authentication Required" },
};

/* Report-Type from Report-Type object */
static const value_string cops_report_type_vals[] = {
        {1, " Success   : Decision was successful at the PEP" },
        {2, " Failure   : Decision could not be completed by PEP" },
        {3, " Accounting: Accounting update for an installed state" },
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

static gint hf_cops_r_type_flags = -1;
static gint hf_cops_m_type_flags = -1;

static gint hf_cops_in_int_ipv4 = -1;
static gint hf_cops_in_int_ipv6 = -1;
static gint hf_cops_out_int_ipv4 = -1;
static gint hf_cops_out_int_ipv6 = -1;
static gint hf_cops_int_ifindex = -1;

static gint hf_cops_reason = -1;
static gint hf_cops_reason_sub = -1;

static gint hf_cops_dec_cmd_code = -1;
static gint hf_cops_dec_flags = -1;

static gint hf_cops_error = -1;
static gint hf_cops_error_sub = -1;

static gint hf_cops_katimer = -1;

static gint hf_cops_pepid = -1;

static gint hf_cops_report_type = -1;

static gint hf_cops_pdprediraddr_ipv4 = -1;
static gint hf_cops_pdprediraddr_ipv6 = -1;
static gint hf_cops_lastpdpaddr_ipv4 = -1;
static gint hf_cops_lastpdpaddr_ipv6 = -1;
static gint hf_cops_pdp_tcp_port = -1;

static gint hf_cops_accttimer = -1;

static gint hf_cops_key_id = -1;
static gint hf_cops_seq_num = -1;

/* Initialize the subtree pointers */
static gint ett_cops = -1;
static gint ett_cops_ver_flags = -1;
static gint ett_cops_obj = -1;
static gint ett_cops_obj_data = -1;
static gint ett_cops_r_type_flags = -1;
static gint ett_cops_itf = -1;
static gint ett_cops_reason = -1;
static gint ett_cops_decision = -1;
static gint ett_cops_error = -1;
static gint ett_cops_pdp = -1;

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree);
static int dissect_cops_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                    guint8 c_num, guint8 c_type, guint16 len);

/* Code to actually dissect the packets */
static void dissect_cops(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint8 op_code;

	CHECK_DISPLAY_AS_DATA(proto_cops, tvb, pinfo, tree);

        pinfo->current_proto = "COPS";
        if (check_col(pinfo->fd, COL_PROTOCOL)) 
                col_set_str(pinfo->fd, COL_PROTOCOL, "COPS");
    
        op_code = tvb_get_guint8(tvb, 1);
        if (check_col(pinfo->fd, COL_INFO))
                col_add_fstr(pinfo->fd, COL_INFO, "COPS %s",
                             val_to_str(op_code, cops_op_code_vals, "Unknown Op Code"));

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *cops_tree, *ver_flags_tree;
                guint32 offset, msg_len;
                guint8 ver_flags;
		gint garbage;

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

                garbage = tvb_length_remaining(tvb, offset);
                if (garbage > 0)
                        proto_tree_add_text(cops_tree, tvb, offset, garbage,
                                            "Trailing garbage: %d byte%s", garbage,
                                            plurality(garbage, "", "s"));
        }

        return;
}

static char *cops_c_type_to_str(guint8 c_num, guint8 c_type)
{
        switch (c_num) {
        case COPS_OBJ_HANDLE:
                if (c_type == 1)
                        return "Client Handle";
                break;
        case COPS_OBJ_IN_INT:
        case COPS_OBJ_OUT_INT:
                if (c_type == 1)
                        return "IPv4 Address + Interface";
                else if (c_type == 2)
                        return "IPv6 Address + Interface";
                break;
        case COPS_OBJ_DECISION:
        case COPS_OBJ_LPDPDECISION:
                if (c_type == 1)
                        return "Decision Flags (Mandatory)";
                else if (c_type == 2)
                        return "Stateless Data";
                else if (c_type == 3)
                        return "Replacement Data";
                else if (c_type == 4)
                        return "Client Specific Decision Data";
                else if (c_type == 5)
                        return "Named Decision Data";
                break;
        case COPS_OBJ_CLIENTSI:
                if (c_type == 1)
                        return "Signaled ClientSI";
                else if (c_type == 2)
                        return "Named ClientSI";
                break;
        case COPS_OBJ_KATIMER:
                if (c_type == 1)
                        return "Keep-alive timer value";
                break;
        case COPS_OBJ_PDPREDIRADDR:
        case COPS_OBJ_LASTPDPADDR:
                if (c_type == 1)
                        return "IPv4 Address + TCP Port";
                else if (c_type == 2)
                        return "IPv6 Address + TCP Port";
                break;
        case COPS_OBJ_ACCTTIMER:
                if (c_type == 1)
                        return "Accounting timer value";
                break;
        case COPS_OBJ_INTEGRITY:
                if (c_type == 1)
                        return "HMAC digest";
                break;
        }

        return "";
}

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree)
{
        guint16 object_len, contents_len;
        guint8 c_num, c_type;
        proto_item *ti;
        proto_tree *obj_tree;
        char *type_str;
        int ret;

        if (tvb_length_remaining(tvb, offset) < COPS_OBJECT_HDR_SIZE)
                return 0;

        object_len = tvb_get_ntohs(tvb, offset);
        c_num = tvb_get_guint8(tvb, offset + 2);
        c_type = tvb_get_guint8(tvb, offset + 3);

        ti = proto_tree_add_uint_format(tree, hf_cops_obj_c_num, tvb, offset, object_len, c_num,
                                        "%s: %s", val_to_str(c_num, cops_c_num_vals, "Unknown"),
                                        cops_c_type_to_str(c_num, c_type));
        obj_tree = proto_item_add_subtree(ti, ett_cops_obj);

        proto_tree_add_uint(obj_tree, hf_cops_obj_len, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
        offset += 2;

        proto_tree_add_uint(obj_tree, hf_cops_obj_c_num, tvb, offset, 1, c_num);
        offset++;

        type_str = cops_c_type_to_str(c_num, c_type);
        proto_tree_add_text(obj_tree, tvb, offset, 1, "C-Type: %s%s%u%s",
                            type_str,
                            strlen(type_str) ? " (" : "",
                            c_type,
                            strlen(type_str) ? ")" : "");
        offset++;

        contents_len = object_len - COPS_OBJECT_HDR_SIZE;
        ret = dissect_cops_object_data(tvb, offset, obj_tree, c_num, c_type, contents_len);
        if (ret < 0) return 0;

        /* Pad to 32bit boundary */
        if (object_len % sizeof (guint32))
                object_len += (sizeof (guint32) - object_len % sizeof (guint32));

        return object_len;
        
}

static int dissect_cops_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                    guint8 c_num, guint8 c_type, guint16 len)
{
        proto_item *ti;
        proto_tree *r_type_tree, *itf_tree, *reason_tree, *dec_tree, *error_tree, *pdp_tree;
        guint16 r_type, m_type, reason, reason_sub, cmd_code, cmd_flags, error, error_sub, tcp_port;
        guint32 ipv4addr, ifindex;
        struct e_in6_addr ipv6addr;

        switch (c_num) {
        case COPS_OBJ_CONTEXT:
                r_type = tvb_get_ntohs(tvb, offset);
                m_type = tvb_get_ntohs(tvb, offset + 2);
                ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: R-Type: %s, M-Type: %u",
                                         val_to_str(r_type, cops_r_type_vals, "Unknown"),
                                         m_type);

                r_type_tree = proto_item_add_subtree(ti, ett_cops_r_type_flags);
                proto_tree_add_uint(r_type_tree, hf_cops_r_type_flags, tvb, offset, 2, r_type);
                offset += 2;
                proto_tree_add_uint(r_type_tree, hf_cops_m_type_flags, tvb, offset, 2, m_type);

                return 0;
                break;
        case COPS_OBJ_IN_INT:
        case COPS_OBJ_OUT_INT:
                if (c_type == 1) {          /* IPv4 */
                        tvb_memcpy(tvb, (guint8 *)&ipv4addr, offset, 4);
                        ifindex = tvb_get_ntohl(tvb, offset + 4);
                        ti = proto_tree_add_text(tree, tvb, offset, 8, "Contents: IPv4 address %s, ifIndex: %u",
                                                 ip_to_str((guint8 *)&ipv4addr), ifindex);
                        itf_tree = proto_item_add_subtree(ti, ett_cops_itf);
                        proto_tree_add_ipv4(itf_tree,
                                            (c_num == COPS_OBJ_IN_INT) ? hf_cops_in_int_ipv4 : hf_cops_out_int_ipv4,
                                            tvb, offset, 4, ipv4addr);
                        offset += 4;
                } else if (c_type == 2) {   /* IPv6 */
                        tvb_memcpy(tvb, (guint8 *)&ipv6addr, offset, sizeof ipv6addr);
                        ifindex = tvb_get_ntohl(tvb, offset + sizeof ipv6addr);
                        ti = proto_tree_add_text(tree, tvb, offset, 20, "Contents: IPv6 address %s, ifIndex: %u",
                                                 ip6_to_str(&ipv6addr), ifindex);
                        itf_tree = proto_item_add_subtree(ti, ett_cops_itf);
                        proto_tree_add_ipv6(itf_tree,
                                            (c_num == COPS_OBJ_IN_INT) ? hf_cops_in_int_ipv6 : hf_cops_out_int_ipv6,
                                            tvb, offset, 16, (guint8 *)&ipv6addr);
                        offset += 16;
                } else {
                        break;
                }
                proto_tree_add_uint(itf_tree, hf_cops_int_ifindex, tvb, offset, 4, ifindex);

                return 0;
                break;
        case COPS_OBJ_REASON:
                reason = tvb_get_ntohs(tvb, offset);
                reason_sub = tvb_get_ntohs(tvb, offset + 2);
                ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Reason-Code: %s, Reason Sub-code: 0x%04x",
                                         val_to_str(reason, cops_reason_vals, "<Unknown value>"), reason_sub);
                reason_tree = proto_item_add_subtree(ti, ett_cops_reason);
                proto_tree_add_uint(reason_tree, hf_cops_reason, tvb, offset, 2, reason);
                offset += 2;
                if (reason == 13) {
                        proto_tree_add_text(reason_tree, tvb, offset, 2, "Reason Sub-code: "
                                            "Unknown object's C-Num %u, C-Type %u",
                                            tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
                } else 
                        proto_tree_add_uint(reason_tree, hf_cops_reason_sub, tvb, offset, 2, reason_sub);

                return 0;
                break;
        case COPS_OBJ_DECISION:
        case COPS_OBJ_LPDPDECISION:
                if (c_type != 1)
                        break;

                cmd_code = tvb_get_ntohs(tvb, offset);
                cmd_flags = tvb_get_ntohs(tvb, offset + 2);
                ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Command-Code: %s, Flags: %s",
                                         val_to_str(cmd_code, cops_dec_cmd_code_vals, "<Unknown value>"),
                                         val_to_str(cmd_flags, cops_dec_cmd_flag_vals, "<Unknown flag>"));
                dec_tree = proto_item_add_subtree(ti, ett_cops_decision);
                proto_tree_add_uint(dec_tree, hf_cops_dec_cmd_code, tvb, offset, 2, cmd_code);
                offset += 2;
                proto_tree_add_uint(dec_tree, hf_cops_dec_flags, tvb, offset, 2, cmd_flags);
                
                return 0;
                break;
        case COPS_OBJ_ERROR:
                if (c_type != 1)
                        break;
                
                error = tvb_get_ntohs(tvb, offset);
                error_sub = tvb_get_ntohs(tvb, offset + 2);
                ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Error-Code: %s, Error Sub-code: 0x%04x",
                                         val_to_str(error, cops_error_vals, "<Unknown value>"), error_sub);
                error_tree = proto_item_add_subtree(ti, ett_cops_error);
                proto_tree_add_uint(error_tree, hf_cops_error, tvb, offset, 2, error);
                offset += 2;
                if (error == 13) {
                        proto_tree_add_text(error_tree, tvb, offset, 2, "Error Sub-code: "
                                            "Unknown object's C-Num %u, C-Type %u",
                                            tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
                } else 
                        proto_tree_add_uint(error_tree, hf_cops_error_sub, tvb, offset, 2, error_sub);

                return 0;
                break;
        case COPS_OBJ_KATIMER:
                if (c_type != 1)
                        break;

                proto_tree_add_item(tree, hf_cops_katimer, tvb, offset + 2, 2, FALSE);
                if (tvb_get_ntohs(tvb, offset + 2) == 0)
                        proto_tree_add_text(tree, tvb, offset, 0, "Value of zero implies infinity.");
                
                return 0;
                break;
        case COPS_OBJ_PEPID:
                if (c_type != 1)
                        break;

                if (tvb_strnlen(tvb, offset, len) == -1)
                        proto_tree_add_text(tree, tvb, offset, len, "<PEP Id is not a NUL terminated ASCII string>");
                else
                        proto_tree_add_item(tree, hf_cops_pepid, tvb, offset,
                                            tvb_strnlen(tvb, offset, len) + 1, FALSE);

                return 0;
                break;
        case COPS_OBJ_REPORT_TYPE:
                if (c_type != 1)
                        break;

                proto_tree_add_item(tree, hf_cops_report_type, tvb, offset, 2, FALSE);

                return 0;
                break;
        case COPS_OBJ_PDPREDIRADDR:
        case COPS_OBJ_LASTPDPADDR:
                if (c_type == 1) {          /* IPv4 */
                        tvb_memcpy(tvb, (guint8 *)&ipv4addr, offset, 4);
                        tcp_port = tvb_get_ntohs(tvb, offset + 4 + 2);
                        ti = proto_tree_add_text(tree, tvb, offset, 8, "Contents: IPv4 address %s, TCP Port Number: %u",
                                                 ip_to_str((guint8 *)&ipv4addr), tcp_port);
                        pdp_tree = proto_item_add_subtree(ti, ett_cops_pdp);
                        proto_tree_add_ipv4(pdp_tree,
                                            (c_num == COPS_OBJ_PDPREDIRADDR) ? hf_cops_pdprediraddr_ipv4 : hf_cops_lastpdpaddr_ipv4,
                                            tvb, offset, 4, ipv4addr);
                        offset += 4;
                } else if (c_type == 2) {   /* IPv6 */
                        tvb_memcpy(tvb, (guint8 *)&ipv6addr, offset, sizeof ipv6addr);
                        tcp_port = tvb_get_ntohs(tvb, offset + sizeof ipv6addr + 2);
                        ti = proto_tree_add_text(tree, tvb, offset, 20, "Contents: IPv6 address %s, TCP Port Number: %u",
                                                 ip6_to_str(&ipv6addr), tcp_port);
                        pdp_tree = proto_item_add_subtree(ti, ett_cops_pdp);
                        proto_tree_add_ipv6(pdp_tree,
                                            (c_num == COPS_OBJ_PDPREDIRADDR) ? hf_cops_pdprediraddr_ipv6 : hf_cops_lastpdpaddr_ipv6,
                                            tvb, offset, 16, (guint8 *)&ipv6addr);
                        offset += 16;
                } else {
                        break;
                }
                offset += 2;
                proto_tree_add_uint(pdp_tree, hf_cops_pdp_tcp_port, tvb, offset, 2, tcp_port);

                return 0;
                break;
        case COPS_OBJ_ACCTTIMER:
                if (c_type != 1)
                        break;

                proto_tree_add_item(tree, hf_cops_accttimer, tvb, offset + 2, 2, FALSE);
                if (tvb_get_ntohs(tvb, offset + 2) == 0)
                        proto_tree_add_text(tree, tvb, offset, 0, "Value of zero means "
                                            "there SHOULD be no unsolicited accounting updates.");

                return 0;
                break;
        case COPS_OBJ_INTEGRITY:
                if (c_type != 1)
                        break;      /* Not HMAC digest */

                proto_tree_add_item(tree, hf_cops_key_id, tvb, offset, 4, FALSE);
                proto_tree_add_item(tree, hf_cops_seq_num, tvb, offset + 4, 4, FALSE);
                proto_tree_add_text(tree, tvb, offset + 8 , len - 8, "Contents: Keyed Message Digest");

                return 0;
                break;
        default:
                break;
        }

        ti = proto_tree_add_text(tree, tvb, offset, len, "Contents: %u bytes", len);

        return 0;
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
                        { "C-Num",           "cops.c_num",
                        FT_UINT8, BASE_DEC, VALS(cops_c_num_vals), 0x0,
                        "C-Num in COPS Object Header" }
                },
                { &hf_cops_obj_c_type,
                        { "C-Type",           "cops.c_type",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        "C-Type in COPS Object Header" }
                },
                { &hf_cops_r_type_flags,
                        { "R-Type",           "cops.context.r_type",
                        FT_UINT16, BASE_HEX, VALS(cops_r_type_vals), 0xFFFF,
                        "R-Type in COPS Context Object" }
                },
                { &hf_cops_m_type_flags,
                        { "M-Type",           "cops.context.m_type",
                        FT_UINT16, BASE_HEX, NULL, 0xFFFF,
                        "M-Type in COPS Context Object" }
                },
                { &hf_cops_in_int_ipv4,
                        { "IPv4 address",           "cops.in-int.ipv4",
                        FT_IPv4, 0, NULL, 0xFFFF,
                        "IPv4 address in COPS IN-Int object" }
                },
                { &hf_cops_in_int_ipv6,
                        { "IPv6 address",           "cops.in-int.ipv6",
                        FT_IPv6, 0, NULL, 0xFFFF,
                        "IPv6 address in COPS IN-Int object" }
                },
                { &hf_cops_out_int_ipv4,
                        { "IPv4 address",           "cops.out-int.ipv4",
                        FT_IPv4, 0, NULL, 0xFFFF,
                        "IPv4 address in COPS OUT-Int object" }
                },
                { &hf_cops_out_int_ipv6,
                        { "IPv6 address",           "cops.out-int.ipv6",
                        FT_IPv6, 0, NULL, 0xFFFF,
                        "IPv6 address in COPS OUT-Int" }
                },
                { &hf_cops_int_ifindex,
                        { "ifIndex",           "cops.in-out-int.ifindex",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "If SNMP is supported, corresponds to MIB-II ifIndex" } 
                },
                { &hf_cops_reason,
                        { "Reason",           "cops.reason",
                        FT_UINT16, BASE_DEC, VALS(cops_reason_vals), 0,
                        "Reason in Reason object" }
                },
                { &hf_cops_reason_sub,
                        { "Reason Sub-code",           "cops.reason_sub",
                        FT_UINT16, BASE_HEX, NULL, 0,
                        "Reason Sub-code in Reason object" }
                },
                { &hf_cops_dec_cmd_code,
                        { "Command-Code",           "cops.decision.cmd",
                        FT_UINT16, BASE_DEC, VALS(cops_dec_cmd_code_vals), 0,
                        "Command-Code in Decision/LPDP Decision object" }
                },
                { &hf_cops_dec_flags,
                        { "Flags",           "cops.decision.flags",
                        FT_UINT16, BASE_HEX, VALS(cops_dec_cmd_flag_vals), 0xffff,
                        "Flags in Decision/LPDP Decision object" }
                },
                { &hf_cops_error,
                        { "Error",           "cops.error",
                        FT_UINT16, BASE_DEC, VALS(cops_error_vals), 0,
                        "Error in Error object" }
                },
                { &hf_cops_error_sub,
                        { "Error Sub-code",           "cops.error_sub",
                        FT_UINT16, BASE_HEX, NULL, 0,
                        "Error Sub-code in Error object" }
                },
                { &hf_cops_katimer,
                        { "Contents: KA Timer Value",           "cops.katimer.value",
                        FT_UINT16, BASE_DEC, NULL, 0,
                        "Keep-Alive Timer Value in KATimer object" }
                },
                { &hf_cops_pepid,
                        { "Contents: PEP Id",           "cops.pepid.id",
                        FT_STRING, BASE_NONE, NULL, 0,
                        "PEP Id in PEPID object" }
                },
                { &hf_cops_report_type,
                        { "Contents: Report-Type",           "cops.report_type",
                        FT_UINT16, BASE_DEC, VALS(cops_report_type_vals), 0,
                        "Report-Type in Report-Type object" }
                },
                { &hf_cops_pdprediraddr_ipv4,
                        { "IPv4 address",           "cops.pdprediraddr.ipv4",
                        FT_IPv4, 0, NULL, 0xFFFF,
                        "IPv4 address in COPS PDPRedirAddr object" }
                },
                { &hf_cops_pdprediraddr_ipv6,
                        { "IPv6 address",           "cops.pdprediraddr.ipv6",
                        FT_IPv6, 0, NULL, 0xFFFF,
                        "IPv6 address in COPS PDPRedirAddr object" }
                },
                { &hf_cops_lastpdpaddr_ipv4,
                        { "IPv4 address",           "cops.lastpdpaddr.ipv4",
                        FT_IPv4, 0, NULL, 0xFFFF,
                        "IPv4 address in COPS LastPDPAddr object" }
                },
                { &hf_cops_lastpdpaddr_ipv6,
                        { "IPv6 address",           "cops.lastpdpaddr.ipv6",
                        FT_IPv6, 0, NULL, 0xFFFF,
                        "IPv6 address in COPS LastPDPAddr object" }
                },
                { &hf_cops_pdp_tcp_port,
                        { "TCP Port Number",           "cops.pdp.tcp_port",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                         "TCP Port Number of PDP in PDPRedirAddr/LastPDPAddr object" }
                },
                { &hf_cops_accttimer,
                        { "Contents: ACCT Timer Value",           "cops.accttimer.value",
                        FT_UINT16, BASE_DEC, NULL, 0,
                        "Accounting Timer Value in AcctTimer object" }
                },
                { &hf_cops_key_id,
                        { "Contents: Key ID",           "cops.integrity.key_id",
                        FT_UINT32, BASE_DEC, NULL, 0,
                        "Key ID in Integrity object" }
                },
                { &hf_cops_seq_num,
                        { "Contents: Sequence Number",           "cops.integrity.seq_num",
                        FT_UINT32, BASE_DEC, NULL, 0,
                        "Sequence Number in Integrity object" }
                },
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_cops,
                &ett_cops_ver_flags,
                &ett_cops_obj,
                &ett_cops_obj_data,
                &ett_cops_r_type_flags,
                &ett_cops_itf,
                &ett_cops_reason,
                &ett_cops_decision,
                &ett_cops_error,
                &ett_cops_pdp,
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
