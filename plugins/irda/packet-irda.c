/* packet-irda.c
 * Routines for IrDA dissection
 * By Shaun Jackman <sjackman@pathwayconnect.com>
 * Copyright 2000 Shaun Jackman
 *
 * Extended by Jan Kiszka <jan.kiszka@web.de>
 * Copyright 2003 Jan Kiszka
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/xdlc.h>

#include "irda-appl.h"

/*
 * This plugin dissects infrared data transmissions as defined by the IrDA
 * specification (www.irda.org).  See
 *
 *	http://www.irda.org/standards/specifications.asp
 *
 * for various IrDA specifications.
 *
 * The plugin operates both offline with libpcap files and online on supported
 * platforms. Live dissection is currently available for Linux-IrDA
 * (irda.sourceforge.net) and for Windows if the Linux-IrDA port IrCOMM2k
 * (www.ircomm2k.de) is installed.
 */

/*
 * LAP
 */

/* Frame types and templates */
#define INVALID   0xff

/*
 * XXX - the IrDA spec gives XID as 0x2c; HDLC (and other HDLC-derived
 * protocolc) use 0xAC.
 */
#define IRDA_XID_CMD   0x2c /* Exchange Station Identification */

#define CMD_FRAME 0x01
#define RSP_FRAME 0x00

/* Discovery Flags */
#define S_MASK    0x03
#define CONFLICT  0x04

/* Negotiation Parameters */
#define PI_BAUD_RATE        0x01
#define PI_MAX_TURN_TIME    0x82
#define PI_DATA_SIZE        0x83
#define PI_WINDOW_SIZE      0x84
#define PI_ADD_BOFS         0x85
#define PI_MIN_TURN_TIME    0x86
#define PI_LINK_DISC        0x08


/*
 * LMP
 */

/* IrLMP frame opcodes */
#define CONNECT_CMD    0x01
#define CONNECT_CNF    0x81
#define DISCONNECT     0x02
#define ACCESSMODE_CMD 0x03
#define ACCESSMODE_CNF 0x83

#define CONTROL_BIT    0x80
#define RESERVED_BIT   0x80

/* LSAP-SEL's */
#define LSAP_MASK     0x7f
#define LSAP_IAS      0x00
#define LSAP_ANY      0xff
#define LSAP_MAX      0x6f /* 0x70-0x7f are reserved */
#define LSAP_CONNLESS 0x70 /* Connectionless LSAP, mostly used for Ultra */


/*
 * IAP
 */

/* IrIAP Op-codes */
#define GET_INFO_BASE      0x01
#define GET_OBJECTS        0x02
#define GET_VALUE          0x03
#define GET_VALUE_BY_CLASS 0x04
#define GET_OBJECT_INFO    0x05
#define GET_ATTRIB_NAMES   0x06

#define IAP_LST            0x80
#define IAP_ACK            0x40
#define IAP_OP             0x3F

#define IAS_SUCCESS        0
#define IAS_CLASS_UNKNOWN  1
#define IAS_ATTRIB_UNKNOWN 2
#define IAS_ATTR_TOO_LONG  3
#define IAS_DISCONNECT     10
#define IAS_UNSUPPORTED    0xFF


/*
 * TTP
 */

#define TTP_PARAMETERS         0x80
#define TTP_MORE               0x80

/* Initialize the protocol and registered fields */
static int proto_irlap = -1;
static int hf_lap_a = -1;
static int hf_lap_a_cr = -1;
static int hf_lap_a_address = -1;
static int hf_lap_c = -1;
static int hf_lap_c_nr = -1;
static int hf_lap_c_ns = -1;
static int hf_lap_c_p = -1;
static int hf_lap_c_f = -1;
static int hf_lap_c_s = -1;
static int hf_lap_c_u_cmd = -1;
static int hf_lap_c_u_rsp = -1;
static int hf_lap_c_i = -1;
static int hf_lap_c_s_u = -1;
static int hf_lap_i = -1;
static int hf_snrm_saddr = -1;
static int hf_snrm_daddr = -1;
static int hf_snrm_ca = -1;
static int hf_ua_saddr = -1;
static int hf_ua_daddr = -1;
static int hf_negotiation_param = -1;
static int hf_param_pi = -1;
static int hf_param_pl = -1;
static int hf_param_pv = -1;
static int hf_xid_ident = -1;
static int hf_xid_saddr = -1;
static int hf_xid_daddr = -1;
static int hf_xid_flags = -1;
static int hf_xid_s = -1;
static int hf_xid_conflict = -1;
static int hf_xid_slotnr = -1;
static int hf_xid_version = -1;

static int proto_irlmp = -1;
static int hf_lmp_xid_hints = -1;
static int hf_lmp_xid_charset = -1;
static int hf_lmp_xid_name = -1;
static int hf_lmp_xid_name_no_ascii = -1;
static int hf_lmp_dst = -1;
static int hf_lmp_dst_control = -1;
static int hf_lmp_dst_lsap = -1;
static int hf_lmp_src = -1;
static int hf_lmp_src_r = -1;
static int hf_lmp_src_lsap = -1;
static int hf_lmp_opcode = -1;
static int hf_lmp_rsvd = -1;
static int hf_lmp_reason = -1;
static int hf_lmp_mode = -1;
static int hf_lmp_status = -1;

static int proto_iap = -1;
static int hf_iap_ctl = -1;
static int hf_iap_ctl_lst = -1;
static int hf_iap_ctl_ack = -1;
static int hf_iap_ctl_opcode = -1;
static int hf_iap_class_name = -1;
static int hf_iap_attr_name = -1;
static int hf_iap_return = -1;
static int hf_iap_list_len = -1;
static int hf_iap_list_entry = -1;
static int hf_iap_obj_id = -1;
static int hf_iap_attr_type = -1;
static int hf_iap_int = -1;
static int hf_iap_seq_len = -1;
static int hf_iap_oct_seq = -1;
static int hf_iap_char_set = -1;
static int hf_iap_string = -1;
static int hf_iap_invaloctet = -1;
static int hf_iap_invallsap = -1;

static int proto_ttp = -1;
static int hf_ttp_p = -1;
static int hf_ttp_icredit = -1;
static int hf_ttp_m = -1;
static int hf_ttp_dcredit = -1;

static int proto_log = -1;
static int hf_log_msg = -1;
static int hf_log_missed = -1;

/* Initialize the subtree pointers */
static gint ett_irlap = -1;
static gint ett_lap_a = -1;
static gint ett_lap_c = -1;
static gint ett_lap_i = -1;
static gint ett_xid_flags = -1;
static gint ett_log = -1;
static gint ett_irlmp = -1;
static gint ett_lmp_dst = -1;
static gint ett_lmp_src = -1;
static gint ett_iap = -1;
static gint ett_iap_ctl = -1;
static gint ett_ttp = -1;

#define MAX_PARAMETERS      32
static gint ett_param[MAX_PARAMETERS];

static gint ett_iap_entry[MAX_IAP_ENTRIES];

static const xdlc_cf_items irlap_cf_items = {
	&hf_lap_c_nr,
	&hf_lap_c_ns,
	&hf_lap_c_p,
	&hf_lap_c_f,
	&hf_lap_c_s,
	&hf_lap_c_u_cmd,
	&hf_lap_c_u_rsp,
	&hf_lap_c_i,
	&hf_lap_c_s_u
};

/* IAP conversation type */
typedef struct iap_conversation {
    struct iap_conversation*    pnext;
    guint32                     iap_query_frame;
    ias_attr_dissector_t* pattr_dissector;
} iap_conversation_t;

/* IrLMP conversation type */
typedef struct lmp_conversation {
    struct lmp_conversation*    pnext;
    guint32                     iap_result_frame;
    gboolean                    ttp;
    dissector_t                 proto_dissector;
} lmp_conversation_t;

static GMemChunk* iap_conv_chunk = NULL;
static GMemChunk* lmp_conv_chunk = NULL;

static const true_false_string lap_cr_vals = {
    "Command",
    "Response"
};

static const true_false_string set_notset = {
    "Set",
    "Not set"
};

static const value_string lap_c_ftype_vals[] = {
    { XDLC_I, "Information frame" },
    { XDLC_S, "Supervisory frame" },
    { XDLC_U, "Unnumbered frame" },
    { 0,      NULL }
};

static const value_string lap_c_u_cmd_abbr_vals[] = {
    { XDLC_SNRM,    "SNRM" },
    { XDLC_DISC,    "DISC" },
    { XDLC_UI,      "UI" },
    { IRDA_XID_CMD, "XID" },
    { XDLC_TEST,    "TEST" },
    { 0,            NULL }
};

static const value_string lap_c_u_rsp_abbr_vals[] = {
    { XDLC_SNRM, "RNRM" },
    { XDLC_UA,   "UA" },
    { XDLC_FRMR, "FRMR" },
    { XDLC_DM,   "DM" },
    { XDLC_RD,   "RD" },
    { XDLC_UI,   "UI" },
    { XDLC_XID,  "XID" },
    { XDLC_TEST, "TEST" },
    { 0,         NULL }
};

static const value_string lap_c_u_cmd_vals[] = {
    { XDLC_SNRM>>2,    "Set Normal Response Mode" },
    { XDLC_DISC>>2,    "Disconnect" },
    { XDLC_UI>>2,      "Unnumbered Information" },
    { IRDA_XID_CMD>>2, "Exchange Station Identification" },
    { XDLC_TEST>>2,    "Test" },
    { 0,               NULL }
};

static const value_string lap_c_u_rsp_vals[] = {
    { XDLC_SNRM>>2,  "Request Normal Response Mode" },
    { XDLC_UA>>2,    "Unnumbered Acknowledge" },
    { XDLC_FRMR>>2,  "Frame Reject" },
    { XDLC_DM>>2,    "Disconnect Mode" },
    { XDLC_RD>>2,    "Request Disconnect" },
    { XDLC_UI>>2,    "Unnumbered Information" },
    { XDLC_XID>>2,   "Exchange Station Identification" },
    { XDLC_TEST>>2,  "Test" },
    { 0,             NULL }
};

static const value_string lap_c_s_vals[] = {
    { XDLC_RR>>2,   "Receiver ready" },
    { XDLC_RNR>>2,  "Receiver not ready" },
    { XDLC_REJ>>2,  "Reject" },
    { XDLC_SREJ>>2, "Selective reject" },
    { 0,            NULL }
};

static const value_string xid_slot_numbers[] = {
/* Number of XID slots */
    { 0, "1" },
    { 1, "6" },
    { 2, "8" },
    { 3, "16" },
    { 0, NULL }
};

static const value_string lmp_opcode_vals[] = {
/* IrLMP frame opcodes */
    { CONNECT_CMD,    "Connect Command" },
    { CONNECT_CNF,    "Connect Confirm" },
    { DISCONNECT,     "Disconnect" },
    { ACCESSMODE_CMD, "Access Mode Command" },
    { ACCESSMODE_CNF, "Access Mode Confirm" },
    { 0,              NULL }
};

static const value_string lmp_reason_vals[] = {
/* IrLMP disconnect reasons */
    { 0x01, "User Request" },
    { 0x02, "Unexpected IrLAP Disconnect" },
    { 0x03, "Failed to establish IrLAP connection" },
    { 0x04, "IrLAP Reset" },
    { 0x05, "Link Management Initiated Disconnect" },
    { 0x06, "Data delivered on disconnected LSAP-Connection"},
    { 0x07, "Non Responsive LM-MUX Client" },
    { 0x08, "No available LM-MUX Client" },
    { 0x09, "Connection Half Open" },
    { 0x0A, "Illegal Source Address" },
    { 0xFF, "Unspecified Disconnect Reason" },
    { 0,    NULL }
};

static const value_string lmp_mode_vals[] = {
/* IrLMP modes */
    { 0x00, "Multiplexed" },
    { 0x01, "Exclusive" },
    { 0,    NULL }
};

static const value_string lmp_status_vals[] = {
/* IrLMP status */
    { 0x00, "Success" },
    { 0x01, "Failure" },
    { 0xFF, "Unsupported" },
    { 0,    NULL }
};

static const value_string iap_opcode_vals[] = {
/* IrIAP Op-codes */
    { GET_INFO_BASE,      "GetInfoBase" },
    { GET_OBJECTS,        "GetObjects" },
    { GET_VALUE,          "GetValue" },
    { GET_VALUE_BY_CLASS, "GetValueByClass" },
    { GET_OBJECT_INFO,    "GetObjectInfo" },
    { GET_ATTRIB_NAMES,   "GetAttributeNames" },
    { 0,                  NULL }
};

static const value_string iap_return_vals[] = {
/* IrIAP Return-codes */
    { IAS_SUCCESS,        "Success" },
    { IAS_CLASS_UNKNOWN,  "Class/Object Unknown" },
    { IAS_ATTRIB_UNKNOWN, "Attribute Unknown" },
    { IAS_ATTR_TOO_LONG,  "Attribute List Too Long" },
    { IAS_DISCONNECT,     "Disconnect (Linux-IrDA only)" },
    { IAS_UNSUPPORTED,    "Unsupported Optional Operation" },
    { 0,                  NULL }
};

static const value_string iap_attr_type_vals[] = {
/* LM-IAS Attribute types */
    { IAS_MISSING, "Missing" },
    { IAS_INTEGER, "Integer" },
    { IAS_OCT_SEQ, "Octet Sequence" },
    { IAS_STRING,  "String" },
    { 0,           NULL }
};

static ias_attr_dissector_t device_attr_dissector[] = {
/* Device attribute dissectors */
/*    { "IrLMPSupport", xxx },  not implemented yet... */
    { NULL, NULL }
};

/* IAS class dissectors */
static ias_class_dissector_t class_dissector[] = { CLASS_DISSECTORS };


/*
 * Dissect parameter tuple
 */
unsigned dissect_param_tuple(tvbuff_t* tvb, proto_tree* tree, unsigned offset)
{
    guint8  len = tvb_get_guint8(tvb, offset + 1);

    if (tree)
        proto_tree_add_item(tree, hf_param_pi, tvb, offset, 1, FALSE);
    offset++;

    if (tree)
        proto_tree_add_item(tree, hf_param_pl, tvb, offset, 1, FALSE);
    offset++;

    if (len > 0)
    {
        if (tree)
            proto_tree_add_item(tree, hf_param_pv, tvb, offset, len, FALSE);
        offset += len;
    }

    return offset;
}


/*
 * Dissect TTP
 */
static unsigned dissect_ttp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, gboolean data)
{
    unsigned    offset = 0;
    guint8      head;


    if (tvb_length(tvb) == 0)
        return 0;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "TTP");

    head = tvb_get_guint8(tvb, offset);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        char    buf[128];


        sprintf(buf, ", Credit=%d", head & ~TTP_PARAMETERS);
        col_append_str(pinfo->cinfo, COL_INFO, buf);
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_ttp, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_ttp);

        if (data)
        {
            proto_tree_add_item(tree, hf_ttp_m, tvb, offset, 1, FALSE);
            proto_tree_add_item(tree, hf_ttp_dcredit, tvb, offset, 1, FALSE);
            offset++;
        }
        else
        {
            proto_tree_add_item(tree, hf_ttp_p, tvb, offset, 1, FALSE);
            proto_tree_add_item(tree, hf_ttp_icredit, tvb, offset, 1, FALSE);
            offset++;
        }
        proto_item_set_len(tree, offset);
    }
    else
        offset++;

    return offset;
}


/*
 * Dissect IAP request
 */
static void dissect_iap_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    unsigned            offset = 0;
    guint8              op;
    guint8              clen = 0;
    guint8              alen = 0;
    guint8              src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    iap_conversation_t* iap_conv;


    if (tvb_length(tvb) == 0)
        return;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");

    op = tvb_get_guint8(tvb, offset) & IAP_OP;

    switch (op)
    {
        case GET_VALUE_BY_CLASS:
            clen = MIN(tvb_get_guint8(tvb, offset + 1), 60);
            alen = MIN(tvb_get_guint8(tvb, offset + 1 + 1 + clen), 60);

            /* create conversation entry */
            src = pinfo->circuit_id ^ CMD_FRAME;
            srcaddr.type  = AT_NONE;
            srcaddr.len   = 1;
            srcaddr.data  = (char*)&src;

            destaddr.type = AT_NONE;
            destaddr.len  = 1;
            destaddr.data = (char*)&pinfo->circuit_id;

            conv = find_conversation(pinfo->fd->num, &srcaddr, &destaddr, PT_NONE, pinfo->srcport, pinfo->destport, 0);
            if (conv)
            {
                iap_conv = (iap_conversation_t*)conversation_get_proto_data(conv, proto_iap);
                while (1)
                {
                    if (iap_conv->iap_query_frame == pinfo->fd->num)
                    {
                        iap_conv = NULL;
                        break;
                    }
                    if (iap_conv->pnext == NULL)
                    {
                        iap_conv->pnext = g_mem_chunk_alloc(iap_conv_chunk);
                        iap_conv = iap_conv->pnext;
                        break;
                    }
                    iap_conv = iap_conv->pnext;
                }
            }
            else
            {
                conv = conversation_new(pinfo->fd->num, &srcaddr, &destaddr, PT_NONE, pinfo->srcport, pinfo->destport, 0);
                iap_conv = g_mem_chunk_alloc(iap_conv_chunk);
                conversation_add_proto_data(conv, proto_iap, (void*)iap_conv);
            }

            /* Dissect IAP query if it is new */
            if (iap_conv)
            {
                int     i, j;
                char    class_name[256];
                char    attr_name[256];


                iap_conv->pnext           = NULL;
                iap_conv->iap_query_frame = pinfo->fd->num;
                iap_conv->pattr_dissector = NULL;

                tvb_memcpy(tvb, class_name, offset + 1 + 1, clen);
                class_name[clen] = 0;
                tvb_memcpy(tvb, attr_name, offset + 1 + 1 + clen + 1, alen);
                attr_name[alen] = 0;

                /* Find the attribute dissector */
                for (i = 0; class_dissector[i].class_name != NULL; i++)
                    if (strcmp(class_name, class_dissector[i].class_name) == 0)
                    {
                        for (j = 0; class_dissector[i].pattr_dissector[j].attr_name != NULL; j++)
                            if (strcmp(attr_name, class_dissector[i].pattr_dissector[j].attr_name) == 0)
                            {
                                iap_conv->pattr_dissector = &class_dissector[i].pattr_dissector[j];
                                break;
                            }
                        break;
                    }
            }

            if (check_col(pinfo->cinfo, COL_INFO))
            {
                char    buf[128];


                col_add_str(pinfo->cinfo, COL_INFO, "GetValueByClass: \"");

                tvb_memcpy(tvb, buf, offset + 1 + 1, clen);
                memcpy(&buf[clen], "\" \"", 3);
                tvb_memcpy(tvb, buf + clen + 3, offset + 1 + 1 + clen + 1, alen);
                buf[clen + 3 + alen] = '\"';
                buf[clen + 3 + alen + 1] = 0;
                col_append_str(pinfo->cinfo, COL_INFO, buf);
            }
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_iap, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_iap);

        proto_tree* ctl_tree;


        ti       = proto_tree_add_item(tree, hf_iap_ctl, tvb, offset, 1, FALSE);
        ctl_tree = proto_item_add_subtree(ti, ett_iap_ctl);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_lst, tvb, offset, 1, FALSE);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_ack, tvb, offset, 1, FALSE);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_opcode, tvb, offset, 1, FALSE);
        offset++;

        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                proto_tree_add_item(tree, hf_iap_class_name, tvb, offset, 1, FALSE);
                offset += 1 + clen;

                proto_tree_add_item(tree, hf_iap_attr_name, tvb, offset, 1, FALSE);
                offset += 1 + alen;
                break;
        }
    }
    else
    {
        offset++;
        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                offset += 1 + clen + 1 + alen;
                break;
        }
    }

    /* If any bytes remain, send it to the generic data dissector */
    tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, tvb, pinfo, root);
}


/*
 * Dissect IAP result
 */
static void dissect_iap_result(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    unsigned            offset = 0;
    unsigned            len    = tvb_length(tvb);
    unsigned            n      = 0;
    unsigned            list_len;
    guint8              op;
    guint8              retcode;
    guint8              type;
    guint16             attr_len;
    char                buf[300];
    guint8              src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    iap_conversation_t* cur_iap_conv;
    iap_conversation_t* iap_conv = NULL;
    guint32             num;


    if (tvb_length(tvb) == 0)
        return;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");

    op      = tvb_get_guint8(tvb, offset) & IAP_OP;
    retcode = tvb_get_guint8(tvb, offset + 1);

    src = pinfo->circuit_id ^ CMD_FRAME;
    srcaddr.type  = AT_NONE;
    srcaddr.len   = 1;
    srcaddr.data  = (char*)&src;

    destaddr.type = AT_NONE;
    destaddr.len  = 1;
    destaddr.data = (char*)&pinfo->circuit_id;

    /* Find result value dissector */
    conv = find_conversation(pinfo->fd->num, &srcaddr, &destaddr, PT_NONE, pinfo->srcport, pinfo->destport, 0);
    if (conv)
    {
        num = pinfo->fd->num;

        iap_conv = (iap_conversation_t*)conversation_get_proto_data(conv, proto_iap);
        while (iap_conv && (iap_conv->iap_query_frame >= num))
            iap_conv = iap_conv->pnext;

        if (iap_conv)
        {
            cur_iap_conv = iap_conv->pnext;
            while (cur_iap_conv)
            {
                if ((cur_iap_conv->iap_query_frame < num) &&
                    (cur_iap_conv->iap_query_frame > iap_conv->iap_query_frame))
                {
                    iap_conv = cur_iap_conv;
                }

                cur_iap_conv = cur_iap_conv->pnext;
            }
        }
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_add_str(pinfo->cinfo, COL_INFO, "Result: ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(retcode, iap_return_vals, "0x%02X"));

        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                if (retcode == 0)
                {
                    switch (tvb_get_guint8(tvb, offset + 6))
                    {
                        case IAS_MISSING:
                            strcpy(buf, ", Missing");
                            break;

                        case IAS_INTEGER:
                            sprintf(buf, ", Integer: %d", tvb_get_ntohl(tvb, offset + 7));
                            break;

                        case IAS_OCT_SEQ:
                            sprintf(buf, ", %d Octets", tvb_get_ntohs(tvb, offset + 7));
                            break;

                        case IAS_STRING:
                            strcpy(buf, ", \"");
                            n = tvb_get_guint8(tvb, offset + 8);
                            tvb_memcpy(tvb, buf + 3, offset + 9, n);
                            strcpy(buf + 3 + n, "\"");
                            break;
                    }
                    col_append_str(pinfo->cinfo, COL_INFO, buf);
                    if (tvb_get_ntohs(tvb, offset + 2) > 1)
                        col_append_str(pinfo->cinfo, COL_INFO, ", ...");
                }
                break;
        }
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_iap, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_iap);

        proto_tree* ctl_tree;
        proto_tree* entry_tree;


        ti       = proto_tree_add_item(tree, hf_iap_ctl, tvb, offset, 1, FALSE);
        ctl_tree = proto_item_add_subtree(ti, ett_iap_ctl);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_lst, tvb, offset, 1, FALSE);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_ack, tvb, offset, 1, FALSE);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_opcode, tvb, offset, 1, FALSE);
        offset++;

        proto_tree_add_item(tree, hf_iap_return, tvb, offset, 1, FALSE);
        offset++;

        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                if (retcode == 0)
                {
                    list_len = tvb_get_ntohs(tvb, offset);

                    proto_tree_add_item(tree, hf_iap_list_len, tvb, offset, 2, FALSE);
                    offset += 2;

                    while ((offset < len) && (n < list_len))
                    {
                        type = tvb_get_guint8(tvb, offset + 2);
                        switch (type)
                        {
                            case IAS_INTEGER:
                                attr_len = 4;
                                break;

                            case IAS_OCT_SEQ:
                                attr_len = tvb_get_ntohs(tvb, offset + 2 + 1) + 2;
                                break;

                            case IAS_STRING:
                                attr_len = tvb_get_guint8(tvb, offset + 2 + 1 + 1) + 2;
                                break;

                            default:
                                attr_len = 0;
                        }

                        ti = proto_tree_add_item(tree, hf_iap_list_entry, tvb, offset, 2 + 1 + attr_len, FALSE);
                        g_snprintf(buf, sizeof(buf) - 1, "%d", n + 1);
                        proto_item_append_text(ti, buf);
                        entry_tree = proto_item_add_subtree(ti, ett_iap_entry[n]);

                        proto_tree_add_item(entry_tree, hf_iap_obj_id, tvb, offset, 2, FALSE);
                        offset += 2;

                        proto_tree_add_item(entry_tree, hf_iap_attr_type, tvb, offset, 1, FALSE);
                        offset++;

                        switch (type)
                        {
                            case IAS_INTEGER:
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type))
                                    proto_tree_add_item(entry_tree, hf_iap_int, tvb, offset, 4, FALSE);
                                break;

                            case IAS_OCT_SEQ:
                                proto_tree_add_item(entry_tree, hf_iap_seq_len, tvb, offset, 2, FALSE);
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type))
                                    proto_tree_add_item(entry_tree, hf_iap_oct_seq, tvb, offset + 2,
                                                        attr_len - 2, FALSE);
                                break;

                            case IAS_STRING:
                                proto_tree_add_item(entry_tree, hf_iap_char_set, tvb, offset, 1, FALSE);
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type))
                                    proto_tree_add_item(entry_tree, hf_iap_string, tvb, offset + 1, 1, FALSE);
                                break;
                        }
                        offset += attr_len;

                        n++;
                    }
                }
                break;
        }
    }
    else
    {
        offset += 2;
        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                if (retcode == 0)
                {
                    offset += 2;

                    while (offset < len)
                    {
                        offset += 2;
                        type = tvb_get_guint8(tvb, offset);
                        offset++;

                        switch (type)
                        {
                            case IAS_INTEGER:
                                attr_len = 4;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type);
                                break;

                            case IAS_OCT_SEQ:
                                attr_len = tvb_get_ntohs(tvb, offset) + 2;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type);
                                break;

                            case IAS_STRING:
                                attr_len = tvb_get_guint8(tvb, offset + 1) + 2;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type);

                            default:
                                attr_len = 0;
                        }
                        offset += attr_len;

                        n++;
                    }
                }
                break;
        }
    }

    /* If any bytes remain, send it to the generic data dissector */
    tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, tvb, pinfo, root);
}


/*
 * Check if IAP result is octet sequence
 */
gboolean check_iap_octet_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                const char* attr_name, guint8 attr_type)
{
    if (attr_type != IAS_OCT_SEQ)
    {
        if (tree)
        {
            proto_item* ti = proto_tree_add_item(tree, hf_iap_invaloctet, tvb, offset, 0, FALSE);
            proto_item_append_text(ti, "%s", attr_name);
            proto_item_append_text(ti, "\" attribute must be octet sequence!");
        }

        return FALSE;
    }
    else
        return TRUE;
}


/*
 * Check if IAP result is correct LsapSel
 */
guint8 check_iap_lsap_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                             const char* attr_name, guint8 attr_type)
{
    guint32 lsap;


    if ((attr_type != IAS_INTEGER) || ((lsap = tvb_get_ntohl(tvb, offset)) < 0x01) ||
        (lsap > 0x6F))
    {
        if (tree)
        {
            proto_item* ti = proto_tree_add_item(tree, hf_iap_invallsap, tvb, offset, 0, FALSE);
            proto_item_append_text(ti, "%s", attr_name);
            proto_item_append_text(ti, "\" attribute must be integer value between 0x01 and 0x6F!");
        }

        return 0;
    }
    else
        return lsap;
}


/*
 * Dissect IrDA application protocol
 */
static void dissect_appl_proto(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, pdu_type_t pdu_type)
{
    unsigned            offset = 0;
    guint8              src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    lmp_conversation_t* cur_lmp_conv;
    lmp_conversation_t* lmp_conv = NULL;
    guint32             num;

    
    src = pinfo->circuit_id ^ CMD_FRAME;
    srcaddr.type  = AT_NONE;
    srcaddr.len   = 1;
    srcaddr.data  = (char*)&src;

    destaddr.type = AT_NONE;
    destaddr.len  = 1;
    destaddr.data = (char*)&pinfo->circuit_id;

    /* Find result value dissector */
    conv = find_conversation(pinfo->fd->num, &srcaddr, &destaddr, PT_NONE, pinfo->srcport, pinfo->destport, 0);
    if (conv)
    {
        num = pinfo->fd->num;

        lmp_conv = (lmp_conversation_t*)conversation_get_proto_data(conv, proto_irlmp);
        while (lmp_conv && (lmp_conv->iap_result_frame >= num))
            lmp_conv = lmp_conv->pnext;

        if (lmp_conv)
        {
            cur_lmp_conv = lmp_conv->pnext;
            while (cur_lmp_conv)
            {
                if ((cur_lmp_conv->iap_result_frame < num) &&
                    (cur_lmp_conv->iap_result_frame > lmp_conv->iap_result_frame))
                {
                    lmp_conv = cur_lmp_conv;
                }

                cur_lmp_conv = cur_lmp_conv->pnext;
            }
        }
    }

    if (lmp_conv)
    {
/*g_message("%x:%d->%x:%d = %p\n", src, pinfo->srcport, pinfo->circuit_id, pinfo->destport, lmp_conv); */
/*g_message("->%d: %d %d %p\n", pinfo->fd->num, lmp_conv->iap_result_frame, lmp_conv->ttp, lmp_conv->proto_dissector); */
        if ((lmp_conv->ttp) && (pdu_type != DISCONNECT_PDU))
        {
            offset += dissect_ttp(tvb, pinfo, root, (pdu_type == DATA_PDU));

            tvb = tvb_new_subset(tvb, offset, -1, -1);
        }

        pinfo->private_data = (void *)pdu_type;

        lmp_conv->proto_dissector(tvb, pinfo, root);
    }
    else
        call_dissector(data_handle, tvb, pinfo, root);
}


/*
 * Dissect LMP
 */
static void dissect_irlmp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    unsigned    offset = 0;
    guint8      dlsap;
    guint8      slsap;
    guint8      cbit;
    guint8      opcode = 0;


    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrLMP");

    dlsap = tvb_get_guint8(tvb, offset);
    cbit  = dlsap & CONTROL_BIT;
    dlsap &= ~CONTROL_BIT;

    slsap = tvb_get_guint8(tvb, offset+1) & ~CONTROL_BIT;

    /* save Lsaps in pinfo */
    pinfo->srcport  = slsap;
    pinfo->destport = dlsap;

    if (cbit != 0)
    {
        opcode = tvb_get_guint8(tvb, offset+2);

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d, ", slsap, dlsap);
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, lmp_opcode_vals, "0x%02X"));
            if ((opcode == ACCESSMODE_CMD) || (opcode == ACCESSMODE_CNF))
            {
                col_append_str(pinfo->cinfo, COL_INFO, " (");
                col_append_str(pinfo->cinfo, COL_INFO,
                               val_to_str(tvb_get_guint8(tvb, offset+4), lmp_mode_vals, "0x%02X"));
                col_append_str(pinfo->cinfo, COL_INFO, ")");
            }
        }
    }
    else
        if (check_col(pinfo->cinfo, COL_INFO))
            col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d, Len=%d", slsap, dlsap,
                         tvb_length(tvb) - 2);

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_irlmp, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_irlmp);

        proto_tree* dst_tree;
        proto_tree* src_tree;


        ti       = proto_tree_add_item(tree, hf_lmp_dst, tvb, offset, 1, FALSE);
        dst_tree = proto_item_add_subtree(ti, ett_lmp_dst);
        proto_tree_add_item(dst_tree, hf_lmp_dst_control, tvb, offset, 1, FALSE);
        proto_tree_add_item(dst_tree, hf_lmp_dst_lsap, tvb, offset, 1, FALSE);
        offset++;

        ti       = proto_tree_add_item(tree, hf_lmp_src, tvb, offset, 1, FALSE);
        src_tree = proto_item_add_subtree(ti, ett_lmp_src);
        proto_tree_add_item(src_tree, hf_lmp_src_r, tvb, offset, 1, FALSE);
        proto_tree_add_item(src_tree, hf_lmp_src_lsap, tvb, offset, 1, FALSE);
        offset++;

        if (cbit != 0)
        {
            proto_tree_add_item(tree, hf_lmp_opcode, tvb, offset, 1, FALSE);
            offset++;

            switch (opcode)
            {
                case CONNECT_CMD:
                case CONNECT_CNF:
                    if (offset < tvb_length(tvb))
                    {
                        proto_tree_add_item(tree, hf_lmp_rsvd, tvb, offset, 1, FALSE);
                        offset++;
                    }
                    break;

                case DISCONNECT:
                    proto_tree_add_item(tree, hf_lmp_reason, tvb, offset, 1, FALSE);
                    offset++;
                    break;

                case ACCESSMODE_CMD:
                    proto_tree_add_item(tree, hf_lmp_rsvd, tvb, offset, 1, FALSE);
                    offset++;

                    proto_tree_add_item(tree, hf_lmp_mode, tvb, offset, 1, FALSE);
                    offset++;
                    break;

                case ACCESSMODE_CNF:
                    proto_tree_add_item( tree, hf_lmp_status, tvb, offset, 1, FALSE);
                    offset++;

                    proto_tree_add_item(tree, hf_lmp_mode, tvb, offset, 1, FALSE);
                    offset++;
                    break;
            }
        }

        tvb = tvb_new_subset(tvb, offset, -1, -1);
        proto_item_set_len(tree, offset);
    }
    else
    {
        offset += 2;
        if (cbit != 0)
        {
            offset += 1;

            switch (opcode)
            {
                case CONNECT_CMD:
                case CONNECT_CNF:
                    if (offset < tvb_length(tvb))
                        offset++;
                    break;

                case DISCONNECT:
                    offset++;
                    break;

                case ACCESSMODE_CMD:
                case ACCESSMODE_CNF:
                    offset += 2;
                    break;
            }
        }

        tvb = tvb_new_subset(tvb, offset, -1, -1);
    }

    if (cbit == 0)
    {
        if (dlsap == LSAP_IAS)
            dissect_iap_request(tvb, pinfo, root);
        else if (slsap == LSAP_IAS)
            dissect_iap_result(tvb, pinfo, root);
        else
            dissect_appl_proto(tvb, pinfo, root, DATA_PDU);
    }
    else
    {
        if ((dlsap == LSAP_IAS) || (slsap == LSAP_IAS))
            call_dissector(data_handle, tvb, pinfo, root);
        else
            switch (opcode)
            {
                case CONNECT_CMD:
                case CONNECT_CNF:
                    dissect_appl_proto(tvb, pinfo, root, CONNECT_PDU);
                    break;

                case DISCONNECT:
                    dissect_appl_proto(tvb, pinfo, root, DISCONNECT_PDU);
                    break;

                default:
                    call_dissector(data_handle, tvb, pinfo, root);
            }
    }
}


/*
 * Add LMP conversation
 */
void add_lmp_conversation(packet_info* pinfo, guint8 dlsap, gboolean ttp, dissector_t proto_dissector)
{
    guint8              dest;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    lmp_conversation_t* lmp_conv = NULL;

    
/*g_message("%d: add_lmp_conversation(%p, %d, %d, %p) = ", pinfo->fd->num, pinfo, dlsap, ttp, proto_dissector); */
    srcaddr.type  = AT_NONE;
    srcaddr.len   = 1;
    srcaddr.data  = (char*)&pinfo->circuit_id;

    dest = pinfo->circuit_id ^ CMD_FRAME;
    destaddr.type = AT_NONE;
    destaddr.len  = 1;
    destaddr.data = (char*)&dest;

    conv = find_conversation(pinfo->fd->num, &destaddr, &srcaddr, PT_NONE, dlsap, 0, NO_PORT_B);
    if (conv)
    {
        lmp_conv = (lmp_conversation_t*)conversation_get_proto_data(conv, proto_irlmp);
        while (1)
        {
            /* Does entry already exist? */
            if (lmp_conv->iap_result_frame == pinfo->fd->num)
                return;

            if (lmp_conv->pnext == NULL)
            {
                lmp_conv->pnext = g_mem_chunk_alloc(lmp_conv_chunk);
                lmp_conv = lmp_conv->pnext;
                break;
            }
            lmp_conv = lmp_conv->pnext;
        }
    }
    else
    {
        conv = conversation_new(pinfo->fd->num, &destaddr, &srcaddr, PT_NONE, dlsap, 0, NO_PORT_B);
        lmp_conv = g_mem_chunk_alloc(lmp_conv_chunk);
        conversation_add_proto_data(conv, proto_irlmp, (void*)lmp_conv);
    }

    lmp_conv->pnext            = NULL;
    lmp_conv->iap_result_frame = pinfo->fd->num;
    lmp_conv->ttp              = ttp;
    lmp_conv->proto_dissector  = proto_dissector;

/*g_message("%p\n", lmp_conv); */
}


/*
 * Dissect Negotiation Parameters
 */
static unsigned dissect_negotiation(tvbuff_t* tvb, proto_tree* tree, unsigned offset)
{
    unsigned    n   = 0;
    proto_item* ti;
    proto_tree* p_tree;
    char        buf[256];
    guint8      pv;

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        guint8  p_len = tvb_get_guint8(tvb, offset + 1);

        if (tree)
        {
            ti = proto_tree_add_item(tree, hf_negotiation_param, tvb, offset, p_len + 2, FALSE);
            p_tree = proto_item_add_subtree(ti, ett_param[n]);

            pv = tvb_get_guint8(tvb, offset+2);
            buf[0] = 0;

            switch (tvb_get_guint8(tvb, offset))
            {
                case PI_BAUD_RATE:
                    proto_item_append_text(ti, ": Baud Rate (");

                    if (pv & 0x01)
                        strcat(buf, ", 2400");
                    if (pv & 0x02)
                        strcat(buf, ", 9600");
                    if (pv & 0x04)
                        strcat(buf, ", 19200");
                    if (pv & 0x08)
                        strcat(buf, ", 38400");
                    if (pv & 0x10)
                        strcat(buf, ", 57600");
                    if (pv & 0x20)
                        strcat(buf, ", 115200");
                    if (pv & 0x40)
                        strcat(buf, ", 576000");
                    if (pv & 0x80)
                        strcat(buf, ", 1152000");
                    if ((p_len > 1) && (tvb_get_guint8(tvb, offset+3) & 0x01))
                        strcat(buf, ", 4000000");

                    strcat(buf, " bps)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_MAX_TURN_TIME:
                    proto_item_append_text(ti, ": Maximum Turn Time (");

                    if (pv & 0x01)
                        strcat(buf, ", 500");
                    if (pv & 0x02)
                        strcat(buf, ", 250");
                    if (pv & 0x04)
                        strcat(buf, ", 100");
                    if (pv & 0x08)
                        strcat(buf, ", 50");

                    strcat(buf, " ms)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_DATA_SIZE:
                    proto_item_append_text(ti, ": Data Size (");

                    if (pv & 0x01)
                        strcat(buf, ", 64");
                    if (pv & 0x02)
                        strcat(buf, ", 128");
                    if (pv & 0x04)
                        strcat(buf, ", 256");
                    if (pv & 0x08)
                        strcat(buf, ", 512");
                    if (pv & 0x10)
                        strcat(buf, ", 1024");
                    if (pv & 0x20)
                        strcat(buf, ", 2048");

                    strcat(buf, " bytes)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_WINDOW_SIZE:
                    proto_item_append_text(ti, ": Window Size (");

                    if (pv & 0x01)
                        strcat(buf, ", 1");
                    if (pv & 0x02)
                        strcat(buf, ", 2");
                    if (pv & 0x04)
                        strcat(buf, ", 3");
                    if (pv & 0x08)
                        strcat(buf, ", 4");
                    if (pv & 0x10)
                        strcat(buf, ", 5");
                    if (pv & 0x20)
                        strcat(buf, ", 6");
                    if (pv & 0x40)
                        strcat(buf, ", 7");

                    strcat(buf, " frame window)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_ADD_BOFS:
                    proto_item_append_text(ti, ": Additional BOFs (");

                    if (pv & 0x01)
                        strcat(buf, ", 48");
                    if (pv & 0x02)
                        strcat(buf, ", 24");
                    if (pv & 0x04)
                        strcat(buf, ", 12");
                    if (pv & 0x08)
                        strcat(buf, ", 5");
                    if (pv & 0x10)
                        strcat(buf, ", 3");
                    if (pv & 0x20)
                        strcat(buf, ", 2");
                    if (pv & 0x40)
                        strcat(buf, ", 1");
                    if (pv & 0x80)
                        strcat(buf, ", 0");

                    strcat(buf, " additional BOFs at 115200)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_MIN_TURN_TIME:
                    proto_item_append_text(ti, ": Minimum Turn Time (");

                    if (pv & 0x01)
                        strcat(buf, ", 10");
                    if (pv & 0x02)
                        strcat(buf, ", 5");
                    if (pv & 0x04)
                        strcat(buf, ", 1");
                    if (pv & 0x08)
                        strcat(buf, ", 0.5");
                    if (pv & 0x10)
                        strcat(buf, ", 0.1");
                    if (pv & 0x20)
                        strcat(buf, ", 0.05");
                    if (pv & 0x40)
                        strcat(buf, ", 0.01");
                    if (pv & 0x80)
                        strcat(buf, ", 0");

                    strcat(buf, " ms)");

                    proto_item_append_text(ti, buf+2);

                    break;

                case PI_LINK_DISC:
                    proto_item_append_text(ti, ": Link Disconnect/Threshold Time (");

                    if (pv & 0x01)
                        strcat(buf, ", 3/0");
                    if (pv & 0x02)
                        strcat(buf, ", 8/3");
                    if (pv & 0x04)
                        strcat(buf, ", 12/3");
                    if (pv & 0x08)
                        strcat(buf, ", 16/3");
                    if (pv & 0x10)
                        strcat(buf, ", 20/3");
                    if (pv & 0x20)
                        strcat(buf, ", 25/3");
                    if (pv & 0x40)
                        strcat(buf, ", 30/3");
                    if (pv & 0x80)
                        strcat(buf, ", 40/3");

                    strcat(buf, " s)");

                    proto_item_append_text(ti, buf+2);

                    break;

                default:
                    proto_item_append_text(ti, ": unknown");
            }
        } else
            p_tree = NULL;

        offset = dissect_param_tuple(tvb, p_tree, offset);
        n++;
    }

    return offset;
}


/*
 * Dissect XID packet
 */
static void dissect_xid(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, proto_tree* lap_tree, gboolean is_command)
{
    int         offset = 0;
    proto_item* ti = NULL;
    proto_tree* i_tree = NULL;
    proto_tree* flags_tree;
    guint32     saddr, daddr;
    guint8      s;
    proto_tree* lmp_tree = NULL;

    if (lap_tree)
    {
        ti = proto_tree_add_item(lap_tree, hf_lap_i, tvb, offset, -1, FALSE);
        i_tree = proto_item_add_subtree(ti, ett_lap_i);

        proto_tree_add_item(i_tree, hf_xid_ident, tvb, offset, 1, FALSE);
    }
    offset++;

    saddr = tvb_get_letohl(tvb, offset);
    if (check_col(pinfo->cinfo, COL_DEF_SRC))
        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
    if (lap_tree)
        proto_tree_add_uint(i_tree, hf_xid_saddr, tvb, offset, 4, saddr);
    offset += 4;

    daddr = tvb_get_letohl(tvb, offset);
    if (check_col(pinfo->cinfo, COL_DEF_DST))
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08X", daddr);
    if (lap_tree)
        proto_tree_add_uint(i_tree, hf_xid_daddr, tvb, offset, 4, daddr);
    offset += 4;

    if (lap_tree)
    {
        ti = proto_tree_add_item(i_tree, hf_xid_flags, tvb, offset, 1, FALSE);
        flags_tree = proto_item_add_subtree(ti, ett_xid_flags);
        proto_tree_add_item(flags_tree, hf_xid_s, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_xid_conflict, tvb, offset, 1, FALSE);
    }
    offset++;

    if (is_command)
    {
        s = tvb_get_guint8(tvb, offset);
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            if (s == 0xFF)
                col_append_str(pinfo->cinfo, COL_INFO, ", s=final");
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, ", s=%u", s);
        }
        if (lap_tree)
        {
            ti = proto_tree_add_uint(i_tree, hf_xid_slotnr, tvb, offset, 1, s);
            if (s == 0xFF)
                proto_item_append_text(ti, " (final)");
        }
    }
    offset++;

    if (lap_tree)
        proto_tree_add_item(i_tree, hf_xid_version, tvb, offset, 1, FALSE);
    offset++;

    if (lap_tree)
    {
        proto_item_set_end(lap_tree, tvb, offset);
        proto_item_set_end(i_tree, tvb, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        unsigned    hints_len;
        guint8      hint1 = 0;
        guint8      hint2 = 0;

        if (root)
        {
            ti = proto_tree_add_item(root, proto_irlmp, tvb, offset, -1, FALSE);
            lmp_tree = proto_item_add_subtree(ti, ett_irlmp);
	}

        for (hints_len = 0;;)
        {
            guint8 hint = tvb_get_guint8(tvb, offset + hints_len++);

            if (hints_len == 1)
                hint1 = hint;
            else if (hints_len == 2)
                hint2 = hint;

            if ((hint & 0x80) == 0)
                break;
        }

        if (root)
        {
            ti = proto_tree_add_item(lmp_tree, hf_lmp_xid_hints, tvb, offset, hints_len, FALSE);
            if ((hint1 | hint2) != 0)
            {
                char    service_hints[256];

                service_hints[0] = 0;

                if (hint1 & 0x01)                
                    strcat(service_hints, ", PnP Compatible");
                if (hint1 & 0x02)
                    strcat(service_hints, ", PDA/Palmtop");
                if (hint1 & 0x04)
                    strcat(service_hints, ", Computer");
                if (hint1 & 0x08)
                    strcat(service_hints, ", Printer");
                if (hint1 & 0x10)
                    strcat(service_hints, ", Modem");
                if (hint1 & 0x20)
                    strcat(service_hints, ", Fax");
                if (hint1 & 0x40)
                    strcat(service_hints, ", LAN Access");
                if (hint2 & 0x01)
                    strcat(service_hints, ", Telephony");
                if (hint2 & 0x02)
                    strcat(service_hints, ", File Server");
                if (hint2 & 0x04)
                    strcat(service_hints, ", IrCOMM");
                if (hint2 & 0x20)
                    strcat(service_hints, ", OBEX");

                strcat(service_hints, ")");
                service_hints[0] = ' ';
                service_hints[1] = '(';

                proto_item_append_text(ti, service_hints);
            }
        }
        offset += hints_len;

        if (tvb_reported_length_remaining(tvb, offset) > 0)
        {
            guint8 cset;
            gint name_len;

            cset = tvb_get_guint8(tvb, offset);
            if (root)
                proto_tree_add_uint(lmp_tree, hf_lmp_xid_charset, tvb, offset, 1, cset);
            offset++;
            name_len = tvb_reported_length_remaining(tvb, offset);
            if (name_len > 0)
            {
                if (cset == 0x00)
                {
                    if (check_col(pinfo->cinfo, COL_INFO))
                    {
                        char buf[23];

                        if (name_len > 22)
                            name_len = 22;
                        tvb_memcpy(tvb, buf, offset, name_len);
                        buf[name_len] = 0;
                        col_append_str(pinfo->cinfo, COL_INFO, ", \"");
                        col_append_str(pinfo->cinfo, COL_INFO, buf);
                        col_append_str(pinfo->cinfo, COL_INFO, "\"");
                    }
                    if (root)
                        proto_tree_add_item(lmp_tree, hf_lmp_xid_name, tvb, offset,
                                            -1, FALSE);
                }
                else
                {
                    if (root)
                        proto_tree_add_item(lmp_tree, hf_lmp_xid_name_no_ascii, tvb, offset,
                                            -1, FALSE);
                }
            }
        }
    }
}


/*
 * Dissect Log Messages
 */
static void dissect_log(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Log");

    /* missed messages? */
    if (pinfo->pseudo_header->irda.pkttype == IRDA_MISSED_MSG)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO,
                "WARNING: Missed one or more messages while capturing!");
    }
    else if (check_col(pinfo->cinfo, COL_INFO))
    {
        guint   length;
        char    buf[256];


        length = tvb_length(tvb);
        if (length > sizeof(buf)-1)
            length = sizeof(buf)-1;
        tvb_memcpy(tvb, buf, 0, length);
        buf[length] = 0;
        if (buf[length-1] == '\n')
            buf[length-1] = 0;
        else if (buf[length-2] == '\n')
            buf[length-2] = 0;

        col_add_str(pinfo->cinfo, COL_INFO, buf);
    }

    if (root)
    {
        proto_item* ti   = proto_tree_add_item(root, proto_log, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_log);

        if (pinfo->pseudo_header->irda.pkttype == IRDA_MISSED_MSG)
            proto_tree_add_item(tree, hf_log_missed, tvb, 0, 0, FALSE);
        else
            proto_tree_add_item(tree, hf_log_msg, tvb, 0, -1, FALSE);    
    }
}


/*
 * Dissect IrLAP
 */
static void dissect_irlap(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    int      offset = 0;
    guint8   a, c;
    gboolean is_response;
    char     addr[9];
    proto_item* ti = NULL;
    proto_tree* tree = NULL;
    proto_tree* i_tree = NULL;
    guint32  saddr, daddr;
    guint8   ca;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrLAP");

    /* Clear Info column */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    /* set direction column */
    if (check_col(pinfo->cinfo, COL_IF_DIR))
    {
        switch (pinfo->pseudo_header->irda.pkttype)
        {
            case IRDA_OUTGOING:
                col_set_str(pinfo->cinfo, COL_IF_DIR, "Out");
                break;
                
            case IRDA_INCOMING:
                col_set_str(pinfo->cinfo, COL_IF_DIR, "In");
                break;
        }
    }

    /* decode values used for demuxing */
    a = tvb_get_guint8(tvb, 0);

    /* save connection address field in pinfo */
    pinfo->circuit_id = a;

    /* initially set address columns to connection address */
    g_snprintf(addr, sizeof(addr)-1, "0x%02X", a >> 1);
    if (check_col(pinfo->cinfo, COL_DEF_SRC))
        col_add_str(pinfo->cinfo, COL_DEF_SRC, addr);
    if (check_col(pinfo->cinfo, COL_DEF_DST))
        col_add_str(pinfo->cinfo, COL_DEF_DST, addr);

    if (root)
    {
        proto_tree* a_tree;
        proto_item* addr_item;

        /* create display subtree for the protocol */
        ti   = proto_tree_add_item(root, proto_irlap, tvb, 0, -1, FALSE);
        tree = proto_item_add_subtree(ti, ett_irlap);

        /* create subtree for the address field */
        ti     = proto_tree_add_item(tree, hf_lap_a, tvb, offset, 1, FALSE);
        a_tree = proto_item_add_subtree(ti, ett_lap_a);
        proto_tree_add_item(a_tree, hf_lap_a_cr, tvb, offset, 1, FALSE);
        addr_item = proto_tree_add_item(a_tree, hf_lap_a_address, tvb, offset, 1, FALSE);
        switch (a & ~CMD_FRAME)
        {
            case 0:
                proto_item_append_text(addr_item, " (NULL Address)");
                break;
            case 0xFE:
                proto_item_append_text(addr_item, " (Broadcast)");
                break;
        }
    }
    is_response = ((a & CMD_FRAME) == 0);
    offset++;

    /* process the control field */
    c = dissect_xdlc_control(tvb, 1, pinfo, tree, hf_lap_c,
	    ett_lap_c, &irlap_cf_items, NULL, lap_c_u_cmd_abbr_vals,
	    lap_c_u_rsp_abbr_vals, is_response, FALSE, FALSE);
    offset++;

    if ((c & XDLC_I_MASK) == XDLC_I) {
        /* I frame */
        proto_item_set_len(tree, offset);
        tvb = tvb_new_subset(tvb, offset, -1, -1);
        dissect_irlmp(tvb, pinfo, root);
        return;
    }

    if ((c & 0x03) == XDLC_U) {
    	/* U frame */
        switch (c & XDLC_U_MODIFIER_MASK)
        {
            case XDLC_SNRM:
                if (root)
                {
                    ti = proto_tree_add_item(tree, hf_lap_i, tvb, offset, -1, FALSE);
                    i_tree = proto_item_add_subtree(ti, ett_lap_i);
                }

                saddr = tvb_get_letohl(tvb, offset);
                if (!is_response)
                {
                    if (check_col(pinfo->cinfo, COL_DEF_SRC))
                        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
                }
                if (root)
                    proto_tree_add_uint(i_tree, hf_snrm_saddr, tvb, offset, 4, saddr);
                offset += 4;

                daddr = tvb_get_letohl(tvb, offset);
                if (!is_response)
                {
                    if (check_col(pinfo->cinfo, COL_DEF_DST))
                        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08X", daddr);
                }
                if (root)
                    proto_tree_add_uint(i_tree, hf_snrm_daddr, tvb, offset, 4, daddr);
                offset += 4;

                ca = tvb_get_guint8(tvb, offset);
                if (!is_response)
                {
                    if (check_col(pinfo->cinfo, COL_INFO))
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", ca=0x%02X",
                                        ca >> 1);
                }
                if (root)
                    proto_tree_add_uint(i_tree, hf_snrm_ca, tvb, offset, 1, ca >> 1);
                offset++;

                offset = dissect_negotiation(tvb, i_tree, offset);
                if (root)
                    proto_item_set_end(ti, tvb, offset);
                break;

            case IRDA_XID_CMD:
                tvb = tvb_new_subset(tvb, offset, -1, -1);
                dissect_xid(tvb, pinfo, root, tree, TRUE);
                return;

            case XDLC_UA:
                if (tvb_reported_length_remaining(tvb, offset) > 0)
                {
                    if (root)
                    {
                        ti = proto_tree_add_item(tree, hf_lap_i, tvb, offset, -1, FALSE);
                        i_tree = proto_item_add_subtree(ti, ett_lap_i);
                    }

                    saddr = tvb_get_letohl(tvb, offset);
                    if (check_col(pinfo->cinfo, COL_DEF_SRC))
                        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
                    if (root)
                        proto_tree_add_uint(i_tree, hf_ua_saddr, tvb, offset, 4, saddr);
                    offset += 4;

                    daddr = tvb_get_letohl(tvb, offset);
                    if (check_col(pinfo->cinfo, COL_DEF_DST))
                        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08X", daddr);
                    if (root)
                        proto_tree_add_uint(i_tree, hf_ua_daddr, tvb, offset, 4, daddr);
                    offset += 4;

                    offset = dissect_negotiation(tvb, i_tree, offset);
                    if (root)
                        proto_item_set_end(ti, tvb, offset);
                }
                break;

            case XDLC_XID:
                tvb = tvb_new_subset(tvb, offset, -1, -1);
                dissect_xid(tvb, pinfo, root, tree, FALSE);
                return;
         }
    }

    /* If any bytes remain, send it to the generic data dissector */
    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        tvb = tvb_new_subset(tvb, offset, -1, -1);
        call_dissector(data_handle, tvb, pinfo, root);
    }
}


/*
 * Dissect IrDA protocol
 */
static void dissect_irda(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    /* load the display labels */
    pinfo->current_proto = "IrDA";

    /* check if log message */
    if ((pinfo->pseudo_header->irda.pkttype & IRDA_CLASS_MASK) == IRDA_CLASS_LOG)
    {
        dissect_log(tvb, pinfo, root);
        return;
    }


    dissect_irlap(tvb, pinfo, root);
}


/*
 * Re-initialize the IrDA dissector
 */
static void init_irda(void)
{
    if (iap_conv_chunk)
        g_mem_chunk_destroy(iap_conv_chunk);
    if (lmp_conv_chunk)
        g_mem_chunk_destroy(lmp_conv_chunk);

    iap_conv_chunk = g_mem_chunk_new("iap_conversation", sizeof(iap_conversation_t),
                                     10 * sizeof(iap_conversation_t), G_ALLOC_AND_FREE);
    lmp_conv_chunk = g_mem_chunk_new("lmp_conversation", sizeof(lmp_conversation_t),
                                     10 * sizeof(lmp_conversation_t), G_ALLOC_AND_FREE);
}


/*
 * Register the protocol with Ethereal
 * This format is required because a script is used to build the C function
 *  that calls all the protocol registrations.
 */
void proto_register_irda(void)
{
    unsigned i;

    /* Setup list of header fields */
    static hf_register_info hf_lap[] = {
        { &hf_lap_a,
            { "Address Field", "irlap.a",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lap_a_cr,
            { "C/R", "irlap.a.cr",
                FT_BOOLEAN, 8, TFS(&lap_cr_vals), CMD_FRAME,
                "", HFILL }},
        { &hf_lap_a_address,
            { "Address", "irlap.a.address",
                FT_UINT8, BASE_HEX, NULL, ~CMD_FRAME,
                "", HFILL }},
        { &hf_lap_c,
            { "Control Field", "irlap.c",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lap_c_nr,
            { "N(R)", "irlap.c.n_r",
                FT_UINT8, BASE_DEC, NULL, XDLC_N_R_MASK,
                "", HFILL }},
        { &hf_lap_c_ns,
            { "N(S)", "irlap.c.n_s",
                FT_UINT8, BASE_DEC, NULL, XDLC_N_S_MASK,
                "", HFILL }},
        { &hf_lap_c_p,
            { "Poll", "irlap.c.p",
                FT_BOOLEAN, 8, TFS(&set_notset), XDLC_P_F,
                "", HFILL }},
        { &hf_lap_c_f,
            { "Final", "irlap.c.f",
                FT_BOOLEAN, 8, TFS(&set_notset), XDLC_P_F,
                "", HFILL }},
        { &hf_lap_c_s,
            { "Supervisory frame type", "irlap.c.s_ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_s_vals), XDLC_S_FTYPE_MASK,
                "", HFILL }},
        { &hf_lap_c_u_cmd,
            { "Command", "irlap.c.u_modifier_cmd",
                FT_UINT8, BASE_HEX, VALS(lap_c_u_cmd_vals), XDLC_U_MODIFIER_MASK,
                "", HFILL }},
        { &hf_lap_c_u_rsp,
            { "Response", "irlap.c.u_modifier_resp",
                FT_UINT8, BASE_HEX, VALS(lap_c_u_rsp_vals), XDLC_U_MODIFIER_MASK,
                "", HFILL }},
        { &hf_lap_c_i,
            { "Frame Type", "irlap.c.ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_ftype_vals), XDLC_I_MASK,
                "", HFILL }},
        { &hf_lap_c_s_u,
            { "Frame Type", "irlap.c.ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_ftype_vals), XDLC_S_U_MASK,
                "", HFILL }},
        { &hf_lap_i,
            { "Information Field", "irlap.i",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_snrm_saddr,
            { "Source Device Address", "irlap.snrm.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_snrm_daddr,
            { "Destination Device Address", "irlap.snrm.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_snrm_ca,
            { "Connection Address", "irlap.snrm.ca",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_negotiation_param,
            { "Negotiation Parameter", "irlap.negotiation",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_param_pi,
            { "Parameter Identifier", "irlap.pi",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_param_pl,
            { "Parameter Length", "irlap.pl",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_param_pv,
            { "Parameter Value", "irlap.pv",
                FT_BYTES, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_ua_saddr,
            { "Source Device Address", "irlap.ua.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_ua_daddr,
            { "Destination Device Address", "irlap.ua.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_xid_ident,
            { "Format Identifier", "irlap.xid.fi",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_xid_saddr,
            { "Source Device Address", "irlap.xid.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_xid_daddr,
            { "Destination Device Address", "irlap.xid.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_xid_flags,
            { "Discovery Flags", "irlap.xid.flags",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_xid_s,
            { "Number of Slots", "irlap.xid.s",
                FT_UINT8, BASE_DEC, VALS(&xid_slot_numbers), S_MASK,
                "", HFILL }},
        { &hf_xid_conflict,
            { "Conflict", "irlap.xid.conflict",
                FT_BOOLEAN, 8, TFS(&set_notset), CONFLICT,
                "", HFILL }},
        { &hf_xid_slotnr,
            { "Slot Number", "irlap.xid.slotnr",
                FT_UINT8, BASE_DEC, NULL, 0,
                "", HFILL }},
        { &hf_xid_version,
            { "Version Number", "irlap.xid.version",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }}
    };

    static hf_register_info hf_log[] = {
        { &hf_log_msg,
            { "Message", "log.msg",
                FT_STRING, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_log_missed,
            { "WARNING: Missed one or more messages while capturing!", "log.missed",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }}
    };

    static hf_register_info hf_lmp[] = {
        { &hf_lmp_xid_hints,
            { "Service Hints", "irlmp.xid.hints",
                FT_BYTES, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lmp_xid_charset,
            { "Character Set", "irlmp.xid.charset",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lmp_xid_name,
            { "Device Nickname", "irlmp.xid.name",
                FT_STRING, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_lmp_xid_name_no_ascii,
            { "Device Nickname (unsupported character set)", "irlmp.xid.name",
                FT_BYTES, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_lmp_dst,
            { "Destination", "irlmp.dst",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lmp_dst_control,
            { "Control Bit", "irlmp.dst.c",
                FT_BOOLEAN, 8, TFS(&set_notset), CONTROL_BIT,
                "", HFILL }},
        { &hf_lmp_dst_lsap,
            { "Destination LSAP", "irlmp.dst.lsap",
                FT_UINT8, BASE_DEC, NULL, ~CONTROL_BIT,
                "", HFILL }},
        { &hf_lmp_src,
            { "Source", "irlmp.src",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_lmp_src_r,
            { "reserved", "irlmp.src.r",
                FT_UINT8, BASE_DEC, NULL, RESERVED_BIT,
                "", HFILL }},
        { &hf_lmp_src_lsap,
            { "Source LSAP", "irlmp.src.lsap",
                FT_UINT8, BASE_DEC, NULL, ~RESERVED_BIT,
                "", HFILL }},
        { &hf_lmp_opcode,
            { "Opcode", "irlmp.opcode",
                FT_UINT8, BASE_HEX, VALS(lmp_opcode_vals), 0x0,
                "", HFILL }},
        { &hf_lmp_rsvd,
            { "Reserved", "irlmp.rsvd",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "", HFILL }},
        { &hf_lmp_reason,
            { "Reason", "irlmp.reason",
                FT_UINT8, BASE_HEX, VALS(lmp_reason_vals), 0x0,
                "", HFILL }},
        { &hf_lmp_mode,
            { "Mode", "irlmp.mode",
                FT_UINT8, BASE_HEX, VALS(lmp_mode_vals), 0x0,
                "", HFILL }},
        { &hf_lmp_status,
            { "Status", "irlmp.status",
                FT_UINT8, BASE_HEX, VALS(lmp_status_vals), 0x0,
                "", HFILL }}
    };

    static hf_register_info hf_iap[] = {
        { &hf_iap_ctl,
            { "Control Field", "iap.ctl",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_iap_ctl_lst,
            { "Last Frame", "iap.ctl.lst",
                FT_BOOLEAN, 8, TFS(&set_notset), IAP_LST,
                "", HFILL }},
        { &hf_iap_ctl_ack,
            { "Acknowledge", "iap.ctl.ack",
                FT_BOOLEAN, 8, TFS(&set_notset), IAP_ACK,
                "", HFILL }},
        { &hf_iap_ctl_opcode,
            { "Opcode", "iap.ctl.opcode",
                FT_UINT8, BASE_HEX, VALS(iap_opcode_vals), IAP_OP,
                "", HFILL }},
        { &hf_iap_class_name,
            { "Class Name", "iap.classname",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_attr_name,
            { "Attribute Name", "iap.attrname",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_return,
            { "Return", "iap.return",
                FT_UINT8, BASE_HEX, VALS(iap_return_vals), 0x0,
                "", HFILL }},
        { &hf_iap_list_len,
            { "List Length", "iap.listlen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_list_entry,
            { "List Entry ", "iap.listentry",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_obj_id,
            { "Object Identifier", "iap.objectid",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_attr_type,
            { "Type", "iap.attrtype",
                FT_UINT8, BASE_DEC, VALS(iap_attr_type_vals), 0x0,
                "", HFILL }},
        { &hf_iap_int,
            { "Value", "iap.int",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_seq_len,
            { "Sequence Length", "iap.seqlen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_oct_seq,
            { "Sequence", "iap.octseq",
                FT_BYTES, BASE_HEX, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_char_set,
            { "Character Set", "iap.charset",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_string,
            { "String", "iap.string",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                "", HFILL }},
        { &hf_iap_invaloctet,
            { "Mailformed IAP result: \"", "iap.invaloctet",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_iap_invallsap,
            { "Mailformed IAP result: \"", "iap.invallsap",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }}
    };

    static hf_register_info hf_ttp[] = {
        { &hf_ttp_p,
            { "Parameter Bit", "ttp.p",
                FT_BOOLEAN, 8, TFS(&set_notset), TTP_PARAMETERS,
                "", HFILL }},
        { &hf_ttp_icredit,
            { "Initial Credit", "ttp.icredit",
                FT_UINT8, BASE_DEC, NULL, ~TTP_PARAMETERS,
                "", HFILL }},
        { &hf_ttp_m,
            { "More Bit", "ttp.m",
                FT_BOOLEAN, 8, TFS(&set_notset), TTP_MORE,
                "", HFILL }},
        { &hf_ttp_dcredit,
            { "Delta Credit", "ttp.dcredit",
                FT_UINT8, BASE_DEC, NULL, ~TTP_MORE,
                "", HFILL }}
    };

    /* Setup protocol subtree arrays */
    static gint* ett[] = {
        &ett_irlap,
        &ett_lap_a,
        &ett_lap_c,
        &ett_lap_i,
        &ett_xid_flags,
        &ett_log,
        &ett_irlmp,
        &ett_lmp_dst,
        &ett_lmp_src,
        &ett_iap,
        &ett_iap_ctl,
        &ett_ttp
    };

    static gint* ett_p[MAX_PARAMETERS];
    static gint* ett_iap_e[MAX_IAP_ENTRIES];


    /* Register re-init routine */
    register_init_routine(init_irda);

    /* Register protocol names and descriptions */
    proto_irlap = proto_register_protocol("IrDA Link Access Protocol", "IrLAP", "irlap");
    proto_log   = proto_register_protocol("Log Message", "Log", "log");
    proto_irlmp = proto_register_protocol("IrDA Link Management Protocol", "IrLMP", "irlmp");
    proto_iap   = proto_register_protocol("Information Access Protocol", "IAP", "iap");
    proto_ttp   = proto_register_protocol("Tiny Transport Protocol", "TTP", "ttp");

    /* Register the dissector */
    register_dissector("irda", dissect_irda, proto_irlap);

    /* Required function calls to register the header fields */
    proto_register_field_array(proto_irlap, hf_lap, array_length(hf_lap));
    proto_register_field_array(proto_log, hf_log, array_length(hf_log));
    proto_register_field_array(proto_irlmp, hf_lmp, array_length(hf_lmp));
    proto_register_field_array(proto_iap, hf_iap, array_length(hf_iap));
    proto_register_field_array(proto_ttp, hf_ttp, array_length(hf_ttp));

    /* Register subtrees */
    proto_register_subtree_array(ett, array_length(ett));
    for (i = 0; i < MAX_PARAMETERS; i++)
    {
        ett_param[i] = -1;
        ett_p[i]     = &ett_param[i];
    }
    proto_register_subtree_array(ett_p, MAX_PARAMETERS);
    for (i = 0; i < MAX_IAP_ENTRIES; i++)
    {
        ett_iap_entry[i] = -1;
        ett_iap_e[i]     = &ett_iap_entry[i];
    }
    proto_register_subtree_array(ett_iap_e, MAX_IAP_ENTRIES);
}


/* If this dissector uses sub-dissector registration add a registration routine.
	This format is required because a script is used to find these routines and
	create the code that calls these routines.
*/

void proto_reg_handoff_irda(void)
{
    dissector_handle_t irda_handle;

    irda_handle = find_dissector("irda");
    dissector_add("wtap_encap", WTAP_ENCAP_IRDA, irda_handle);
    data_handle = find_dissector("data");
}
