/* packet-irda.c
 * Routines for IrDA dissection
 * By Shaun Jackman <sjackman@pathwayconnect.com>
 * Copyright 2000 Shaun Jackman
 *
 * Extended by Jan Kiszka <jan.kiszka@web.de>
 * Copyright 2003 Jan Kiszka
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/xdlc.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wiretap/wtap.h>

#include <epan/dissectors/packet-sll.h>
#include "irda-appl.h"

/*
 * This plugin dissects infrared data transmissions as defined by IrDA
 * specifications.  See
 *
 *    https://web.archive.org/web/20040405053146/http://www.irda.org/standards/specifications.asp
 *
 * or
 *
 *    https://archive.org/search?query=creator%3A%22Infrared+Data+Association%22
 *
 * for various IrDA specifications, including a zip archive of the IrPHY
 * 1.4, IrLAP 1.1, IrLMP 1.1, IrDA Tiny TP 1.1, and IrDA Point and Shoot
 * Profile 1.1 and Test Specification 1.0 at
 *
 *    https://web.archive.org/web/20040405053146/http://www.irda.org/standards/pubs/IrData.zip
 *
 * or the the IrLAP 1.1 specification at
 *
 *    https://archive.org/details/ir-lap-11
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

void proto_reg_handoff_irda(void);
void proto_register_irda(void);

/* Initialize the protocol and registered fields */
static int proto_irlap;
static int hf_lap_a;
static int hf_lap_a_cr;
static int hf_lap_a_address;
static int hf_lap_c;
static int hf_lap_c_nr;
static int hf_lap_c_ns;
static int hf_lap_c_p;
static int hf_lap_c_f;
static int hf_lap_c_s;
static int hf_lap_c_u_cmd;
static int hf_lap_c_u_rsp;
static int hf_lap_c_i;
static int hf_lap_c_s_u;
static int hf_lap_i;
static int hf_snrm_saddr;
static int hf_snrm_daddr;
static int hf_snrm_ca;
static int hf_ua_saddr;
static int hf_ua_daddr;
static int hf_negotiation_param;
static int hf_param_pi;
static int hf_param_pl;
static int hf_param_pv;
static int hf_xid_ident;
static int hf_xid_saddr;
static int hf_xid_daddr;
static int hf_xid_flags;
static int hf_xid_s;
static int hf_xid_conflict;
static int hf_xid_slotnr;
static int hf_xid_version;

static int proto_irlmp;
static int hf_lmp_xid_hints;
static int hf_lmp_xid_charset;
static int hf_lmp_xid_name;
static int hf_lmp_xid_name_no_encoding;
static int hf_lmp_dst;
static int hf_lmp_dst_control;
static int hf_lmp_dst_lsap;
static int hf_lmp_src;
static int hf_lmp_src_r;
static int hf_lmp_src_lsap;
static int hf_lmp_opcode;
static int hf_lmp_rsvd;
static int hf_lmp_reason;
static int hf_lmp_mode;
static int hf_lmp_status;

static int proto_iap;
static int hf_iap_ctl;
static int hf_iap_ctl_lst;
static int hf_iap_ctl_ack;
static int hf_iap_ctl_opcode;
static int hf_iap_class_name;
static int hf_iap_attr_name;
static int hf_iap_return;
static int hf_iap_list_len;
static int hf_iap_list_entry;
static int hf_iap_obj_id;
static int hf_iap_attr_type;
static int hf_iap_int;
static int hf_iap_seq_len;
static int hf_iap_oct_seq;
static int hf_iap_char_set;
static int hf_iap_string;
static int hf_iap_invaloctet;
static int hf_iap_invallsap;

static int proto_ttp;
static int hf_ttp_p;
static int hf_ttp_icredit;
static int hf_ttp_m;
static int hf_ttp_dcredit;

static int proto_log;
static int hf_log_msg;
static int hf_log_missed;

/* Initialize the subtree pointers */
static int ett_irlap;
static int ett_lap_a;
static int ett_lap_c;
static int ett_lap_i;
static int ett_xid_flags;
static int ett_log;
static int ett_irlmp;
static int ett_lmp_dst;
static int ett_lmp_src;
static int ett_iap;
static int ett_iap_ctl;
static int ett_ttp;

#define MAX_PARAMETERS      32
static int ett_param[MAX_PARAMETERS];

static int ett_iap_entry[MAX_IAP_ENTRIES];

static int irda_address_type = -1;

static dissector_handle_t irda_handle;

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
    uint32_t                    iap_query_frame;
    ias_attr_dissector_t* pattr_dissector;
} iap_conversation_t;

/* IrLMP conversation type */
typedef struct lmp_conversation {
    struct lmp_conversation*    pnext;
    uint32_t                    iap_result_frame;
    bool                        ttp;
    dissector_handle_t          dissector;
} lmp_conversation_t;

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

#define LMP_CHARSET_ASCII      0
#define LMP_CHARSET_ISO_8859_1 1
#define LMP_CHARSET_ISO_8859_2 2
#define LMP_CHARSET_ISO_8859_3 3
#define LMP_CHARSET_ISO_8859_4 4
#define LMP_CHARSET_ISO_8859_5 5
#define LMP_CHARSET_ISO_8859_6 6
#define LMP_CHARSET_ISO_8859_7 7
#define LMP_CHARSET_ISO_8859_8 8
#define LMP_CHARSET_ISO_8859_9 9
#define LMP_CHARSET_UNICODE    0xFF /* UCS-2 (byte order?) */

static const value_string lmp_charset_vals[] = {
/* IrLMP character set */
    { LMP_CHARSET_ASCII,      "ASCII" },
    { LMP_CHARSET_ISO_8859_1, "ISO 8859-1" },
    { LMP_CHARSET_ISO_8859_2, "ISO 8859-2" },
    { LMP_CHARSET_ISO_8859_3, "ISO 8859-3" },
    { LMP_CHARSET_ISO_8859_4, "ISO 8859-4" },
    { LMP_CHARSET_ISO_8859_5, "ISO 8859-5" },
    { LMP_CHARSET_ISO_8859_6, "ISO 8859-6" },
    { LMP_CHARSET_ISO_8859_7, "ISO 8859-7" },
    { LMP_CHARSET_ISO_8859_8, "ISO 8859-8" },
    { LMP_CHARSET_ISO_8859_9, "ISO 8859-9" },
    { LMP_CHARSET_UNICODE,    "Unicode" },
    { 0,                      NULL }
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
    uint8_t len = tvb_get_uint8(tvb, offset + 1);

    if (tree)
        proto_tree_add_item(tree, hf_param_pi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (tree)
        proto_tree_add_item(tree, hf_param_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (len > 0)
    {
        if (tree)
            proto_tree_add_item(tree, hf_param_pv, tvb, offset, len, ENC_NA);
        offset += len;
    }

    return offset;
}


/*
 * Dissect TTP
 */
static unsigned dissect_ttp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, bool data)
{
    unsigned  offset = 0;
    uint8_t head;
    char   buf[128];

    if (tvb_reported_length(tvb) == 0)
        return 0;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TTP");

    head = tvb_get_uint8(tvb, offset);

    snprintf(buf, 128, ", Credit=%d", head & ~TTP_PARAMETERS);
    col_append_str(pinfo->cinfo, COL_INFO, buf);

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_ttp, tvb, 0, -1, ENC_NA);
        proto_tree* tree = proto_item_add_subtree(ti, ett_ttp);

        if (data)
        {
            proto_tree_add_item(tree, hf_ttp_m, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_ttp_dcredit, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
        else
        {
            proto_tree_add_item(tree, hf_ttp_p, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_ttp_icredit, tvb, offset, 1, ENC_BIG_ENDIAN);
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
static void dissect_iap_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, uint8_t circuit_id)
{
    unsigned            offset = 0;
    uint8_t             op;
    uint8_t             clen = 0;
    uint8_t             alen = 0;
    uint8_t             src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    iap_conversation_t* iap_conv;

    if (tvb_reported_length(tvb) == 0)
        return;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");

    op = tvb_get_uint8(tvb, offset) & IAP_OP;

    switch (op)
    {
        case GET_VALUE_BY_CLASS:
            clen = MIN(tvb_get_uint8(tvb, offset + 1), 60);
            alen = MIN(tvb_get_uint8(tvb, offset + 1 + 1 + clen), 60);

            /* create conversation entry */
            src = circuit_id ^ CMD_FRAME;
            set_address(&srcaddr, irda_address_type, 1, &src);

            set_address(&destaddr, irda_address_type, 1, &circuit_id);

            conv = find_conversation(pinfo->num, &srcaddr, &destaddr, CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
            if (conv)
            {
                iap_conv = (iap_conversation_t*)conversation_get_proto_data(conv, proto_iap);
                while (1)
                {
                    if (iap_conv->iap_query_frame == pinfo->num)
                    {
                        iap_conv = NULL;
                        break;
                    }
                    if (iap_conv->pnext == NULL)
                    {
                        iap_conv->pnext = wmem_new(wmem_file_scope(), iap_conversation_t);
                        iap_conv = iap_conv->pnext;
                        break;
                    }
                    iap_conv = iap_conv->pnext;
                }
            }
            else
            {
                conv = conversation_new(pinfo->num, &srcaddr, &destaddr, CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
                iap_conv = wmem_new(wmem_file_scope(), iap_conversation_t);
                conversation_add_proto_data(conv, proto_iap, (void*)iap_conv);
            }
            if (iap_conv)
            {
                iap_conv->pnext           = NULL;
                iap_conv->iap_query_frame = pinfo->num;
                iap_conv->pattr_dissector = NULL;
            }

            char   *class_name = (char *) tvb_get_string_enc(pinfo->pool, tvb, offset + 1 + 1, clen, ENC_ASCII|ENC_NA);
            char   *attr_name = (char *) tvb_get_string_enc(pinfo->pool, tvb, offset + 1 + 1 + clen + 1, alen, ENC_ASCII|ENC_NA);

            col_add_fstr(pinfo->cinfo, COL_INFO, "GetValueByClass: \"%s\" \"%s\"",
                format_text(pinfo->pool, (unsigned char *) class_name, strlen(class_name)),
                format_text(pinfo->pool, (unsigned char *) attr_name, strlen(attr_name)));

            /* Dissect IAP query if it is new */
            if (iap_conv)
            {
                int     i, j;

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
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_iap, tvb, 0, -1, ENC_NA);
        proto_tree* tree = proto_item_add_subtree(ti, ett_iap);

        proto_tree* ctl_tree;


        ti       = proto_tree_add_item(tree, hf_iap_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
        ctl_tree = proto_item_add_subtree(ti, ett_iap_ctl);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_lst, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                proto_tree_add_item(tree, hf_iap_class_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                offset += 1 + clen;

                proto_tree_add_item(tree, hf_iap_attr_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
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
    tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(tvb, pinfo, root);
}


/*
 * Dissect IAP result
 */
static void dissect_iap_result(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, uint8_t circuit_id)
{
    unsigned            offset = 0;
    unsigned            len    = tvb_reported_length(tvb);
    unsigned            n      = 0;
    unsigned            list_len;
    uint8_t             op;
    uint8_t             retcode;
    uint8_t             type;
    uint16_t            attr_len;
    char                buf[300];
    uint8_t             src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    iap_conversation_t* cur_iap_conv;
    iap_conversation_t* iap_conv = NULL;
    uint32_t            num;


    if (len == 0)
        return;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");

    op      = tvb_get_uint8(tvb, offset) & IAP_OP;
    retcode = tvb_get_uint8(tvb, offset + 1);

    src = circuit_id ^ CMD_FRAME;
    set_address(&srcaddr, irda_address_type, 1, &src);

    set_address(&destaddr, irda_address_type, 1, &circuit_id);

    /* Find result value dissector */
    conv = find_conversation(pinfo->num, &srcaddr, &destaddr, CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
    if (conv)
    {
        num = pinfo->num;

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

    col_set_str(pinfo->cinfo, COL_INFO, "Result: ");
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(retcode, iap_return_vals, "0x%02X"));

    switch (op)
    {
        case GET_VALUE_BY_CLASS:
            if (retcode == 0)
            {
                switch (tvb_get_uint8(tvb, offset + 6))
                {
                    case IAS_MISSING:
                        col_append_str(pinfo->cinfo, COL_INFO, ", Missing");
                        break;

                    case IAS_INTEGER:
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", Integer: %d", tvb_get_ntohl(tvb, offset + 7));
                        break;

                    case IAS_OCT_SEQ:
                        snprintf(buf, 300, ", %d Octets", tvb_get_ntohs(tvb, offset + 7));
                        break;

                    case IAS_STRING:
                        n = tvb_get_uint8(tvb, offset + 8);
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", \"%s\"", tvb_get_string_enc(pinfo->pool, tvb, offset + 9, n, ENC_ASCII));
                        break;
                    default:
                        break;
                }
                if (tvb_get_ntohs(tvb, offset + 2) > 1)
                    col_append_str(pinfo->cinfo, COL_INFO, ", ...");
            }
            break;
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_iap, tvb, 0, -1, ENC_NA);
        proto_tree* tree = proto_item_add_subtree(ti, ett_iap);

        proto_tree* ctl_tree;
        proto_tree* entry_tree;


        ti       = proto_tree_add_item(tree, hf_iap_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
        ctl_tree = proto_item_add_subtree(ti, ett_iap_ctl);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_lst, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ctl_tree, hf_iap_ctl_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_iap_return, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch (op)
        {
            case GET_VALUE_BY_CLASS:
                if (retcode == 0)
                {
                    list_len = tvb_get_ntohs(tvb, offset);

                    proto_tree_add_item(tree, hf_iap_list_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    while ((offset < len) && (n < list_len))
                    {
                        type = tvb_get_uint8(tvb, offset + 2);
                        switch (type)
                        {
                            case IAS_INTEGER:
                                attr_len = 4;
                                break;

                            case IAS_OCT_SEQ:
                                attr_len = tvb_get_ntohs(tvb, offset + 2 + 1) + 2;
                                break;

                            case IAS_STRING:
                                attr_len = tvb_get_uint8(tvb, offset + 2 + 1 + 1) + 2;
                                break;

                            default:
                                attr_len = 0;
                        }

                        ti = proto_tree_add_item(tree, hf_iap_list_entry, tvb, offset, 2 + 1 + attr_len, ENC_NA);
                        proto_item_append_text(ti, "%d", n + 1);
                        entry_tree = proto_item_add_subtree(ti, ett_iap_entry[n]);

                        proto_tree_add_item(entry_tree, hf_iap_obj_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;

                        proto_tree_add_item(entry_tree, hf_iap_attr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        switch (type)
                        {
                            case IAS_INTEGER:
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type, circuit_id))
                                    proto_tree_add_item(entry_tree, hf_iap_int, tvb, offset, 4, ENC_BIG_ENDIAN);
                                break;

                            case IAS_OCT_SEQ:
                                proto_tree_add_item(entry_tree, hf_iap_seq_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type, circuit_id))
                                    proto_tree_add_item(entry_tree, hf_iap_oct_seq, tvb, offset + 2,
                                                        attr_len - 2, ENC_NA);
                                break;

                            case IAS_STRING:
                                proto_tree_add_item(entry_tree, hf_iap_char_set, tvb, offset, 1, ENC_BIG_ENDIAN);
                                if (!iap_conv || !iap_conv->pattr_dissector ||
                                    !iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, entry_tree,
                                                                                n, type, circuit_id))
                                    proto_tree_add_item(entry_tree, hf_iap_string, tvb, offset + 1, 1, ENC_ASCII|ENC_BIG_ENDIAN);
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
                        type = tvb_get_uint8(tvb, offset);
                        offset++;

                        switch (type)
                        {
                            case IAS_INTEGER:
                                attr_len = 4;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type, circuit_id);
                                break;

                            case IAS_OCT_SEQ:
                                attr_len = tvb_get_ntohs(tvb, offset) + 2;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type, circuit_id);
                                break;

                            case IAS_STRING:
                                attr_len = tvb_get_uint8(tvb, offset + 1) + 2;
                                if (iap_conv && iap_conv->pattr_dissector)
                                    iap_conv->pattr_dissector->value_dissector(tvb, offset, pinfo, 0,
                                                                               n, type, circuit_id);
                                break;

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
    tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(tvb, pinfo, root);
}


/*
 * Check if IAP result is octet sequence
 */
bool check_iap_octet_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                const char* attr_name, uint8_t attr_type)
{
    if (attr_type != IAS_OCT_SEQ)
    {
        if (tree)
        {
            proto_item* ti = proto_tree_add_item(tree, hf_iap_invaloctet, tvb, offset, 0, ENC_NA);
            proto_item_append_text(ti, "%s", attr_name);
            proto_item_append_text(ti, "\" attribute must be octet sequence!");
        }

        return false;
    }
    else
        return true;
}


/*
 * Check if IAP result is correct LsapSel
 */
uint8_t check_iap_lsap_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                             const char* attr_name, uint8_t attr_type)
{
    uint32_t lsap;


    if ((attr_type != IAS_INTEGER) || ((lsap = tvb_get_ntohl(tvb, offset)) < 0x01) ||
        (lsap > 0x6F))
    {
        if (tree)
        {
            proto_item* ti = proto_tree_add_item(tree, hf_iap_invallsap, tvb, offset, 0, ENC_NA);
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
static void dissect_appl_proto(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, pdu_type_t pdu_type, uint8_t circuit_id)
{
    unsigned            offset = 0;
    uint8_t             src;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    lmp_conversation_t* cur_lmp_conv;
    lmp_conversation_t* lmp_conv = NULL;
    uint32_t            num;


    src = circuit_id ^ CMD_FRAME;
    set_address(&srcaddr, irda_address_type, 1, &src);

    set_address(&destaddr, irda_address_type, 1, &circuit_id);

    /* Find result value dissector */
    conv = find_conversation(pinfo->num, &srcaddr, &destaddr, CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
    if (conv)
    {
        num = pinfo->num;

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
/*ws_message("%x:%d->%x:%d = %p\n", src, pinfo->srcport, circuit_id, pinfo->destport, lmp_conv); */
/*ws_message("->%d: %d %d %p\n", pinfo->num, lmp_conv->iap_result_frame, lmp_conv->ttp, lmp_conv->proto_dissector); */
        if ((lmp_conv->ttp) && (pdu_type != DISCONNECT_PDU))
        {
            offset += dissect_ttp(tvb, pinfo, root, (pdu_type == DATA_PDU));

            tvb = tvb_new_subset_remaining(tvb, offset);
        }

        call_dissector_with_data(lmp_conv->dissector, tvb, pinfo, root, GUINT_TO_POINTER(pdu_type));
    }
    else
        call_data_dissector(tvb, pinfo, root);
}


/*
 * Dissect LMP
 */
static void dissect_irlmp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, uint8_t circuit_id)
{
    unsigned    offset = 0;
    uint8_t     dlsap;
    uint8_t     slsap;
    uint8_t     cbit;
    uint8_t     opcode = 0;


    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrLMP");

    dlsap = tvb_get_uint8(tvb, offset);
    cbit  = dlsap & CONTROL_BIT;
    dlsap &= ~CONTROL_BIT;

    slsap = tvb_get_uint8(tvb, offset+1) & ~CONTROL_BIT;

    /* save Lsaps in pinfo */
    pinfo->srcport  = slsap;
    pinfo->destport = dlsap;

    if (cbit != 0)
    {
        opcode = tvb_get_uint8(tvb, offset+2);

        col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d, ", slsap, dlsap);
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, lmp_opcode_vals, "0x%02X"));
        if ((opcode == ACCESSMODE_CMD) || (opcode == ACCESSMODE_CNF))
        {
            col_append_str(pinfo->cinfo, COL_INFO, " (");
            col_append_str(pinfo->cinfo, COL_INFO,
                           val_to_str(tvb_get_uint8(tvb, offset+4), lmp_mode_vals, "0x%02X"));
            col_append_str(pinfo->cinfo, COL_INFO, ")");
        }
    }
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d, Len=%d", slsap, dlsap,
                     tvb_reported_length(tvb) - 2);

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_irlmp, tvb, 0, -1, ENC_NA);
        proto_tree* tree = proto_item_add_subtree(ti, ett_irlmp);

        proto_tree* dst_tree;
        proto_tree* src_tree;


        ti       = proto_tree_add_item(tree, hf_lmp_dst, tvb, offset, 1, ENC_BIG_ENDIAN);
        dst_tree = proto_item_add_subtree(ti, ett_lmp_dst);
        proto_tree_add_item(dst_tree, hf_lmp_dst_control, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dst_tree, hf_lmp_dst_lsap, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        ti       = proto_tree_add_item(tree, hf_lmp_src, tvb, offset, 1, ENC_BIG_ENDIAN);
        src_tree = proto_item_add_subtree(ti, ett_lmp_src);
        proto_tree_add_item(src_tree, hf_lmp_src_r, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(src_tree, hf_lmp_src_lsap, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (cbit != 0)
        {
            proto_tree_add_item(tree, hf_lmp_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            switch (opcode)
            {
                case CONNECT_CMD:
                case CONNECT_CNF:
                    if (offset < tvb_reported_length(tvb))
                    {
                        proto_tree_add_item(tree, hf_lmp_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    }
                    break;

                case DISCONNECT:
                    proto_tree_add_item(tree, hf_lmp_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;

                case ACCESSMODE_CMD:
                    proto_tree_add_item(tree, hf_lmp_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;

                    proto_tree_add_item(tree, hf_lmp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;

                case ACCESSMODE_CNF:
                    proto_tree_add_item( tree, hf_lmp_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;

                    proto_tree_add_item(tree, hf_lmp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;
            }
        }

        tvb = tvb_new_subset_remaining(tvb, offset);
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
                    if (offset < tvb_reported_length(tvb))
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

        tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (cbit == 0)
    {
        if (dlsap == LSAP_IAS)
            dissect_iap_request(tvb, pinfo, root, circuit_id);
        else if (slsap == LSAP_IAS)
            dissect_iap_result(tvb, pinfo, root, circuit_id);
        else
            dissect_appl_proto(tvb, pinfo, root, DATA_PDU, circuit_id);
    }
    else
    {
        if ((dlsap == LSAP_IAS) || (slsap == LSAP_IAS))
            call_data_dissector(tvb, pinfo, root);
        else
            switch (opcode)
            {
                case CONNECT_CMD:
                case CONNECT_CNF:
                    dissect_appl_proto(tvb, pinfo, root, CONNECT_PDU, circuit_id);
                    break;

                case DISCONNECT:
                    dissect_appl_proto(tvb, pinfo, root, DISCONNECT_PDU, circuit_id);
                    break;

                default:
                    call_data_dissector(tvb, pinfo, root);
            }
    }
}


/*
 * Add LMP conversation
 */
void add_lmp_conversation(packet_info* pinfo, uint8_t dlsap, bool ttp, dissector_handle_t dissector, uint8_t circuit_id)
{
    uint8_t             dest;
    address             srcaddr;
    address             destaddr;
    conversation_t*     conv;
    lmp_conversation_t* lmp_conv = NULL;


/*ws_message("%d: add_lmp_conversation(%p, %d, %d, %p) = ", pinfo->num, pinfo, dlsap, ttp, proto_dissector); */
    set_address(&srcaddr, irda_address_type, 1, &circuit_id);
    dest = circuit_id ^ CMD_FRAME;
    set_address(&destaddr, irda_address_type, 1, &dest);

    conv = find_conversation(pinfo->num, &destaddr, &srcaddr, CONVERSATION_NONE, dlsap, 0, NO_PORT_B);
    if (conv)
    {
        lmp_conv = (lmp_conversation_t*)conversation_get_proto_data(conv, proto_irlmp);
        while (1)
        {
            /* Does entry already exist? */
            if (lmp_conv->iap_result_frame == pinfo->num)
                return;

            if (lmp_conv->pnext == NULL)
            {
                lmp_conv->pnext = wmem_new(wmem_file_scope(), lmp_conversation_t);
                lmp_conv = lmp_conv->pnext;
                break;
            }
            lmp_conv = lmp_conv->pnext;
        }
    }
    else
    {
        conv = conversation_new(pinfo->num, &destaddr, &srcaddr, CONVERSATION_NONE, dlsap, 0, NO_PORT2);
        lmp_conv = wmem_new(wmem_file_scope(), lmp_conversation_t);
        conversation_add_proto_data(conv, proto_irlmp, (void*)lmp_conv);
    }

    lmp_conv->pnext            = NULL;
    lmp_conv->iap_result_frame = pinfo->num;
    lmp_conv->ttp              = ttp;
    lmp_conv->dissector        = dissector;

/*ws_message("%p\n", lmp_conv); */
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
    uint8_t     pv;

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        uint8_t p_len = tvb_get_uint8(tvb, offset + 1);

        if (tree)
        {
            ti = proto_tree_add_item(tree, hf_negotiation_param, tvb, offset, p_len + 2, ENC_NA);
            p_tree = proto_item_add_subtree(ti, ett_param[n]);

            pv = tvb_get_uint8(tvb, offset+2);
            buf[0] = 0;

            switch (tvb_get_uint8(tvb, offset))
            {
                case PI_BAUD_RATE:
                    proto_item_append_text(ti, ": Baud Rate (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 2400", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 9600", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 19200", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 38400", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 57600", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 115200", 256);
                    if (pv & 0x40)
                        (void) g_strlcat(buf, ", 576000", 256);
                    if (pv & 0x80)
                        (void) g_strlcat(buf, ", 1152000", 256);
                    if ((p_len > 1) && (tvb_get_uint8(tvb, offset+3) & 0x01))
                        (void) g_strlcat(buf, ", 4000000", 256);

                    (void) g_strlcat(buf, " bps)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_MAX_TURN_TIME:
                    proto_item_append_text(ti, ": Maximum Turn Time (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 500", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 250", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 100", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 50", 256);

                    (void) g_strlcat(buf, " ms)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_DATA_SIZE:
                    proto_item_append_text(ti, ": Data Size (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 64", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 128", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 256", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 512", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 1024", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 2048", 256);

                    (void) g_strlcat(buf, " bytes)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_WINDOW_SIZE:
                    proto_item_append_text(ti, ": Window Size (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 1", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 2", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 3", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 4", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 5", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 6", 256);
                    if (pv & 0x40)
                        (void) g_strlcat(buf, ", 7", 256);

                    (void) g_strlcat(buf, " frame window)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_ADD_BOFS:
                    proto_item_append_text(ti, ": Additional BOFs (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 48", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 24", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 12", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 5", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 3", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 2", 256);
                    if (pv & 0x40)
                        (void) g_strlcat(buf, ", 1", 256);
                    if (pv & 0x80)
                        (void) g_strlcat(buf, ", 0", 256);

                    (void) g_strlcat(buf, " additional BOFs at 115200)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_MIN_TURN_TIME:
                    proto_item_append_text(ti, ": Minimum Turn Time (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 10", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 5", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 1", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 0.5", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 0.1", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 0.05", 256);
                    if (pv & 0x40)
                        (void) g_strlcat(buf, ", 0.01", 256);
                    if (pv & 0x80)
                        (void) g_strlcat(buf, ", 0", 256);

                    (void) g_strlcat(buf, " ms)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case PI_LINK_DISC:
                    proto_item_append_text(ti, ": Link Disconnect/Threshold Time (");

                    if (pv & 0x01)
                        (void) g_strlcat(buf, ", 3/0", 256);
                    if (pv & 0x02)
                        (void) g_strlcat(buf, ", 8/3", 256);
                    if (pv & 0x04)
                        (void) g_strlcat(buf, ", 12/3", 256);
                    if (pv & 0x08)
                        (void) g_strlcat(buf, ", 16/3", 256);
                    if (pv & 0x10)
                        (void) g_strlcat(buf, ", 20/3", 256);
                    if (pv & 0x20)
                        (void) g_strlcat(buf, ", 25/3", 256);
                    if (pv & 0x40)
                        (void) g_strlcat(buf, ", 30/3", 256);
                    if (pv & 0x80)
                        (void) g_strlcat(buf, ", 40/3", 256);

                    (void) g_strlcat(buf, " s)", 256);

                    proto_item_append_text(ti, "%s", buf+2);

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
static void dissect_xid(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, proto_tree* lap_tree, bool is_command)
{
    int         offset = 0;
    proto_item* ti = NULL;
    proto_tree* i_tree = NULL;
    proto_tree* flags_tree;
    uint32_t    saddr, daddr;
    uint8_t     s;
    proto_tree* lmp_tree = NULL;

    if (lap_tree)
    {
        ti = proto_tree_add_item(lap_tree, hf_lap_i, tvb, offset, -1, ENC_NA);
        i_tree = proto_item_add_subtree(ti, ett_lap_i);

        proto_tree_add_item(i_tree, hf_xid_ident, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    saddr = tvb_get_letohl(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
    if (lap_tree)
        proto_tree_add_uint(i_tree, hf_xid_saddr, tvb, offset, 4, saddr);
    offset += 4;

    daddr = tvb_get_letohl(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08X", daddr);
    if (lap_tree)
        proto_tree_add_uint(i_tree, hf_xid_daddr, tvb, offset, 4, daddr);
    offset += 4;

    if (lap_tree)
    {
        /* Discovery flags */
        ti = proto_tree_add_item(i_tree, hf_xid_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(ti, ett_xid_flags);
        proto_tree_add_item(flags_tree, hf_xid_s, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_xid_conflict, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    if (is_command)
    {
        s = tvb_get_uint8(tvb, offset);
        if (s == 0xFF)
            col_append_str(pinfo->cinfo, COL_INFO, ", s=final");
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, ", s=%u", s);
        if (lap_tree)
        {
            ti = proto_tree_add_uint(i_tree, hf_xid_slotnr, tvb, offset, 1, s);
            if (s == 0xFF)
                proto_item_append_text(ti, " (final)");
        }
    }
    /* Skip (empty?) byte even if no command.. Have seen non-zero values in a capture */
    offset++;

    if (lap_tree)
        proto_tree_add_item(i_tree, hf_xid_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (lap_tree)
    {
        proto_item_set_end(lap_tree, tvb, offset);
        proto_item_set_end(i_tree, tvb, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        unsigned hints_len;
        uint8_t     hint1 = 0;
        uint8_t     hint2 = 0;

        if (root)
        {
            ti = proto_tree_add_item(root, proto_irlmp, tvb, offset, -1, ENC_NA);
            lmp_tree = proto_item_add_subtree(ti, ett_irlmp);
        }

        for (hints_len = 0;;)
        {
            uint8_t hint = tvb_get_uint8(tvb, offset + hints_len++);

            if (hints_len == 1)
                hint1 = hint;
            else if (hints_len == 2)
                hint2 = hint;

            if ((hint & 0x80) == 0)
                break;
        }

        if (root)
        {
            ti = proto_tree_add_item(lmp_tree, hf_lmp_xid_hints, tvb, offset, hints_len, ENC_NA);
            if ((hint1 | hint2) != 0)
            {
                char    service_hints[256];

                service_hints[0] = 0;

                if (hint1 & 0x01)
                    (void) g_strlcat(service_hints, ", PnP Compatible", 256);
                if (hint1 & 0x02)
                    (void) g_strlcat(service_hints, ", PDA/Palmtop", 256);
                if (hint1 & 0x04)
                    (void) g_strlcat(service_hints, ", Computer", 256);
                if (hint1 & 0x08)
                    (void) g_strlcat(service_hints, ", Printer", 256);
                if (hint1 & 0x10)
                    (void) g_strlcat(service_hints, ", Modem", 256);
                if (hint1 & 0x20)
                    (void) g_strlcat(service_hints, ", Fax", 256);
                if (hint1 & 0x40)
                    (void) g_strlcat(service_hints, ", LAN Access", 256);
                if (hint2 & 0x01)
                    (void) g_strlcat(service_hints, ", Telephony", 256);
                if (hint2 & 0x02)
                    (void) g_strlcat(service_hints, ", File Server", 256);
                if (hint2 & 0x04)
                    (void) g_strlcat(service_hints, ", IrCOMM", 256);
                if (hint2 & 0x20)
                    (void) g_strlcat(service_hints, ", OBEX", 256);

                (void) g_strlcat(service_hints, ")", 256);
                service_hints[0] = ' ';
                service_hints[1] = '(';

                proto_item_append_text(ti, "%s", service_hints);
            }
        }
        offset += hints_len;

        if (tvb_reported_length_remaining(tvb, offset) > 0)
        {
            uint8_t cset;
            int name_len;
            char *name;
            bool have_encoding;
            unsigned  encoding;

            cset = tvb_get_uint8(tvb, offset);
            if (root)
                proto_tree_add_uint(lmp_tree, hf_lmp_xid_charset, tvb, offset, 1, cset);
            offset++;
            name_len = tvb_reported_length_remaining(tvb, offset);
            if (name_len > 0)
            {
                switch (cset) {

                case LMP_CHARSET_ASCII:
                    encoding = ENC_ASCII|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_1:
                    encoding = ENC_ISO_8859_1|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_2:
                    encoding = ENC_ISO_8859_2|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_3:
                    encoding = ENC_ISO_8859_3|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_4:
                    encoding = ENC_ISO_8859_4|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_5:
                    encoding = ENC_ISO_8859_5|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_6:
                    encoding = ENC_ISO_8859_6|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_7:
                    encoding = ENC_ISO_8859_7|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_8:
                    encoding = ENC_ISO_8859_8|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_ISO_8859_9:
                    encoding = ENC_ISO_8859_9|ENC_NA;
                    have_encoding = true;
                    break;

                case LMP_CHARSET_UNICODE:
                    /* Presumably big-endian; assume just UCS-2 for now */
                    encoding = ENC_UCS_2|ENC_BIG_ENDIAN;
                    have_encoding = true;
                    break;

                default:
                    encoding = 0;
                    have_encoding = false;
                    break;
                }

                if (have_encoding)
                {
                    name = (char *) tvb_get_string_enc(pinfo->pool, tvb, offset, name_len, encoding);
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", \"%s\"", format_text(pinfo->pool, (unsigned char *) name, strlen(name)));
                    if (root)
                        proto_tree_add_item(lmp_tree, hf_lmp_xid_name, tvb, offset,
                                            -1, encoding);
                }
                else
                {
                    if (root)
                        proto_tree_add_item(lmp_tree, hf_lmp_xid_name_no_encoding, tvb, offset,
                                            -1, ENC_NA);
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Log");

    /* missed messages? */
    if (pinfo->pseudo_header->irda.pkttype == IRDA_MISSED_MSG)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "WARNING: Missed one or more messages while capturing!");
    }
    else
    {
        unsigned   length;
        char   *buf;

        length = tvb_captured_length(tvb);
        buf = (char *) tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_ASCII|ENC_NA);
        if (length > 0 && buf[length-1] == '\n')
            buf[length-1] = 0;
        else if (length > 1 && buf[length-2] == '\n')
            buf[length-2] = 0;

        col_add_str(pinfo->cinfo, COL_INFO, format_text(pinfo->pool, (unsigned char *) buf, strlen(buf)));
    }

    if (root)
    {
        proto_item* ti   = proto_tree_add_item(root, proto_log, tvb, 0, -1, ENC_NA);
        proto_tree* tree = proto_item_add_subtree(ti, ett_log);

        if (pinfo->pseudo_header->irda.pkttype == IRDA_MISSED_MSG)
            proto_tree_add_item(tree, hf_log_missed, tvb, 0, 0, ENC_NA);
        else
            proto_tree_add_item(tree, hf_log_msg, tvb, 0, -1, ENC_ASCII);
    }
}


/*
 * Dissect IrLAP
 */
static void dissect_irlap(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    int      offset = 0;
    uint8_t  circuit_id, c;
    bool is_response;
    char     addr[9];
    proto_item* ti = NULL;
    proto_tree* tree = NULL;
    proto_tree* i_tree = NULL;
    uint32_t saddr, daddr;
    uint8_t  ca;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrLAP");

    /* Clear Info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* set direction column */
    switch (pinfo->pseudo_header->irda.pkttype)
    {
        case IRDA_OUTGOING:
            col_set_str(pinfo->cinfo, COL_IF_DIR, "Out");
            break;

        case IRDA_INCOMING:
            col_set_str(pinfo->cinfo, COL_IF_DIR, "In");
            break;
    }

    /* decode values used for demuxing */
    circuit_id = tvb_get_uint8(tvb, 0);

    /* initially set address columns to connection address */
    snprintf(addr, sizeof(addr)-1, "0x%02X", circuit_id >> 1);
    col_add_str(pinfo->cinfo, COL_DEF_SRC, addr);
    col_add_str(pinfo->cinfo, COL_DEF_DST, addr);

    if (root)
    {
        proto_tree* a_tree;
        proto_item* addr_item;

        /* create display subtree for the protocol */
        ti   = proto_tree_add_item(root, proto_irlap, tvb, 0, -1, ENC_NA);
        tree = proto_item_add_subtree(ti, ett_irlap);

        /* create subtree for the address field */
        ti     = proto_tree_add_item(tree, hf_lap_a, tvb, offset, 1, ENC_BIG_ENDIAN);
        a_tree = proto_item_add_subtree(ti, ett_lap_a);
        proto_tree_add_item(a_tree, hf_lap_a_cr, tvb, offset, 1, ENC_BIG_ENDIAN);
        addr_item = proto_tree_add_item(a_tree, hf_lap_a_address, tvb, offset, 1, ENC_BIG_ENDIAN);
        switch (circuit_id & ~CMD_FRAME)
        {
            case 0:
                proto_item_append_text(addr_item, " (NULL Address)");
                break;
            case 0xFE:
                proto_item_append_text(addr_item, " (Broadcast)");
                break;
        }
    }
    is_response = ((circuit_id & CMD_FRAME) == 0);
    offset++;

    /* process the control field */
    c = dissect_xdlc_control(tvb, offset, pinfo, tree, hf_lap_c,
            ett_lap_c, &irlap_cf_items, NULL, lap_c_u_cmd_abbr_vals,
            lap_c_u_rsp_abbr_vals, is_response, false, false);
    offset++;

    if ((c & XDLC_I_MASK) == XDLC_I) {
        /* I frame */
        proto_item_set_len(tree, offset);
        tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_irlmp(tvb, pinfo, root, circuit_id);
        return;
    }

    if ((c & XDLC_S_U_MASK) == XDLC_U) {
        /* U frame */
        switch (c & XDLC_U_MODIFIER_MASK)
        {
            case XDLC_SNRM:
                if (root)
                {
                    ti = proto_tree_add_item(tree, hf_lap_i, tvb, offset, -1, ENC_NA);
                    i_tree = proto_item_add_subtree(ti, ett_lap_i);
                }

                saddr = tvb_get_letohl(tvb, offset);
                if (!is_response)
                {
                    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
                }
                if (root)
                    proto_tree_add_uint(i_tree, hf_snrm_saddr, tvb, offset, 4, saddr);
                offset += 4;

                daddr = tvb_get_letohl(tvb, offset);
                if (!is_response)
                {
                    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08X", daddr);
                }
                if (root)
                    proto_tree_add_uint(i_tree, hf_snrm_daddr, tvb, offset, 4, daddr);
                offset += 4;

                ca = tvb_get_uint8(tvb, offset);
                if (!is_response)
                {
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
                tvb = tvb_new_subset_remaining(tvb, offset);
                dissect_xid(tvb, pinfo, root, tree, true);
                return;

            case XDLC_UA:
                if (tvb_reported_length_remaining(tvb, offset) > 0)
                {
                    if (root)
                    {
                        ti = proto_tree_add_item(tree, hf_lap_i, tvb, offset, -1, ENC_NA);
                        i_tree = proto_item_add_subtree(ti, ett_lap_i);
                    }

                    saddr = tvb_get_letohl(tvb, offset);
                    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08X", saddr);
                    if (root)
                        proto_tree_add_uint(i_tree, hf_ua_saddr, tvb, offset, 4, saddr);
                    offset += 4;

                    daddr = tvb_get_letohl(tvb, offset);
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
                tvb = tvb_new_subset_remaining(tvb, offset);
                dissect_xid(tvb, pinfo, root, tree, false);
                return;
         }
    }

    /* If any bytes remain, send it to the generic data dissector */
    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(tvb, pinfo, root);
    }
}


/*
 * Dissect IrDA protocol
 */
static int dissect_irda(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, void* data _U_)
{
    /* check if log message */
    if ((pinfo->pseudo_header->irda.pkttype & IRDA_CLASS_MASK) == IRDA_CLASS_LOG)
    {
        dissect_log(tvb, pinfo, root);
        return tvb_captured_length(tvb);
    }


    dissect_irlap(tvb, pinfo, root);
    return tvb_captured_length(tvb);
}

static int irda_addr_to_str(const address* addr, char *buf, int buf_len _U_)
{
    const uint8_t *addrdata = (const uint8_t *)addr->data;

    uint32_to_str_buf(*addrdata, buf, buf_len);
    return (int)strlen(buf);
}

static int irda_addr_str_len(const address* addr _U_)
{
    return 11; /* Leaves required space (10 bytes) for uint_to_str_back() */
}

static const char* irda_col_filter_str(const address* addr _U_, bool is_src _U_)
{
    return "irlap.a";
}

static int irda_addr_len(void)
{
    return 1;
}

/*
 * Register the protocol with Wireshark
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
                NULL, HFILL }},
        { &hf_lap_a_cr,
            { "C/R", "irlap.a.cr",
                FT_BOOLEAN, 8, TFS(&lap_cr_vals), CMD_FRAME,
                NULL, HFILL }},
        { &hf_lap_a_address,
            { "Address", "irlap.a.address",
                FT_UINT8, BASE_HEX, NULL, ~CMD_FRAME,
                NULL, HFILL }},
        { &hf_lap_c,
            { "Control Field", "irlap.c",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_lap_c_nr,
            { "N(R)", "irlap.c.n_r",
                FT_UINT8, BASE_DEC, NULL, XDLC_N_R_MASK,
                NULL, HFILL }},
        { &hf_lap_c_ns,
            { "N(S)", "irlap.c.n_s",
                FT_UINT8, BASE_DEC, NULL, XDLC_N_S_MASK,
                NULL, HFILL }},
        { &hf_lap_c_p,
            { "Poll", "irlap.c.p",
                FT_BOOLEAN, 8, TFS(&set_notset), XDLC_P_F,
                NULL, HFILL }},
        { &hf_lap_c_f,
            { "Final", "irlap.c.f",
                FT_BOOLEAN, 8, TFS(&set_notset), XDLC_P_F,
                NULL, HFILL }},
        { &hf_lap_c_s,
            { "Supervisory frame type", "irlap.c.s_ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_s_vals), XDLC_S_FTYPE_MASK,
                NULL, HFILL }},
        { &hf_lap_c_u_cmd,
            { "Command", "irlap.c.u_modifier_cmd",
                FT_UINT8, BASE_HEX, VALS(lap_c_u_cmd_vals), XDLC_U_MODIFIER_MASK,
                NULL, HFILL }},
        { &hf_lap_c_u_rsp,
            { "Response", "irlap.c.u_modifier_resp",
                FT_UINT8, BASE_HEX, VALS(lap_c_u_rsp_vals), XDLC_U_MODIFIER_MASK,
                NULL, HFILL }},
        { &hf_lap_c_i,
            { "Frame Type", "irlap.c.ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_ftype_vals), XDLC_I_MASK,
                NULL, HFILL }},
        { &hf_lap_c_s_u,
            { "Frame Type", "irlap.c.ftype",
                FT_UINT8, BASE_HEX, VALS(lap_c_ftype_vals), XDLC_S_U_MASK,
                NULL, HFILL }},
        { &hf_lap_i,
            { "Information Field", "irlap.i",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_snrm_saddr,
            { "Source Device Address", "irlap.snrm.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_snrm_daddr,
            { "Destination Device Address", "irlap.snrm.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_snrm_ca,
            { "Connection Address", "irlap.snrm.ca",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_negotiation_param,
            { "Negotiation Parameter", "irlap.negotiation",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_param_pi,
            { "Parameter Identifier", "irlap.pi",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_param_pl,
            { "Parameter Length", "irlap.pl",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_param_pv,
            { "Parameter Value", "irlap.pv",
                FT_BYTES, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_ua_saddr,
            { "Source Device Address", "irlap.ua.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_ua_daddr,
            { "Destination Device Address", "irlap.ua.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_ident,
            { "Format Identifier", "irlap.xid.fi",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_saddr,
            { "Source Device Address", "irlap.xid.saddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_daddr,
            { "Destination Device Address", "irlap.xid.daddr",
                FT_UINT32, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_flags,
            { "Discovery Flags", "irlap.xid.flags",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_s,
            { "Number of Slots", "irlap.xid.s",
                FT_UINT8, BASE_DEC, VALS(xid_slot_numbers), S_MASK,
                NULL, HFILL }},
        { &hf_xid_conflict,
            { "Conflict", "irlap.xid.conflict",
                FT_BOOLEAN, 8, TFS(&set_notset), CONFLICT,
                NULL, HFILL }},
        { &hf_xid_slotnr,
            { "Slot Number", "irlap.xid.slotnr",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }},
        { &hf_xid_version,
            { "Version Number", "irlap.xid.version",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }}
    };

    static hf_register_info hf_log[] = {
        { &hf_log_msg,
            { "Message", "log.msg",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_log_missed,
            { "WARNING: Missed one or more messages while capturing!", "log.missed",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }}
    };

    static hf_register_info hf_lmp[] = {
        { &hf_lmp_xid_hints,
            { "Service Hints", "irlmp.xid.hints",
                FT_BYTES, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_lmp_xid_charset,
            { "Character Set", "irlmp.xid.charset",
                FT_UINT8, BASE_HEX, VALS(lmp_charset_vals), 0,
                NULL, HFILL }},
        { &hf_lmp_xid_name,
            { "Device Nickname", "irlmp.xid.name",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_lmp_xid_name_no_encoding,
            { "Device Nickname (unsupported character set)", "irlmp.xid.name.no_encoding",
                FT_BYTES, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_lmp_dst,
            { "Destination", "irlmp.dst",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_lmp_dst_control,
            { "Control Bit", "irlmp.dst.c",
                FT_BOOLEAN, 8, TFS(&set_notset), CONTROL_BIT,
                NULL, HFILL }},
        { &hf_lmp_dst_lsap,
            { "Destination LSAP", "irlmp.dst.lsap",
                FT_UINT8, BASE_DEC, NULL, ~CONTROL_BIT,
                NULL, HFILL }},
        { &hf_lmp_src,
            { "Source", "irlmp.src",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_lmp_src_r,
            { "reserved", "irlmp.src.r",
                FT_UINT8, BASE_DEC, NULL, RESERVED_BIT,
                NULL, HFILL }},
        { &hf_lmp_src_lsap,
            { "Source LSAP", "irlmp.src.lsap",
                FT_UINT8, BASE_DEC, NULL, ~RESERVED_BIT,
                NULL, HFILL }},
        { &hf_lmp_opcode,
            { "Opcode", "irlmp.opcode",
                FT_UINT8, BASE_HEX, VALS(lmp_opcode_vals), 0x0,
                NULL, HFILL }},
        { &hf_lmp_rsvd,
            { "Reserved", "irlmp.rsvd",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_lmp_reason,
            { "Reason", "irlmp.reason",
                FT_UINT8, BASE_HEX, VALS(lmp_reason_vals), 0x0,
                NULL, HFILL }},
        { &hf_lmp_mode,
            { "Mode", "irlmp.mode",
                FT_UINT8, BASE_HEX, VALS(lmp_mode_vals), 0x0,
                NULL, HFILL }},
        { &hf_lmp_status,
            { "Status", "irlmp.status",
                FT_UINT8, BASE_HEX, VALS(lmp_status_vals), 0x0,
                NULL, HFILL }}
    };

    static hf_register_info hf_iap[] = {
        { &hf_iap_ctl,
            { "Control Field", "iap.ctl",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_iap_ctl_lst,
            { "Last Frame", "iap.ctl.lst",
                FT_BOOLEAN, 8, TFS(&set_notset), IAP_LST,
                NULL, HFILL }},
        { &hf_iap_ctl_ack,
            { "Acknowledge", "iap.ctl.ack",
                FT_BOOLEAN, 8, TFS(&set_notset), IAP_ACK,
                NULL, HFILL }},
        { &hf_iap_ctl_opcode,
            { "Opcode", "iap.ctl.opcode",
                FT_UINT8, BASE_HEX, VALS(iap_opcode_vals), IAP_OP,
                NULL, HFILL }},
        { &hf_iap_class_name,
            { "Class Name", "iap.classname",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_attr_name,
            { "Attribute Name", "iap.attrname",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_return,
            { "Return", "iap.return",
                FT_UINT8, BASE_HEX, VALS(iap_return_vals), 0x0,
                NULL, HFILL }},
        { &hf_iap_list_len,
            { "List Length", "iap.listlen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_list_entry,
            { "List Entry", "iap.listentry",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_obj_id,
            { "Object Identifier", "iap.objectid",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_attr_type,
            { "Type", "iap.attrtype",
                FT_UINT8, BASE_DEC, VALS(iap_attr_type_vals), 0x0,
                NULL, HFILL }},
        { &hf_iap_int,
            { "Value", "iap.int",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_seq_len,
            { "Sequence Length", "iap.seqlen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_oct_seq,
            { "Sequence", "iap.octseq",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_char_set,
            { "Character Set", "iap.charset",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_string,
            { "String", "iap.string",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_iap_invaloctet,
            { "Malformed IAP result: \"", "iap.invaloctet",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_iap_invallsap,
            { "Malformed IAP result: \"", "iap.invallsap",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }}
    };

    static hf_register_info hf_ttp[] = {
        { &hf_ttp_p,
            { "Parameter Bit", "ttp.p",
                FT_BOOLEAN, 8, TFS(&set_notset), TTP_PARAMETERS,
                NULL, HFILL }},
        { &hf_ttp_icredit,
            { "Initial Credit", "ttp.icredit",
                FT_UINT8, BASE_DEC, NULL, ~TTP_PARAMETERS,
                NULL, HFILL }},
        { &hf_ttp_m,
            { "More Bit", "ttp.m",
                FT_BOOLEAN, 8, TFS(&set_notset), TTP_MORE,
                NULL, HFILL }},
        { &hf_ttp_dcredit,
            { "Delta Credit", "ttp.dcredit",
                FT_UINT8, BASE_DEC, NULL, ~TTP_MORE,
                NULL, HFILL }}
    };

    /* Setup protocol subtree arrays */
    static int* ett[] = {
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

    int* ett_p[MAX_PARAMETERS];
    int* ett_iap_e[MAX_IAP_ENTRIES];


    /* Register protocol names and descriptions */
    proto_irlap = proto_register_protocol("IrDA Link Access Protocol", "IrLAP", "irlap");
    proto_log   = proto_register_protocol("Log Message", "Log", "log");
    proto_irlmp = proto_register_protocol("IrDA Link Management Protocol", "IrLMP", "irlmp");
    proto_iap   = proto_register_protocol("Information Access Protocol", "IAP", "iap");
    proto_ttp   = proto_register_protocol("Tiny Transport Protocol", "TTP", "ttp");

    /* Register the dissector */
    irda_handle = register_dissector("irda", dissect_irda, proto_irlap);

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
        ett_p[i]     = &ett_param[i];
    }
    proto_register_subtree_array(ett_p, MAX_PARAMETERS);
    for (i = 0; i < MAX_IAP_ENTRIES; i++)
    {
        ett_iap_e[i]     = &ett_iap_entry[i];
    }
    proto_register_subtree_array(ett_iap_e, MAX_IAP_ENTRIES);

    irda_address_type = address_type_dissector_register("AT_IRDA", "IRDA Address", irda_addr_to_str, irda_addr_str_len, NULL, irda_col_filter_str, irda_addr_len, NULL, NULL);
}


/* If this dissector uses sub-dissector registration add a registration routine.
        This format is required because a script is used to find these routines and
        create the code that calls these routines.
*/

void proto_reg_handoff_irda(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_IRDA, irda_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IRDA_LAP, irda_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
