/* packet-iso7816.c
 * Routines for packet dissection of generic ISO 7816 smart card messages
 * Copyright 2012-2013 by Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This dissector supports the command and response apdu structure
 * as defined in ISO 7816-4. Detailed dissection of the APDUs defined
 * in the ISO 7816 specifications will be added in the future.
 *
 * The dissection of Answer To Reset (ATR) messages was made a separate
 * protocol so that it can be shared easily.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>

void proto_register_iso7816(void);
void proto_reg_handoff_iso7816(void);

static int proto_iso7816;
static int proto_iso7816_atr;

static dissector_handle_t iso7816_handle;
static dissector_handle_t iso7816_atr_handle;

static wmem_tree_t *transactions;

static dissector_table_t iso7816_apdu_pld_table;

static int ett_iso7816;
static int ett_iso7816_class;
static int ett_iso7816_param;
static int ett_iso7816_p1;
static int ett_iso7816_p2;
static int ett_iso7816_atr;
static int ett_iso7816_atr_ta;
static int ett_iso7816_atr_td;

static int hf_iso7816_atr_init_char;
static int hf_iso7816_atr_t0;
static int hf_iso7816_atr_ta;
/* these two fields hold the converted values Fi and Di,
   not the binary representations FI and DI */
static int hf_iso7816_atr_ta1_fi;
static int hf_iso7816_atr_ta1_di;
static int hf_iso7816_atr_tb;
static int hf_iso7816_atr_tc;
static int hf_iso7816_atr_td;
static int hf_iso7816_atr_next_ta_present;
static int hf_iso7816_atr_next_tb_present;
static int hf_iso7816_atr_next_tc_present;
static int hf_iso7816_atr_next_td_present;
static int hf_iso7816_atr_k;
static int hf_iso7816_atr_t;
static int hf_iso7816_atr_hist_bytes;
static int hf_iso7816_atr_tck;

static int hf_iso7816_resp_in;
static int hf_iso7816_resp_to;
static int hf_iso7816_cla;
static int hf_iso7816_cla_sm;
static int hf_iso7816_cla_channel;
static int hf_iso7816_ins;
static int hf_iso7816_p1;
static int hf_iso7816_p2;
static int hf_iso7816_lc;
static int hf_iso7816_le;
static int hf_iso7816_body;
static int hf_iso7816_sw1;
static int hf_iso7816_sw2;
static int hf_iso7816_sel_file_ctrl;
static int hf_iso7816_sel_file_fci_req;
static int hf_iso7816_sel_file_occ;
static int hf_iso7816_read_rec_ef;
static int hf_iso7816_read_rec_usage;
static int hf_iso7816_get_resp;
static int hf_iso7816_offset_first_byte;
static int hf_iso7816_rfu;
static int hf_iso7816_application_data;

static expert_field ei_iso7816_atr_tck_not1;

#define ADDR_INTF "Interface"
#define ADDR_CARD "Card"

typedef struct _iso7816_transaction_t {
    uint32_t cmd_frame;
    uint32_t resp_frame;
    uint8_t  cmd_ins;  /* instruction byte in the command apdu */
    /* no need to add the channel number,
       the response contains no channel number to compare this to
       and the spec explicitly prohibits interleaving of command-response
       pairs, regardless of logical channels */
    dissector_handle_t handle;
} iso7816_transaction_t;

static const value_string iso7816_atr_init_char[] = {
    { 0x3B, "Direct convention (A==0, Z==1, MSB==m9)" },
    { 0x3F, "Inverse convention (A==1, Z==0, MSB==m2)" },
    { 0, NULL }
};

static const value_string iso7816_cla_sm[] = {
    { 0x00, "No SM" },
    { 0x01, "Proprietary SM" },
    { 0x02, "SM, command header not authenticated" },
    { 0x03, "SM, command header authenticated" },
    { 0, NULL }
};

#define INS_ERASE_BIN      0x0E
#define INS_VRFY           0x20
#define INS_MANAGE_CHANNEL 0x70
#define INS_EXT_AUTH       0x82
#define INS_GET_CHALLENGE  0x84
#define INS_SELECT_FILE    0xA4
#define INS_READ_BIN       0xB0
#define INS_READ_REC       0xB2
#define INS_GET_RESP       0xC0
#define INS_ENVELOPE       0xC2
#define INS_GET_DATA       0xCA
#define INS_WRITE_BIN      0xD0
#define INS_WRITE_REC      0xD2
#define INS_UPDATE_BIN     0xD6
#define INS_PUT_DATA       0xDA
#define INS_UPDATE_REC     0xDC
#define INS_APPEND_REC     0xE2
/* for our transaction tracking, not defined in the specification */
#define INS_INVALID        0x00

static const value_string iso7816_ins[] = {
    /* instructions defined in ISO 7816-4 */
    { INS_ERASE_BIN,      "Erase binary" },
    { INS_VRFY,           "Verify" },
    { INS_MANAGE_CHANNEL, "Manage channel" },
    { INS_EXT_AUTH,       "External authenticate" },
    { INS_GET_CHALLENGE,  "Get challenge" },
    { INS_SELECT_FILE,    "Select file" },
    { INS_READ_BIN,       "Read binary" },
    { INS_READ_REC,       "Read record" },
    { INS_GET_RESP,       "Get response" },
    { INS_ENVELOPE,       "Envelope" },
    { INS_GET_DATA,       "Get data" },
    { INS_WRITE_BIN,      "Write binary" },
    { INS_WRITE_REC,      "Write record" },
    { INS_UPDATE_BIN,     "Update binary" },
    { INS_PUT_DATA,       "Put data" },
    { INS_UPDATE_REC,     "Update record" },
    { INS_APPEND_REC,     "Append record" },
    { 0, NULL }
};
static value_string_ext iso7816_ins_ext = VALUE_STRING_EXT_INIT(iso7816_ins);

static const value_string iso7816_sel_file_ctrl[] = {
    { 0x00, "Select MF, DF or EF" },
    { 0x01, "Select child DF" },
    { 0x02, "Select EF under current DF" },
    { 0x03, "Select parent DF of the current DF" },
    { 0x04, "Direct selection by DF name" },
    { 0x08, "Selection by path from MF" },
    { 0x09, "Selection by path from current DF" },
    { 0, NULL }
};
static value_string_ext ext_iso7816_sel_file_ctrl =
    VALUE_STRING_EXT_INIT(iso7816_sel_file_ctrl);

static const value_string iso7816_sel_file_fci_req[] = {
    { 0x00, "Return FCI, optional template" },
    { 0x01, "Return FCP template" },
    { 0x02, "Return FMD template" },
    { 0, NULL }
};
static value_string_ext ext_iso7816_sel_file_fci_req =
    VALUE_STRING_EXT_INIT(iso7816_sel_file_fci_req);

static const value_string iso7816_sel_file_occ[] = {
    { 0x00, "First or only occurrence" },
    { 0x01, "Last occurrence" },
    { 0x02, "Next occurrence" },
    { 0x03, "Previous occurrence" },
    { 0, NULL }
};
static value_string_ext ext_iso7816_sel_file_occ =
    VALUE_STRING_EXT_INIT(iso7816_sel_file_occ);

#define READ_REC_USAGE_SINGLE 0x04
#define READ_REC_USAGE_START  0x05
static const value_string iso7816_read_rec_usage[] = {
    { READ_REC_USAGE_SINGLE, "Read record P1" },
    { READ_REC_USAGE_START,  "Read all records from P1 up to the last" },
    { 0, NULL }
};
static value_string_ext ext_iso7816_read_rec_usage =
    VALUE_STRING_EXT_INIT(iso7816_read_rec_usage);

static const range_string iso7816_sw1[] = {
  { 0x61, 0x61, "Normal processing" },
  { 0x62, 0x63, "Warning processing" },
  { 0x64, 0x65, "Execution error" },
  { 0x67, 0x6F, "Checking error" },
  { 0x90, 0x90, "Normal processing" },
  { 0,0,  NULL }
};

static const range_string iso7816_class_rvals[] = {
    {0x00, 0x0F, "structure and coding according to ISO/IEC 7816" },
    {0x10, 0x7F, "reserved for future use" },
    {0x80, 0x9F, "structure according to ISO/IEC 7816, coding is proprietary" },
    {0xA0, 0xAF, "structure and coding according to ISO/IEC 7816 unless specified otherwise by the application context" },
    {0xB0, 0xCF, "structure according to ISO/IEC 7816" },
    {0xD0, 0xFE, "proprietary structure and coding" },
    {0xFF, 0xFF, "reserved for Protocol Type Selection" },
    {0, 0,   NULL}
};

static const value_string unique_or_unused[] = {
    { 0, "or unused" },
    { 0, NULL }
};

static const value_string unique_max_num_available_bytes[] = {
    { 0, "maximum number of available bytes" },
    { 0, NULL }
};

static inline
uint16_t FI_to_Fi(uint8_t FI)
{
    if (FI<=1)
        return 372;
    else if (FI<=6)
        return (FI-1) * 372;
    else if (FI==9)
        return 512;
    else if (FI==10)
        return 768;
    else if (FI==11)
        return 1024;
    else if (FI==12)
        return 1536;
    else if (FI==13)
        return 2048;

    return 0; /* 0 means RFU (reserved for future use) here */
}

static inline
uint8_t DI_to_Di(uint8_t DI)
{
    if (DI>=1 && DI<=6)
        return 1 << (DI-1);
    else if (DI==8)
        return 12;
    else if (DI==9)
        return 20;

    return 0; /* 0 means RFU (reserved for future use) here */
}

/* dissect TA(ta_index) */
static void
dissect_iso7816_atr_ta(tvbuff_t *tvb, int offset, unsigned ta_index,
        packet_info *pinfo _U_, proto_tree *tree)
{
    uint8_t     ta, FI, DI;
    uint16_t    Fi;
    uint8_t     Di;
    proto_item *ta_it;
    proto_tree *ta_tree;

    ta = tvb_get_uint8(tvb, offset);
    ta_it = proto_tree_add_uint_format(tree, hf_iso7816_atr_ta,
            tvb, offset, 1, ta,
            "Interface character TA(%d): 0x%02x", ta_index, ta);
    ta_tree = proto_item_add_subtree(ta_it, ett_iso7816_atr_ta);

    if (ta_index==1) {
        FI = (tvb_get_uint8(tvb, offset) & 0xF0) >> 4;
        Fi = FI_to_Fi(FI);
        if (Fi>0) {
            proto_tree_add_uint_format(ta_tree, hf_iso7816_atr_ta1_fi,
                    tvb, offset, 1, Fi,
                    "Clock rate conversion factor Fi: %d (FI 0x%x)",
                    Fi, FI);
        }

        DI = tvb_get_uint8(tvb, offset) & 0x0F;
        Di = DI_to_Di(DI);
        if (Di>0) {
            proto_tree_add_uint_format(ta_tree, hf_iso7816_atr_ta1_di,
                    tvb, offset, 1, Di,
                    "Baud rate adjustment factor Di: %d (DI 0x%x)",
                    Di, DI);
        }
    }
}

static int
dissect_iso7816_atr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int         offset=0;
    uint8_t     init_char;
    unsigned    i=0;  /* loop index for TA(i)...TD(i) */
    proto_item *proto_it;
    proto_tree *proto_tr;
    uint8_t     tb, tc, td, k=0;
    int         tck_len;

    /* we need at least the initial char TS and the format char T0 */
    if (tvb_captured_length(tvb) < 2)
        return 0; /* no ATR sequence */

    init_char = tvb_get_uint8(tvb, offset);
    if (init_char!=0x3B && init_char!=0x3F)
        return 0;

    proto_it = proto_tree_add_protocol_format(tree, proto_iso7816_atr,
                tvb, 0, -1, "ISO 7816 ATR");
    proto_tr = proto_item_add_subtree(proto_it, ett_iso7816_atr);

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "ATR");

    /* ISO 7816-4, section 4 indicates that concatenations are big endian */
    proto_tree_add_item(proto_tr, hf_iso7816_atr_init_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    do {
        proto_item *td_it;
        proto_tree *td_tree;

        /* for i==0, this is the T0 byte, otherwise it's the TD(i) byte
           in each loop, we dissect T0/TD(i) and TA(i+1), TB(i+1), TC(i+1) */
        td = tvb_get_uint8(tvb, offset);
        if (i==0) {
            td_it = proto_tree_add_item(proto_tr, hf_iso7816_atr_t0,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            td_it = proto_tree_add_uint_format(proto_tr, hf_iso7816_atr_td,
                    tvb, offset, 1, td,
                    "Interface character TD(%d): 0x%02x", i, td);
        }
        td_tree = proto_item_add_subtree(td_it, ett_iso7816_atr_td);

        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_ta_present,
                tvb, offset, 1, td&0x10,
                "TA(%d) present: %s", i+1, td&0x10 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_tb_present,
                tvb, offset, 1, td&0x20,
                "TB(%d) present: %s", i+1, td&0x20 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_tc_present,
                tvb, offset, 1, td&0x40,
                "TC(%d) present: %s", i+1, td&0x40 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_td_present,
                tvb, offset, 1, td&0x80,
                "TD(%d) present: %s", i+1, td&0x80 ? "True" : "False");

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                "TA(%d)=%s TB(%d)=%s TC(%d)=%s TD(%d)=%s",
                i+1, td&0x10 ? "True" : "False",
                i+1, td&0x20 ? "True" : "False",
                i+1, td&0x40 ? "True" : "False",
                i+1, td&0x80 ? "True" : "False");

        if (i==0) {
            k = td&0x0F;   /* number of historical bytes */
            proto_tree_add_item(td_tree, hf_iso7816_atr_k,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(td_tree, hf_iso7816_atr_t,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        offset++;

        if (td&0x10) {
            /* we read TA(i+1), see comment above */
            dissect_iso7816_atr_ta(tvb, offset, i+1, pinfo, proto_tr);
            offset++;
        }
        if (td&0x20) {
            tb = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint_format(proto_tr, hf_iso7816_atr_tb,
                    tvb, offset, 1, tb,
                    "Interface character TB(%d): 0x%02x", i+1, tb);
            offset++;
        }
        if (td&0x40) {
            tc = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint_format(proto_tr, hf_iso7816_atr_tc,
                    tvb, offset, 1, tc,
                    "Interface character TC(%d): 0x%02x", i+1, tc);
            offset++;
        }

        i++;
    } while (td&0x80);

    if (k>0) {
        proto_tree_add_item(proto_tr, hf_iso7816_atr_hist_bytes,
                tvb, offset, k, ENC_NA);
        offset += k;
    }

    tck_len = tvb_reported_length_remaining(tvb, offset);
    /* tck is either absent or exactly one byte */
    if (tck_len==1) {
        proto_tree_add_item(proto_tr, hf_iso7816_atr_tck,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    else if (tck_len>1) {
        proto_tree_add_expert(proto_tr, pinfo, &ei_iso7816_atr_tck_not1,
                tvb, offset, tck_len);
    }

    proto_item_set_len(proto_it, offset);
    return offset;
}

/* Dissect the class byte. Return 1 if the APDU's structure and coding
   adhere to ISO 7816. In this case, we can dissect the rest of the
   APDU. Otherwise, return -1. We may then pass the APDU to other
   dissectors. */
static int
dissect_iso7816_class(tvbuff_t *tvb, int offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *class_item;
    proto_tree *class_tree;
    uint8_t     dev_class;

    class_item = proto_tree_add_item(tree, hf_iso7816_cla,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    class_tree = proto_item_add_subtree(class_item, ett_iso7816_class);

    dev_class = tvb_get_uint8(tvb, offset);

    if (dev_class>=0x10 && dev_class<=0x7F) {
        /* these values are RFU. */
        return -1;
    }

    if (dev_class>=0xD0 && dev_class<=0xFE) {
        /* proprietary structure and coding */
        return -1;
    }

    if (dev_class==0xFF) {
        /* reserved for Protocol Type Selection */
        return -1;
    }

    /* If we made it this far, the structrue of the APDU is compliant
       with ISO 7816. */

    proto_tree_add_item(class_tree, hf_iso7816_cla_sm,
            tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(class_tree, hf_iso7816_cla_channel,
            tvb, offset, 1, ENC_BIG_ENDIAN);

    if (dev_class>=0x80 && dev_class<=0x9F) {
        /* structure according to ISO 7816, coding is proprietary */
        return -1;
    }

    if (dev_class>=0xB0 && dev_class<=0xCF) {
        /* structure according to ISO 7816 */
        return -1;
    }

    /* both structure and coding according to ISO 7816 */
    return 1;
}

/* dissect the parameters p1 and p2
   return number of dissected bytes or -1 for error */
static int
dissect_iso7816_params(uint8_t ins, tvbuff_t *tvb, int offset,
                 packet_info *pinfo _U_, proto_tree *tree)
{
    int         offset_start, p1_offset, p2_offset;
    proto_tree *params_tree;
    uint8_t     p1, p2;
    proto_item *p1_it = NULL, *p2_it = NULL;
    proto_tree *p1_tree = NULL, *p2_tree = NULL;
    proto_item *p1_p2_it = NULL;
    uint16_t    P1P2;
    uint32_t    ef, read_rec_usage;

    offset_start = offset;

    params_tree = proto_tree_add_subtree(tree, tvb, offset_start, 2,
                                ett_iso7816_param, NULL, "Parameters");

    p1 = tvb_get_uint8(tvb,offset);
    p1_it = proto_tree_add_item(params_tree, hf_iso7816_p1, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    p1_offset = offset;
    offset++;
    p2 = tvb_get_uint8(tvb,offset);
    p2_it = proto_tree_add_item(params_tree, hf_iso7816_p2,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    p2_offset = offset;
    offset++;
    P1P2 = (p1<<8|p2);

    switch (ins) {
        case INS_EXT_AUTH:
            if (p1>0) {
                proto_item_append_text(p1_it,
                        " (reference of the algorithm on the card)");
            }
            proto_item_append_text(p2_it, " (reference of the secret)");
            break;
        case INS_SELECT_FILE:
            proto_item_append_text(p1_it, " (selection control)");
            p1_tree = proto_item_add_subtree(p1_it, ett_iso7816_p1);
            proto_tree_add_item(p1_tree, hf_iso7816_sel_file_ctrl,
                    tvb, p1_offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(p2_it, " (selection options)");
            p2_tree = proto_item_add_subtree(p2_it, ett_iso7816_p2);
            proto_tree_add_item(p2_tree, hf_iso7816_sel_file_fci_req,
                    tvb, p2_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_iso7816_sel_file_occ,
                    tvb, p2_offset, 1, ENC_BIG_ENDIAN);
            break;
        case INS_READ_BIN:
            if (p1&0x80) {
                /* XXX - b5-b1 of P1 == short ef identifier for the selected file */
                /* XXX - P2 == offset for the read */
            }
            else {
                p1_p2_it = proto_tree_add_uint(params_tree, hf_iso7816_offset_first_byte,
                        tvb, offset_start, offset-offset_start, P1P2);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "offset %d", P1P2);
            }
            break;
        case INS_READ_REC:
            proto_item_append_text(p1_it, " (record number)");
            proto_item_append_text(p2_it, " (reference control)");
            p2_tree = proto_item_add_subtree(p2_it, ett_iso7816_p2);
            proto_tree_add_item_ret_uint(p2_tree, hf_iso7816_read_rec_ef,
                    tvb, p2_offset, 1, ENC_BIG_ENDIAN, &ef);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "EF %d", ef);
            proto_tree_add_item_ret_uint(p2_tree, hf_iso7816_read_rec_usage,
                    tvb, p2_offset, 1, ENC_BIG_ENDIAN, &read_rec_usage);
            if (read_rec_usage == READ_REC_USAGE_SINGLE) {
                col_append_sep_fstr(
                        pinfo->cinfo, COL_INFO, NULL, "record %d", p1);
            }
            break;
        case INS_GET_RESP:
            p1_p2_it = proto_tree_add_uint_format(params_tree, hf_iso7816_get_resp,
                    tvb, offset_start, offset-offset_start, P1P2,
                    "Both should be 0x00, other values are RFU");
            break;
        case INS_GET_DATA:
            if (P1P2<=0x003F || (0x0300<=P1P2 && P1P2<=0x3FFF)) {
                p1_p2_it = proto_tree_add_uint(params_tree, hf_iso7816_rfu,
                        tvb, offset_start, offset-offset_start, P1P2);
            }
            else if (0x0100<=P1P2 && P1P2<=0x01FF) {
                p1_p2_it = proto_tree_add_uint(params_tree, hf_iso7816_application_data,
                        tvb, offset_start, offset-offset_start, P1P2);
            }
            break;
        default:
            break;
    }

    proto_item_set_generated(p1_p2_it);

    return 2;
}

static int
dissect_iso7816_le(
        tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_iso7816_le, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}


static int
dissect_iso7816_cmd_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    iso7816_transaction_t *iso7816_trans = NULL;
    proto_item            *trans_ti = NULL;
    int                    ret;
    int                    offset = 0;
    uint8_t                ins;
    int                    body_len;
    uint8_t                lc;


    if (PINFO_FD_VISITED(pinfo)) {
        iso7816_trans = (iso7816_transaction_t *)wmem_tree_lookup32(
                transactions, pinfo->num);
        if (iso7816_trans && iso7816_trans->cmd_frame==pinfo->num &&
                iso7816_trans->resp_frame!=0) {
            trans_ti = proto_tree_add_uint_format(tree, hf_iso7816_resp_in,
                           NULL, 0, 0, iso7816_trans->resp_frame,
                           "Response in frame %d", iso7816_trans->resp_frame);
            proto_item_set_generated(trans_ti);
        }
    }
    else {
        if (transactions) {
            iso7816_trans = wmem_new(wmem_file_scope(), iso7816_transaction_t);
            iso7816_trans->cmd_frame = pinfo->num;
            iso7816_trans->resp_frame = 0;
            iso7816_trans->cmd_ins = INS_INVALID;
            iso7816_trans->handle = NULL;

            wmem_tree_insert32(transactions,
                    iso7816_trans->cmd_frame, (void *)iso7816_trans);
        }
    }

    ret = dissect_iso7816_class(tvb, offset, pinfo, tree);
    if (ret == -1) {
        /* the class byte says that the remaining APDU is not
            in ISO7816 format */

        if (iso7816_trans) {
            iso7816_trans->handle =
                dissector_get_payload_handle(iso7816_apdu_pld_table);
            if (iso7816_trans->handle != NULL) {
                ret = call_dissector(iso7816_trans->handle, tvb, pinfo, tree);
                if (ret == 0) {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                            "Command APDU using proprietary format");
                    return 1; /* we only dissected the class byte */
                }
            }
        }

        return ret;
    }
    offset += ret;

    ins = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_iso7816_ins, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str_ext_const(ins, &iso7816_ins_ext, "Unknown instruction"));
    offset++;
    /* if we just created a new transaction, we can now fill in the cmd id */
    if (iso7816_trans && iso7816_trans->cmd_ins==INS_INVALID)
        iso7816_trans->cmd_ins = ins;

    ret = dissect_iso7816_params(ins, tvb, offset, pinfo, tree);
    if (ret>0)
        offset += ret;

    /* for now, we support only short length fields
       based on infos from the ATR, we could support extended length fields too */
    body_len = tvb_reported_length_remaining(tvb, offset);

    /* nothing to do for body_len==0 */
    if (body_len==1) {
        offset += dissect_iso7816_le(tvb, offset, pinfo, tree);
    }
    else if (body_len>1) {
        lc = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(
                tree, hf_iso7816_lc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (lc>0) {
            proto_tree_add_item(tree, hf_iso7816_body, tvb, offset, lc, ENC_NA);
            offset += lc;
        }
        if (tvb_reported_length_remaining(tvb, offset)>0) {
            offset += dissect_iso7816_le(tvb, offset, pinfo, tree);
        }
    }

    return offset;
}

static int
dissect_iso7816_resp_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    iso7816_transaction_t *iso7816_trans;
    proto_item            *trans_ti = NULL;
    const char            *cmd_ins_str;
    int                    offset = 0;
    int                    body_len;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Response APDU");

    if (transactions) {
        /* receive the largest key that is less than or equal to our frame
           number */
        iso7816_trans = (iso7816_transaction_t *)wmem_tree_lookup32_le(
                transactions, pinfo->num);
        if (iso7816_trans) {
            if (iso7816_trans->resp_frame==0) {
                /* there's a pending request, this packet is the response */
                iso7816_trans->resp_frame = pinfo->num;
            }

            if (iso7816_trans->resp_frame== pinfo->num) {
                /* we found the request that corresponds to our response */
                cmd_ins_str = val_to_str_const(iso7816_trans->cmd_ins,
                        iso7816_ins, "Unknown instruction");
                trans_ti = proto_tree_add_uint_format(tree, hf_iso7816_resp_to,
                        NULL, 0, 0, iso7816_trans->cmd_frame,
                        "Response to frame %d (%s)",
                        iso7816_trans->cmd_frame, cmd_ins_str);
                proto_item_set_generated(trans_ti);

                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ",
                        "(to %s)", cmd_ins_str);
            }

            if (iso7816_trans->handle != NULL)
                call_dissector(iso7816_trans->handle, tvb, pinfo, tree);
        }
    }

    /* - 2 bytes SW1, SW2 */
    body_len = tvb_reported_length_remaining(tvb, offset) - 2;

    if (body_len>0) {
        proto_tree_add_item(tree, hf_iso7816_body,
                tvb, offset, body_len, ENC_NA);
        offset += body_len;
    }

    if (tvb_reported_length_remaining(tvb, offset) >= 2) {
        proto_tree_add_item(tree, hf_iso7816_sw1,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso7816_sw2,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    return offset;
}

static int
dissect_iso7816(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int         offset = 0;
    proto_item *tree_ti;
    proto_tree *iso7816_tree;
    bool        is_atr = false;

    if (pinfo->p2p_dir!=P2P_DIR_SENT && pinfo->p2p_dir!=P2P_DIR_RECV)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO 7816");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_ti = proto_tree_add_protocol_format(tree, proto_iso7816,
            tvb, 0, tvb_reported_length(tvb), "ISO 7816");
    iso7816_tree = proto_item_add_subtree(tree_ti, ett_iso7816);

    /* per our definition, sent/received is from the perspective of the interface
       i.e sent is from interface to card, received is from card to interface */
    if (pinfo->p2p_dir==P2P_DIR_SENT) {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_INTF)+1, ADDR_INTF);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_CARD)+1, ADDR_CARD);
        proto_item_append_text(tree_ti, " Command APDU");
        offset = dissect_iso7816_cmd_apdu(tvb, pinfo, iso7816_tree);
    }
    else if (pinfo->p2p_dir==P2P_DIR_RECV) {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_CARD)+1, ADDR_CARD);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_INTF)+1, ADDR_INTF);

        if (iso7816_atr_handle) {
            offset = call_dissector_only(iso7816_atr_handle,
                    tvb, pinfo, iso7816_tree, NULL);
            if (offset > 0)
                is_atr = true;
        }
        if (!is_atr) {
            proto_item_append_text(tree_ti, " Response APDU");
            offset = dissect_iso7816_resp_apdu(tvb, pinfo, iso7816_tree);
        }
    }

    return offset;
}

void
proto_register_iso7816(void)
{
    static hf_register_info hf[] = {
        { &hf_iso7816_atr_init_char,
            { "Initial character", "iso7816.atr.init_char",
                FT_UINT8, BASE_HEX, VALS(iso7816_atr_init_char), 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_t0,
            { "Format character T0", "iso7816.atr.t0",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_ta,
            { "Interface character TA(i)", "iso7816.atr.ta",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_ta1_fi,
            { "Fi", "iso7816.atr.ta1.fi",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_ta1_di,
            { "Di", "iso7816.atr.ta1.di",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tb,
            { "Interface character TB(i)", "iso7816.atr.tb",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tc,
            { "Interface character TC(i)", "iso7816.atr.tc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_td,
            { "Interface character TD(i)", "iso7816.atr.td",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_ta_present,
            { "TA(i+1) present", "iso7816.atr.next_ta_present",
                FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_tb_present,
            { "TB(i+1) present", "iso7816.atr.next_tb_present",
                FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_tc_present,
            { "TC(i+1) present", "iso7816.atr.next_tc_present",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_td_present,
            { "TD(i+1) present", "iso7816.atr.next_td_present",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_iso7816_atr_k,
            { "Number K of historical bytes", "iso7816.atr.k",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso7816_atr_t,
            { "Protocol reference T", "iso7816.atr.t",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso7816_atr_hist_bytes,
            { "Historical bytes", "iso7816.atr.historical_bytes",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tck,
            { "Check character TCK", "iso7816.atr.tck",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_resp_in,
            { "Response In", "iso7816.resp_in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "The response to this command is in this frame", HFILL }
        },
        { &hf_iso7816_resp_to,
            { "Response To", "iso7816.resp_to",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This is the response to the command in this frame", HFILL }
        },
        { &hf_iso7816_cla,
            { "Class", "iso7816.apdu.cla",
                FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(iso7816_class_rvals), 0, NULL , HFILL }
        },
        { &hf_iso7816_cla_sm,
            { "Secure Messaging", "iso7816.apdu.cla.sm",
                FT_UINT8, BASE_HEX, VALS(iso7816_cla_sm), 0x0C, NULL , HFILL }
        },
        { &hf_iso7816_cla_channel,
            { "Logical channel number", "iso7816.apdu.cla.channel",
                FT_UINT8, BASE_HEX|BASE_SPECIAL_VALS, VALS(unique_or_unused), 0x03, NULL , HFILL }
        },
        { &hf_iso7816_ins,
            { "Instruction", "iso7816.apdu.ins",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING, &iso7816_ins_ext, 0, NULL, HFILL }
        },
        { &hf_iso7816_p1,
            { "Parameter 1", "iso7816.apdu.p1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_p2,
            { "Parameter 2", "iso7816.apdu.p2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_lc,
            { "Length field Lc", "iso7816.apdu.lc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_le,
            { "Expected response length Le", "iso7816.apdu.le",
                FT_UINT8, BASE_HEX|BASE_SPECIAL_VALS, VALS(unique_max_num_available_bytes), 0, NULL, HFILL }
        },
        { &hf_iso7816_body,
            { "APDU Body", "iso7816.apdu.body",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_sw1,
            { "Status Word SW1", "iso7816.apdu.sw1", FT_UINT8,
                BASE_RANGE_STRING|BASE_HEX, RVALS(iso7816_sw1), 0, NULL, HFILL }
        },
        { &hf_iso7816_sw2,
            { "Status Word SW2", "iso7816.apdu.sw2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_sel_file_ctrl,
            { "Selection control", "iso7816.apdu.select_file.ctrl",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING,
                &ext_iso7816_sel_file_ctrl, 0, NULL, HFILL }
        },
        { &hf_iso7816_sel_file_fci_req,
            { "File control information request", "iso7816.apdu.select_file.fci_req",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING,
                &ext_iso7816_sel_file_fci_req, 0x0C, NULL, HFILL }
        },
        { &hf_iso7816_sel_file_occ,
            { "Occurrence", "iso7816.apdu.select_file.occurrence",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING,
                &ext_iso7816_sel_file_occ, 0x03, NULL, HFILL }
        },
        { &hf_iso7816_read_rec_ef,
            { "Short EF identifier", "iso7816.apdu.read_rec.ef",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_iso7816_read_rec_usage,
            { "Usage", "iso7816.apdu.read_rec.usage",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING,
                &ext_iso7816_read_rec_usage, 0x07, NULL, HFILL }
        },
        { &hf_iso7816_offset_first_byte,
            { "Offset of the first byte to read", "iso7816.offset_first_byte",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_get_resp,
            { "GetResp", "iso7816.get_resp",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_rfu,
            { "RFU", "iso7816.rfu",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_application_data,
            { "Application data (proprietary coding)", "iso7816.application_data",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
    };
    static int *ett[] = {
        &ett_iso7816,
        &ett_iso7816_class,
        &ett_iso7816_param,
        &ett_iso7816_p1,
        &ett_iso7816_p2,
        &ett_iso7816_atr,
        &ett_iso7816_atr_ta,
        &ett_iso7816_atr_td
    };

    static ei_register_info ei[] = {
        { &ei_iso7816_atr_tck_not1, { "iso7816.atr.tck.not1", PI_PROTOCOL, PI_WARN, "TCK byte must either be absent or exactly one byte", EXPFILL }}
    };

    expert_module_t* expert_iso7816;

    proto_iso7816 = proto_register_protocol("ISO/IEC 7816", "ISO 7816", "iso7816");
    proto_register_field_array(proto_iso7816, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_iso7816 = expert_register_protocol(proto_iso7816);
    expert_register_field_array(expert_iso7816, ei, array_length(ei));

    iso7816_handle = register_dissector("iso7816", dissect_iso7816, proto_iso7816);

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_iso7816_atr = proto_register_protocol_in_name_only("ISO/IEC 7816-3", "ISO 7816-3", "iso7816.atr", proto_iso7816, FT_PROTOCOL);
    iso7816_atr_handle = register_dissector("iso7816.atr", dissect_iso7816_atr, proto_iso7816_atr);

    iso7816_apdu_pld_table =
        register_decode_as_next_proto(proto_iso7816,
                "iso7816.apdu_payload",
                "ISO7816 proprietary APDU dissector", NULL);
}


void proto_reg_handoff_iso7816(void)
{
    dissector_add_for_decode_as("usbccid.subdissector", iso7816_handle);
    dissector_add_for_decode_as("iso14443.subdissector", iso7816_handle);
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
