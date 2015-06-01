/* packet-zvt.c
 * Routines for ZVT dissection
 * Copyright 2014-2015, Martin Kaiser <martin@kaiser.cx>
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

/* ZVT is a manufacturer-independent protocol between payment terminals and
 * electronic cash-register systems / vending machines
 *
 * the specifications are available from http://www.zvt-kassenschnittstelle.de
 *
 * ZVT defines a "serial transport protocol" and a "TCP/IP transport
 * protocol"
 *
 * ZVT can sit on top of USB, either the serial or the TCP/IP protocol
 * can be used in this case - this is not supported for now
 *
 * a dump of ZVT data can be converted to pcap, using a user-defined DLT
 * we register the dissector by name and try to auto-detect the serial
 * or TCP/IP protocol
 *
 * finally, ZVT can run on top of TCP, the default port is 20007, only
 * the TCP/IP protocol can be used here
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>

/* special characters of the serial transport protocol */
#define STX 0x02
#define ETX 0x03
#define ACK 0x06
#define DLE 0x10
#define NAK 0x15

/* an APDU needs at least a 2-byte control-field and one byte length */
#define ZVT_APDU_MIN_LEN 3


static GHashTable *apdu_table = NULL;

static wmem_tree_t *transactions = NULL;

typedef enum _zvt_direction_t {
    DIRECTION_UNKNOWN,
    DIRECTION_ECR_TO_PT,
    DIRECTION_PT_TO_ECR
} zvt_direction_t;

/* source/destination address field */
#define ADDR_ECR "ECR"
#define ADDR_PT  "PT"

#define CCRC_POS 0x80
#define CCRC_NEG 0x84

typedef struct _apdu_info_t {
    guint16          ctrl;
    guint32          min_len_field;
    zvt_direction_t  direction;
    void (*dissect_payload)(tvbuff_t *, gint, guint16, packet_info *, proto_tree *);
} apdu_info_t;

/* control code 0 is not defined in the specification */
#define ZVT_CTRL_NONE      0x0000

#define CTRL_STATUS        0x040F
#define CTRL_INT_STATUS    0x04FF
#define CTRL_REGISTRATION  0x0600
#define CTRL_AUTHORISATION 0x0601
#define CTRL_COMPLETION    0x060F
#define CTRL_ABORT         0x061E
#define CTRL_END_OF_DAY    0x0650
#define CTRL_DIAG          0x0670
#define CTRL_INIT          0x0693
#define CTRL_PRINT_LINE    0x06D1

static void dissect_zvt_reg(
        tvbuff_t *tvb, gint offset, guint16 len, packet_info *pinfo, proto_tree *tree);
static void dissect_zvt_bitmap_apdu(
        tvbuff_t *tvb, gint offset, guint16 len, packet_info *pinfo, proto_tree *tree);

static const apdu_info_t apdu_info[] = {
    { CTRL_STATUS,        0, DIRECTION_PT_TO_ECR, NULL },
    { CTRL_INT_STATUS,    0, DIRECTION_PT_TO_ECR, NULL },
    { CTRL_REGISTRATION,  4, DIRECTION_ECR_TO_PT, dissect_zvt_reg },
    /* authorisation has at least a 0x04 tag and 6 bytes for the amount */
    { CTRL_AUTHORISATION, 7, DIRECTION_ECR_TO_PT, dissect_zvt_bitmap_apdu },
    { CTRL_COMPLETION,    0, DIRECTION_PT_TO_ECR, dissect_zvt_bitmap_apdu },
    { CTRL_ABORT,         0, DIRECTION_PT_TO_ECR, NULL },
    { CTRL_END_OF_DAY,    0, DIRECTION_ECR_TO_PT, NULL },
    { CTRL_DIAG,          0,  DIRECTION_ECR_TO_PT, NULL },
    { CTRL_INIT,          0, DIRECTION_ECR_TO_PT, NULL },
    { CTRL_PRINT_LINE,    0, DIRECTION_PT_TO_ECR, NULL }
};

void proto_register_zvt(void);
void proto_reg_handoff_zvt(void);

/* the specification mentions tcp port 20007
   this port is not officially registered with IANA */
static guint pref_zvt_tcp_port = 0;

static int proto_zvt = -1;

static int ett_zvt = -1;
static int ett_zvt_apdu = -1;
static int ett_zvt_tlv_dat_obj = -1;

static int hf_zvt_resp_in = -1;
static int hf_zvt_resp_to = -1;
static int hf_zvt_serial_char = -1;
static int hf_zvt_crc = -1;
static int hf_zvt_ctrl = -1;
static int hf_zvt_ccrc = -1;
static int hf_zvt_aprc = -1;
static int hf_zvt_len = -1;
static int hf_zvt_data = -1;
static int hf_zvt_reg_pwd = -1;
static int hf_zvt_reg_cfg = -1;
static int hf_zvt_cc = -1;
static int hf_zvt_reg_svc_byte = -1;
static int hf_zvt_bitmap = -1;
static int hf_zvt_tlv_tag = -1;
static int hf_zvt_tlv_len = -1;

typedef struct _zvt_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    guint16 ctrl;
} zvt_transaction_t;

static const value_string serial_char[] = {
    { STX, "Start of text (STX)" },
    { ETX, "End of text (ETX)" },
    { ACK, "Acknowledged (ACK)" },
    { DLE, "Data line escape (DLE)" },
    { NAK, "Not acknowledged (NAK)" },
    { 0, NULL }
};
static value_string_ext serial_char_ext = VALUE_STRING_EXT_INIT(serial_char);


static const value_string ctrl_field[] = {
    { CTRL_STATUS, "Status Information" },
    { CTRL_INT_STATUS, "Intermediate Status Information" },
    { CTRL_REGISTRATION, "Registration" },
    { CTRL_AUTHORISATION, "Authorisation" },
    { CTRL_COMPLETION, "Completion" },
    { CTRL_ABORT, "Abort" },
    { CTRL_END_OF_DAY, "End Of Day" },
    { CTRL_DIAG, "Diagnosis" },
    { CTRL_INIT, "Initialisation" },
    { CTRL_PRINT_LINE, "Print Line" },
    { 0x06D3, "Print Text Block" },
    { 0, NULL }
};
static value_string_ext ctrl_field_ext = VALUE_STRING_EXT_INIT(ctrl_field);

#define BMP_TIMEOUT       0x01
#define BMP_MAX_STAT_INFO 0x02
#define BMP_AMOUNT        0x04
#define BMP_PUMP_NR       0x05
#define BMP_TLV_CONTAINER 0x06
#define BMP_EXP_DATE      0x0E
#define BMP_PAYMENT_TYPE  0x19
#define BMP_CARD_NUM      0x22
#define BMP_T2_DAT        0x23
#define BMP_T3_DAT        0x24
#define BMP_T1_DAT        0x2D
#define BMP_CVV_CVC       0x3A
#define BMP_ADD_DATA      0x3C
#define BMP_CC            0x49

static const value_string bitmap[] = {
    { BMP_TIMEOUT,       "Timeout" },
    { BMP_MAX_STAT_INFO, "max. status info" },
    { BMP_AMOUNT,        "Amount" },
    { BMP_PUMP_NR,       "Pump number" },
    { BMP_TLV_CONTAINER, "TLV container" },
    { BMP_EXP_DATE,      "Exipry date" },
    { BMP_PAYMENT_TYPE,  "Payment type" },
    { BMP_CARD_NUM,      "Card number" },
    { BMP_T2_DAT,        "Track 2 data" },
    { BMP_T3_DAT,        "Track 3 data" },
    { BMP_T1_DAT,        "Track 1 data" },
    { BMP_CVV_CVC,       "CVV / CVC" },
    { BMP_ADD_DATA,      "Additional data" },
    { BMP_CC,            "Currency code (CC)" },
    { 0, NULL }
};
static value_string_ext bitmap_ext = VALUE_STRING_EXT_INIT(bitmap);

static const value_string tlv_tags[] = {
    { 0, NULL }
};
static value_string_ext tlv_tags_ext = VALUE_STRING_EXT_INIT(tlv_tags);


static gint
dissect_zvt_tlv_tag(tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree, guint32 *tag)
{
    guint8 tag_byte;

    tag_byte = tvb_get_guint8(tvb, offset);
    if ((tag_byte & 0x1F) == 0x1F) {
        /* XXX - handle multi-byte tags */
        return -1;
    }

    proto_tree_add_uint_format(tree, hf_zvt_tlv_tag,
            tvb, offset, 1, tag_byte, "Tag: 0x%x", tag_byte);

    if (tag)
        *tag = tag_byte;
    return 1;
}


static gint
dissect_zvt_tlv_container(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint        offset_start;
    proto_item *dat_obj_it;
    proto_tree *dat_obj_tree;
    gint        tag_len;
    guint32     tag;
    guint8      data_len_bytes = 1;
    guint16     data_len;

    offset_start = offset;

    while (tvb_captured_length_remaining(tvb, offset) > 0) {
        dat_obj_tree = proto_tree_add_subtree(tree,
            tvb, offset, -1, ett_zvt_tlv_dat_obj, &dat_obj_it,
            "TLV data object");

        tag_len = dissect_zvt_tlv_tag(tvb, offset, pinfo, dat_obj_tree, &tag);
        if (tag_len <= 0)
            return offset - offset_start;
        offset += tag_len;

        data_len = tvb_get_guint8(tvb, offset);
        if (data_len & 0x80) {
            if ((data_len & 0x03) == 1) {
                data_len_bytes++;
                data_len = tvb_get_guint8(tvb, offset+1);
            }
            else if ((data_len & 0x03) == 2) {
                data_len_bytes += 2;
                data_len = tvb_get_ntohs(tvb, offset+1);
            }
            else {
                /* XXX - expert info, exit */
            }
        }
        proto_tree_add_uint(dat_obj_tree, hf_zvt_tlv_len,
                tvb, offset, data_len_bytes, data_len);
        offset += data_len_bytes;

        /* XXX - dissect the data-element */
        offset += data_len;

        proto_item_set_len(dat_obj_it, tag_len + data_len_bytes + data_len);
    }

    return offset - offset_start;
}


/* dissect one "bitmap", i.e BMP and the corresponding data */
static gint
dissect_zvt_bitmap(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint    offset_start;
    guint8  bmp;
    gint    ret;

    offset_start = offset;

    bmp = tvb_get_guint8(tvb, offset);
    if (try_val_to_str(bmp, bitmap) == NULL)
        return -1;

    proto_tree_add_item(tree, hf_zvt_bitmap, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (bmp) {
        case BMP_TIMEOUT:
            offset++;
            break;
        case BMP_MAX_STAT_INFO:
            offset++;
            break;
        case BMP_AMOUNT:
            offset += 6;
            break;
        case BMP_PUMP_NR:
            offset++;
            break;
        case BMP_EXP_DATE:
            offset += 2;
            break;
        case BMP_PAYMENT_TYPE:
            offset++;
            break;
        case BMP_CVV_CVC:
            offset += 2;
            break;
        case BMP_CC:
            offset += 2;
            break;
        case BMP_TLV_CONTAINER:
            ret = dissect_zvt_tlv_container(tvb, offset, pinfo, tree);
            if (ret<0)
                return -1;

            offset += ret;
            break;

        case BMP_CARD_NUM:
        case BMP_T2_DAT:
        case BMP_T3_DAT:
        case BMP_T1_DAT:
        case BMP_ADD_DATA:
            /* the bitmaps are not TLV but only TV, there's no length field
               the tags listed above have variable length
               -> if we see one of those tags, we have to stop the
               dissection and report an error to the caller */
            return -1;

        default:
            g_assert_not_reached();
            break;
    };

    return offset - offset_start;
}

static void
dissect_zvt_reg(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_zvt_reg_pwd, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_zvt_reg_cfg,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* check for the optional part CC|0x03|service byte */
    if (tvb_captured_length_remaining(tvb, offset)>=4 &&
            tvb_get_guint8(tvb, offset+2)==0x03) {

        proto_tree_add_item(tree, hf_zvt_cc,
            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset++; /* 0x03 */

        proto_tree_add_item(tree, hf_zvt_reg_svc_byte,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* it's ok if the remaining len is 0 */
    dissect_zvt_bitmap_apdu(tvb, offset,
            tvb_captured_length_remaining(tvb, offset),
            pinfo, tree);
}


/* dissect an APDU that contains a sequence of bitmaps */
static void
dissect_zvt_bitmap_apdu(tvbuff_t *tvb, gint offset, guint16 len,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start, ret;

    offset_start = offset;

    while (offset - offset_start < len) {
        ret = dissect_zvt_bitmap(tvb, offset, pinfo, tree);
        if (ret <=0)
            break;
        offset += ret;
    }
}


static void
zvt_set_addresses(packet_info *pinfo, zvt_transaction_t *zvt_trans)
{
    apdu_info_t     *ai;
    zvt_direction_t  dir = DIRECTION_UNKNOWN;

    if (!zvt_trans)
        return;

    ai = (apdu_info_t *)g_hash_table_lookup(
            apdu_table, GUINT_TO_POINTER((guint)zvt_trans->ctrl));
    if (!ai)
        return;

    if (zvt_trans->rqst_frame == PINFO_FD_NUM(pinfo)) {
        dir = ai->direction;
    }
    else if (zvt_trans->resp_frame == PINFO_FD_NUM(pinfo)) {
        if (ai->direction == DIRECTION_ECR_TO_PT)
            dir = DIRECTION_PT_TO_ECR;
        else
            dir = DIRECTION_ECR_TO_PT;
    }

    if (dir  == DIRECTION_ECR_TO_PT) {
        SET_ADDRESS(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_ECR)+1, ADDR_ECR);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PT)+1, ADDR_PT);
    }
    else if (dir  == DIRECTION_PT_TO_ECR) {
        SET_ADDRESS(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PT)+1, ADDR_PT);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_ECR)+1, ADDR_ECR);
    }
}


/* dissect a ZVT APDU
   return -1 if we don't have a complete APDU, 0 if the packet is no ZVT APDU
   or the length of the ZVT APDU if all goes well */
static int
dissect_zvt_apdu(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    gint               offset_start;
    guint8             len_bytes = 1; /* number of bytes for the len field */
    guint16            ctrl = ZVT_CTRL_NONE;
    guint16            len;
    guint8             byte;
    proto_item        *apdu_it;
    proto_tree        *apdu_tree;
    apdu_info_t       *ai;
    zvt_transaction_t *zvt_trans = NULL;
    proto_item        *it;

    offset_start = offset;

    if (tvb_captured_length_remaining(tvb, offset) < ZVT_APDU_MIN_LEN)
        return -1;

    len = tvb_get_guint8(tvb, offset+2);
    if (len == 0xFF) {
        len_bytes = 3;
        len = tvb_get_ntohs(tvb, offset+3);
    }

    /* ZVT_APDU_MIN_LEN already includes one length byte */
    if (tvb_captured_length_remaining(tvb, offset) <
            ZVT_APDU_MIN_LEN + (len_bytes-1) + len) {
        return -1;
    }

    apdu_tree = proto_tree_add_subtree(tree,
            tvb, offset, -1, ett_zvt_apdu, &apdu_it, "ZVT APDU");

    byte = tvb_get_guint8(tvb, offset);
    if (byte == CCRC_POS || byte == CCRC_NEG) {
        proto_tree_add_item(apdu_tree, hf_zvt_ccrc, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                byte == CCRC_POS ? "Positive completion" : "Negative completion");
        offset++;
        proto_tree_add_item(apdu_tree, hf_zvt_aprc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* XXX - can this ever be NULL? */
        if (transactions) {
            zvt_trans = (zvt_transaction_t *)wmem_tree_lookup32_le(
                    transactions, PINFO_FD_NUM(pinfo));
           if (zvt_trans && zvt_trans->resp_frame==0) {
               /* there's a pending request, this packet is the response */
               zvt_trans->resp_frame = PINFO_FD_NUM(pinfo);
           }

           if (zvt_trans && zvt_trans->resp_frame == PINFO_FD_NUM(pinfo)) {
               it = proto_tree_add_uint(apdu_tree, hf_zvt_resp_to,
                       NULL, 0, 0, zvt_trans->rqst_frame);
               PROTO_ITEM_SET_GENERATED(it);
           }
        }

    }
    else {
        ctrl = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(apdu_tree, hf_zvt_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                val_to_str_const(ctrl, ctrl_field, "Unknown 0x%x"));
        offset += 2;

        if (PINFO_FD_VISITED(pinfo)) {
            zvt_trans = (zvt_transaction_t *)wmem_tree_lookup32(
                    transactions, PINFO_FD_NUM(pinfo));
            if (zvt_trans && zvt_trans->rqst_frame==PINFO_FD_NUM(pinfo) &&
                    zvt_trans->resp_frame!=0) {
               it = proto_tree_add_uint(apdu_tree, hf_zvt_resp_in,
                       NULL, 0, 0, zvt_trans->resp_frame);
               PROTO_ITEM_SET_GENERATED(it);
            }
        }
        else {
            /* XXX - can this ever be NULL? */
            if (transactions) {
                zvt_trans = wmem_new(wmem_file_scope(), zvt_transaction_t);
                zvt_trans->rqst_frame = PINFO_FD_NUM(pinfo);
                zvt_trans->resp_frame = 0;
                zvt_trans->ctrl = ctrl;
                wmem_tree_insert32(transactions,
                        zvt_trans->rqst_frame, (void *)zvt_trans);
            }
        }
    }

    proto_tree_add_uint(apdu_tree, hf_zvt_len, tvb, offset, len_bytes, len);
    offset += len_bytes;

    ai = (apdu_info_t *)g_hash_table_lookup(
            apdu_table, GUINT_TO_POINTER((guint)ctrl));

    zvt_set_addresses(pinfo, zvt_trans);
    /* XXX - check the minimum length */

    if (len > 0) {
        if (ai && ai->dissect_payload)
            ai->dissect_payload(tvb, offset, len, pinfo, apdu_tree);
        else
            proto_tree_add_item(apdu_tree, hf_zvt_data, tvb, offset, len, ENC_NA);
    }
    offset += len;

    proto_item_set_len(apdu_it, offset - offset_start);
    return offset - offset_start;
}


static gint
dissect_zvt_serial(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint  offset_start;
    int   apdu_len;

    offset_start = offset;

    if (tvb_reported_length_remaining(tvb, offset) == 1) {
        proto_tree_add_item(tree, hf_zvt_serial_char,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++; /* ACK or NAK byte */
        return offset - offset_start;
    }

    proto_tree_add_item(tree, hf_zvt_serial_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++; /* DLE byte */
    proto_tree_add_item(tree, hf_zvt_serial_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++; /* STX byte */

    apdu_len = dissect_zvt_apdu(tvb, offset, pinfo, tree);
    if (apdu_len < 0)
        return apdu_len;

    offset += apdu_len;

    proto_tree_add_item(tree, hf_zvt_serial_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++; /* DLE byte */
    proto_tree_add_item(tree, hf_zvt_serial_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++; /* ETX byte */

    /* the CRC is little endian, the other fields are big endian */
    proto_tree_add_item(tree, hf_zvt_crc,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2; /* CRC bytes */

    return offset - offset_start;
}


static gboolean
valid_ctrl_field(tvbuff_t *tvb, gint offset)
{
    if (tvb_get_guint8(tvb, offset) == 0x80 ||
        tvb_get_guint8(tvb, offset) == 0x84 ||
        try_val_to_str_ext(tvb_get_ntohs(tvb, offset), &ctrl_field_ext)) {
            return TRUE;
    }

    return FALSE;
}


static int
dissect_zvt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        zvt_len = 0;
    proto_item *zvt_ti;
    proto_tree *zvt_tree;
    gboolean    is_serial; /* serial or TCP/IP protocol? */

    if (tvb_captured_length(tvb) == 1 &&
            (tvb_get_guint8(tvb, 0) == ACK ||
             tvb_get_guint8(tvb, 0) == NAK)) {
        is_serial = TRUE;
    }
    else if (tvb_captured_length(tvb) >= 2 &&
            tvb_get_guint8(tvb, 0) == DLE &&
            tvb_get_guint8(tvb, 1) == STX) {
        is_serial = TRUE;
    }
    else if (tvb_captured_length(tvb) >= ZVT_APDU_MIN_LEN &&
            valid_ctrl_field(tvb, 0)) {
        is_serial = FALSE;
    }
    else
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZVT");
    col_clear(pinfo->cinfo, COL_INFO);
    zvt_ti = proto_tree_add_protocol_format(tree, proto_zvt,
            tvb, 0, -1,
            "ZVT Kassenschnittstelle: %s", is_serial ?
            "Serial Transport Protocol" : "Transport Protocol TCP/IP");
    zvt_tree = proto_item_add_subtree(zvt_ti, ett_zvt);

    if (is_serial)
        zvt_len = dissect_zvt_serial(tvb, 0, pinfo, zvt_tree);
    else
        zvt_len = dissect_zvt_apdu(tvb, 0, pinfo, zvt_tree);

    /* zvt_len < 0 means that we have an incomplete APDU
       we can't do any reassembly here, so let's consume all bytes */
    if (zvt_len < 0)
        zvt_len = tvb_captured_length(tvb);

    proto_item_set_len(zvt_ti, zvt_len);
    return zvt_len;
}


static int
dissect_zvt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        offset = 0, zvt_len = 0, ret;
    proto_item *zvt_ti;
    proto_tree *zvt_tree;

    if (tvb_captured_length(tvb) < ZVT_APDU_MIN_LEN) {
        if (pinfo->can_desegment) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        }
        return zvt_len;
    }

    if (!valid_ctrl_field(tvb, 0))
        return 0; /* reject the packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZVT");
    col_clear(pinfo->cinfo, COL_INFO);
    zvt_ti = proto_tree_add_protocol_format(tree, proto_zvt,
            tvb, 0, -1,
            "ZVT Kassenschnittstelle: Transport Protocol TCP/IP");
    zvt_tree = proto_item_add_subtree(zvt_ti, ett_zvt);

    while (tvb_captured_length_remaining(tvb, offset) > 0) {
        ret = dissect_zvt_apdu(tvb, offset, pinfo, zvt_tree);
        if (ret == 0) {
            /* not a valid APDU
               mark the bytes that we consumed and exit, give
               other dissectors a chance to try the remaining
               bytes */
            break;
        }
        else if (ret < 0) {
            /* not enough data - ask the TCP layer for more */

            if (pinfo->can_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            }
            break;
        }
        else {
            offset += ret;
            zvt_len += ret;
        }
    }

    proto_item_set_len(zvt_ti, zvt_len);
    return zvt_len;
}


void
proto_register_zvt(void)
{
    guint     i;
    module_t *zvt_module;

    static gint *ett[] = {
        &ett_zvt,
        &ett_zvt_apdu,
        &ett_zvt_tlv_dat_obj
    };
    static hf_register_info hf[] = {
        { &hf_zvt_resp_in,
            { "Response In", "zvt.resp_in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_zvt_resp_to,
            { "Response To", "zvt.resp_to",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
         { &hf_zvt_serial_char,
            { "Serial character", "zvt.serial_char", FT_UINT8,
                BASE_HEX|BASE_EXT_STRING, &serial_char_ext, 0, NULL, HFILL } },
        { &hf_zvt_crc,
            { "CRC", "zvt.crc", FT_UINT16,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_ctrl,
            { "Control-field", "zvt.control_field", FT_UINT16,
                BASE_HEX|BASE_EXT_STRING, &ctrl_field_ext, 0, NULL, HFILL } },
        { &hf_zvt_ccrc,
            { "CCRC", "zvt.ccrc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_aprc,
            { "APRC", "zvt.aprc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_len,
            { "Length-field", "zvt.length_field",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_zvt_data,
          { "APDU data", "zvt.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_reg_pwd,
            { "Password", "zvt.reg.password",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_reg_cfg,
            { "Config byte", "zvt.reg.config_byte",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        /* we don't call the filter zvt.reg.cc, the currency code
           appears in several apdus */
        { &hf_zvt_cc,
            { "Currency Code (CC)", "zvt.cc",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_reg_svc_byte,
            { "Service byte", "zvt.reg.service_byte",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_bitmap,
            { "Bitmap", "zvt.bitmap", FT_UINT8,
                BASE_HEX|BASE_EXT_STRING, &bitmap_ext, 0, NULL, HFILL } },
        { &hf_zvt_tlv_tag,
            { "Tag", "zvt.tlv.tag", FT_UINT32,
                BASE_HEX|BASE_EXT_STRING, &tlv_tags_ext, 0, NULL, HFILL } },
        { &hf_zvt_tlv_len,
            { "Length", "zvt.tlv.len",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } }
    };


    apdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(apdu_info); i++) {
        g_hash_table_insert(apdu_table,
                            GUINT_TO_POINTER((guint)apdu_info[i].ctrl),
                            (const gpointer)(&apdu_info[i]));
    }

    proto_zvt = proto_register_protocol(
            "ZVT Kassenschnittstelle", "ZVT", "zvt");
    proto_register_field_array(proto_zvt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    zvt_module = prefs_register_protocol(proto_zvt, proto_reg_handoff_zvt);
    prefs_register_uint_preference(zvt_module, "tcp.port",
                   "ZVT TCP Port",
                   "Set the TCP port for ZVT messages (port 20007 according to the spec)",
                   10,
                   &pref_zvt_tcp_port);

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}


void
proto_reg_handoff_zvt(void)
{
    static gboolean            registered_dissector = FALSE;
    static int                 zvt_tcp_port;
    static dissector_handle_t  zvt_tcp_handle;

    if (!registered_dissector) {
        /* register by name to allow mapping to a user DLT */
        new_register_dissector("zvt", dissect_zvt, proto_zvt);

        zvt_tcp_handle = new_create_dissector_handle(dissect_zvt_tcp, proto_zvt);

        registered_dissector = TRUE;
    }
    else
        dissector_delete_uint("tcp.port", zvt_tcp_port, zvt_tcp_handle);

    zvt_tcp_port = pref_zvt_tcp_port;
    dissector_add_uint("tcp.port", zvt_tcp_port, zvt_tcp_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
