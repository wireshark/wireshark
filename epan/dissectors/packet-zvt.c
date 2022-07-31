/* packet-zvt.c
 * Routines for ZVT dissection
 * Copyright 2014-2015, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ZVT is a manufacturer-independent protocol between payment terminals and
 * electronic cash-register systems / vending machines
 *
 * the specifications are available from https://www.terminalhersteller.de
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
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include "packet-tcp.h"

/* special characters of the serial transport protocol */
#define STX 0x02
#define ETX 0x03
#define ACK 0x06
#define DLE 0x10
#define NAK 0x15

/* an APDU needs at least a 2-byte control-field and one byte length */
#define ZVT_APDU_MIN_LEN 3


static GHashTable *apdu_table = NULL, *bitmap_table = NULL, *tlv_table = NULL;

static wmem_tree_t *transactions = NULL;

typedef struct _zvt_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    guint16 ctrl;
} zvt_transaction_t;

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

/* "don't care" value for min_len_field */
#define LEN_FIELD_ANY G_MAXUINT32

typedef struct _apdu_info_t {
    guint16          ctrl;
    guint32          min_len_field;
    zvt_direction_t  direction;
    void (*dissect_payload)(tvbuff_t *, gint, guint16,
            packet_info *, proto_tree *, zvt_transaction_t *);
} apdu_info_t;

/* control code 0 is not defined in the specification */
#define ZVT_CTRL_NONE      0x0000

#define CTRL_STATUS        0x040F
#define CTRL_INT_STATUS    0x04FF
#define CTRL_REGISTRATION  0x0600
#define CTRL_AUTHORISATION 0x0601
#define CTRL_COMPLETION    0x060F
#define CTRL_ABORT         0x061E
#define CTRL_REVERSAL      0x0630
#define CTRL_REFUND        0x0631
#define CTRL_END_OF_DAY    0x0650
#define CTRL_DIAG          0x0670
#define CTRL_INIT          0x0693
#define CTRL_PRINT_LINE    0x06D1
#define CTRL_PRINT_TEXT    0x06D3

static void dissect_zvt_int_status(tvbuff_t *tvb, gint offset, guint16 len,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans);
static void dissect_zvt_reg(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans);
static void dissect_zvt_bitmap_seq(tvbuff_t *tvb, gint offset, guint16 len,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans _U_);
static void dissect_zvt_init(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo _U_, proto_tree *tree, zvt_transaction_t *zvt_trans _U_);
static void dissect_zvt_pass_bitmap_seq(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans);
static void dissect_zvt_abort(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans);

static const apdu_info_t apdu_info[] = {
    { CTRL_STATUS,        0, DIRECTION_PT_TO_ECR, dissect_zvt_bitmap_seq },
    { CTRL_INT_STATUS,    0, DIRECTION_PT_TO_ECR, dissect_zvt_int_status },
    { CTRL_REGISTRATION,  4, DIRECTION_ECR_TO_PT, dissect_zvt_reg },
    /* authorisation has at least a 0x04 tag and 6 bytes for the amount */
    { CTRL_AUTHORISATION, 7, DIRECTION_ECR_TO_PT, dissect_zvt_bitmap_seq },
    { CTRL_COMPLETION,    0, DIRECTION_PT_TO_ECR, dissect_zvt_bitmap_seq },
    { CTRL_ABORT,         0, DIRECTION_PT_TO_ECR, dissect_zvt_abort },
    { CTRL_REVERSAL,      0, DIRECTION_ECR_TO_PT, dissect_zvt_pass_bitmap_seq },
    { CTRL_REFUND,        0, DIRECTION_ECR_TO_PT, dissect_zvt_pass_bitmap_seq },
    { CTRL_END_OF_DAY,    0, DIRECTION_ECR_TO_PT, NULL },
    { CTRL_DIAG,          0, DIRECTION_ECR_TO_PT, NULL },
    { CTRL_INIT,          0, DIRECTION_ECR_TO_PT, dissect_zvt_init },
    { CTRL_PRINT_LINE,    0, DIRECTION_PT_TO_ECR, NULL },
    { CTRL_PRINT_TEXT,    0, DIRECTION_PT_TO_ECR, dissect_zvt_bitmap_seq }
};


typedef struct _bitmap_info_t {
    guint8   bmp;
    guint16  payload_len;
    gint (*dissect_payload)(tvbuff_t *, gint, packet_info *, proto_tree *);
} bitmap_info_t;

#define BMP_TIMEOUT       0x01
#define BMP_MAX_STAT_INFO 0x02
#define BMP_SVC_BYTE      0x03
#define BMP_AMOUNT        0x04
#define BMP_PUMP_NR       0x05
#define BMP_TLV_CONTAINER 0x06
#define BMP_TRACE_NUM     0x0B
#define BMP_TIME          0x0C
#define BMP_DATE          0x0D
#define BMP_EXP_DATE      0x0E
#define BMP_CARD_SEQ_NUM  0x17
#define BMP_PAYMENT_TYPE  0x19
#define BMP_CARD_NUM      0x22
#define BMP_T2_DAT        0x23
#define BMP_T3_DAT        0x24
#define BMP_RES_CODE      0x27
#define BMP_TID           0x29
#define BMP_VU_NUMBER     0x2A
#define BMP_T1_DAT        0x2D
#define BMP_CVV_CVC       0x3A
#define BMP_AID           0x3B
#define BMP_ADD_DATA      0x3C
#define BMP_CC            0x49
#define BMP_RCPT_NUM      0x87
#define BMP_CARD_TYPE     0x8A
#define BMP_CARD_NAME     0x8B

#define BMP_PLD_LEN_UNKNOWN 0  /* unknown/variable bitmap payload len */

static gint dissect_zvt_amount(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static gint dissect_zvt_tlv_container(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_res_code(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree);
static inline gint dissect_zvt_cc(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree);
static inline gint dissect_zvt_terminal_id(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_time(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_date(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_card_type(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree);
static inline gint dissect_zvt_trace_number(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_expiry_date(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_card_number(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_card_name(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);
static inline gint dissect_zvt_additional_data(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree);

static const bitmap_info_t bitmap_info[] = {
    { BMP_TIMEOUT,                         1, NULL },
    { BMP_MAX_STAT_INFO,                   1, NULL },
    { BMP_SVC_BYTE,                        1, NULL },
    { BMP_AMOUNT,                          6, dissect_zvt_amount },
    { BMP_PUMP_NR,                         1, NULL },
    { BMP_TLV_CONTAINER, BMP_PLD_LEN_UNKNOWN, dissect_zvt_tlv_container },
    { BMP_TRACE_NUM,                       3, dissect_zvt_trace_number },
    { BMP_TIME,                            3, dissect_zvt_time },
    { BMP_DATE,                            2, dissect_zvt_date },
    { BMP_EXP_DATE,                        2, dissect_zvt_expiry_date },
    { BMP_CARD_SEQ_NUM,                    2, NULL },
    { BMP_PAYMENT_TYPE,                    1, NULL },
    { BMP_CARD_NUM,      BMP_PLD_LEN_UNKNOWN, dissect_zvt_card_number },
    { BMP_T2_DAT,        BMP_PLD_LEN_UNKNOWN, NULL },
    { BMP_T3_DAT,        BMP_PLD_LEN_UNKNOWN, NULL },
    { BMP_RES_CODE,                        1, dissect_zvt_res_code },
    { BMP_TID,                             4, dissect_zvt_terminal_id },
    { BMP_VU_NUMBER,                      15, NULL },
    { BMP_T1_DAT,        BMP_PLD_LEN_UNKNOWN, NULL },
    { BMP_CVV_CVC,                         2, NULL },
    { BMP_AID,                             8, NULL },
    { BMP_ADD_DATA,      BMP_PLD_LEN_UNKNOWN, dissect_zvt_additional_data },
    { BMP_CC,                              2, dissect_zvt_cc },
    { BMP_RCPT_NUM,                        2, NULL },
    { BMP_CARD_TYPE,                       1, dissect_zvt_card_type },
    { BMP_CARD_NAME,     BMP_PLD_LEN_UNKNOWN, dissect_zvt_card_name }
};


void proto_register_zvt(void);
void proto_reg_handoff_zvt(void);

static int proto_zvt = -1;

static int ett_zvt = -1;
static int ett_zvt_apdu = -1;
static int ett_zvt_bitmap = -1;
static int ett_zvt_tlv_dat_obj = -1;
static int ett_zvt_tlv_subseq = -1;
static int ett_zvt_tlv_tag = -1;
static int ett_zvt_tlv_receipt = -1;

static int hf_zvt_resp_in = -1;
static int hf_zvt_resp_to = -1;
static int hf_zvt_serial_char = -1;
static int hf_zvt_crc = -1;
static int hf_zvt_ctrl = -1;
static int hf_zvt_ccrc = -1;
static int hf_zvt_aprc = -1;
static int hf_zvt_len = -1;
static int hf_zvt_data = -1;
static int hf_zvt_int_status = -1;
static int hf_zvt_pwd = -1;
static int hf_zvt_reg_cfg = -1;
static int hf_zvt_res_code = -1;
static int hf_zvt_cc = -1;
static int hf_zvt_amount = -1;
static int hf_zvt_terminal_id = -1;
static int hf_zvt_time = -1;
static int hf_zvt_date = -1;
static int hf_zvt_card_type = -1;
static int hf_zvt_bmp = -1;
static int hf_zvt_tlv_total_len = -1;
static int hf_zvt_tlv_tag = -1;
static int hf_zvt_tlv_tag_class = -1;
static int hf_zvt_tlv_tag_type = -1;
static int hf_zvt_tlv_len = -1;
static int hf_zvt_text_lines_line = -1;
static int hf_zvt_permitted_cmd = -1;
static int hf_zvt_receipt_type = -1;
static int hf_zvt_receipt_parameter_positive_customer = -1;
static int hf_zvt_receipt_parameter_negative_customer = -1;
static int hf_zvt_receipt_parameter_positive_merchant = -1;
static int hf_zvt_receipt_parameter_negative_merchant = -1;
static int hf_zvt_receipt_parameter_customer_before_merchant = -1;
static int hf_zvt_receipt_parameter_print_short_receipt = -1;
static int hf_zvt_receipt_parameter_no_product_data = -1;
static int hf_zvt_receipt_parameter_ecr_as_printer = -1;
static int hf_zvt_receipt_parameter = -1;
static int hf_zvt_trace_number = -1;
static int hf_zvt_expiry_date = -1;
static int hf_zvt_card_number = -1;
static int hf_zvt_card_name = -1;
static int hf_zvt_additional_data = -1;
static int hf_zvt_characters_per_line = -1;
static int hf_zvt_receipt_info = -1;
static int hf_zvt_receipt_info_positive = -1;
static int hf_zvt_receipt_info_signature = -1;
static int hf_zvt_receipt_info_negative = -1;
static int hf_zvt_receipt_info_printing = -1;

static int * const receipt_parameter_flag_fields[] = {
    &hf_zvt_receipt_parameter_positive_customer,
    &hf_zvt_receipt_parameter_negative_customer,
    &hf_zvt_receipt_parameter_positive_merchant,
    &hf_zvt_receipt_parameter_negative_merchant,
    &hf_zvt_receipt_parameter_customer_before_merchant,
    &hf_zvt_receipt_parameter_print_short_receipt,
    &hf_zvt_receipt_parameter_no_product_data,
    &hf_zvt_receipt_parameter_ecr_as_printer,
    NULL
};

static int * const receipt_info_fields[] = {
    &hf_zvt_receipt_info_positive,
    &hf_zvt_receipt_info_signature,
    &hf_zvt_receipt_info_negative,
    &hf_zvt_receipt_info_printing,
    NULL
};

static expert_field ei_invalid_apdu_len = EI_INIT;

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
    { CTRL_REVERSAL, "Reversal" },
    { CTRL_REFUND, "Refund" },
    { CTRL_END_OF_DAY, "End Of Day" },
    { CTRL_DIAG, "Diagnosis" },
    { CTRL_INIT, "Initialisation" },
    { CTRL_PRINT_LINE, "Print Line" },
    { CTRL_PRINT_TEXT, "Print Text Block" },
    { 0, NULL }
};
static value_string_ext ctrl_field_ext = VALUE_STRING_EXT_INIT(ctrl_field);

/* ISO 4217 currency codes */
static const value_string zvt_cc[] = {
    { 0x0756, "CHF" },
    { 0x0826, "GBP" },
    { 0x0840, "USD" },
    { 0x0978, "EUR" },
    { 0, NULL }
};

static const value_string receipt_type[] = {
    { 0x01, "Transaction receipt (merchant)" },
    { 0x02, "Transaction receipt (customer)" },
    { 0x03, "Administration receipt" },
    { 0, NULL }
};

static const value_string card_type[] = {
    {  2, "ec-card" },
    {  5, "girocard" },
    {  6, "Mastercard" },
    { 10, "VISA" },
    { 46, "Maestro" },
    {  0, NULL }
};
static value_string_ext card_type_ext = VALUE_STRING_EXT_INIT(card_type);

static const value_string bitmap[] = {
    { BMP_TIMEOUT,       "Timeout" },
    { BMP_MAX_STAT_INFO, "max. status info" },
    { BMP_SVC_BYTE,      "Service byte" },
    { BMP_AMOUNT,        "Amount" },
    { BMP_PUMP_NR,       "Pump number" },
    { BMP_TLV_CONTAINER, "TLV container" },
    { BMP_TRACE_NUM,     "Trace number" },
    { BMP_TIME,          "Time" },
    { BMP_DATE,          "Date" },
    { BMP_EXP_DATE,      "Expiry date" },
    { BMP_CARD_SEQ_NUM,  "Card sequence number" },
    { BMP_PAYMENT_TYPE,  "Payment type" },
    { BMP_CARD_NUM,      "Card number" },
    { BMP_T2_DAT,        "Track 2 data" },
    { BMP_T3_DAT,        "Track 3 data" },
    { BMP_RES_CODE,      "Result code" },
    { BMP_TID,           "Terminal ID" },
    { BMP_VU_NUMBER,     "Contract number"},
    { BMP_T1_DAT,        "Track 1 data" },
    { BMP_CVV_CVC,       "CVV / CVC" },
    { BMP_AID,           "Authorization attribute" },
    { BMP_ADD_DATA,      "Additional data" },
    { BMP_CC,            "Currency code (CC)" },
    { BMP_RCPT_NUM,      "Receipt number" },
    { BMP_CARD_TYPE,     "Card type" },
    { BMP_CARD_NAME,     "Card name" },
    { 0, NULL }
};
static value_string_ext bitmap_ext = VALUE_STRING_EXT_INIT(bitmap);

static const value_string tlv_tag_class[] = {
    { 0x00, "Universal" },
    { 0x01, "Application" },
    { 0x02, "Context-specific" },
    { 0x03, "Private" },
    { 0, NULL }
};
static value_string_ext tlv_tag_class_ext = VALUE_STRING_EXT_INIT(tlv_tag_class);

#define TLV_TAG_TEXT_LINES          0x07
#define TLV_TAG_ATTRIBUTE           0x09
#define TLV_TAG_PERMITTED_ZVT_CMD   0x0A
#define TLV_TAG_CHARS_PER_LINE      0x12
#define TLV_TAG_DISPLAY_TEXTS       0x24
#define TLV_TAG_PRINT_TEXTS         0x25
#define TLV_TAG_PERMITTED_ZVT_CMDS  0x26
#define TLV_TAG_SUPPORTED_CHARSETS  0x27
#define TLV_TAG_PAYMENT_TYPE        0x2F
#define TLV_TAG_EMV_CFG_PARAM       0x40
#define TLV_TAG_CARD_TYPE_ID        0x41
#define TLV_TAG_RECEIPT_PARAMETER   0x45
#define TLV_TAG_APPLICATION         0x60
#define TLV_TAG_RECEIPT_PARAM       0x1F04
#define TLV_TAG_RECEIPT_TYPE        0x1F07
#define TLV_TAG_CARDHOLDER_AUTH     0x1F10
#define TLV_TAG_ONLINE_FLAG         0x1F11
#define TLV_TAG_CARD_TYPE           0x1F12
#define TLV_TAG_RECEIPT_INFO        0x1F37


typedef struct _tlv_seq_info_t {
    guint txt_enc;
} tlv_seq_info_t;


static gint
dissect_zvt_tlv_seq(tvbuff_t *tvb, gint offset, guint16 seq_max_len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info);

typedef struct _tlv_info_t {
    guint32 tag;
    gint (*dissect_payload)(tvbuff_t *, gint, gint,
            packet_info *, proto_tree *, tlv_seq_info_t *);
} tlv_info_t;

static inline gint dissect_zvt_tlv_text_lines(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info);

static inline gint dissect_zvt_tlv_subseq(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info);

static inline gint dissect_zvt_tlv_permitted_cmd(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_);

static inline gint dissect_zvt_tlv_receipt_type(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_);

static inline gint dissect_zvt_tlv_receipt_param(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_);

static inline gint dissect_zvt_tlv_characters_per_line(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info _U_);

static inline gint dissect_zvt_tlv_receipt_info(
        tvbuff_t *tvb, gint offset, gint len, packet_info *pinfo _U_,
        proto_tree *tree, tlv_seq_info_t *seq_info _U_);

static const tlv_info_t tlv_info[] = {
    { TLV_TAG_TEXT_LINES, dissect_zvt_tlv_text_lines },
    { TLV_TAG_DISPLAY_TEXTS, dissect_zvt_tlv_subseq },
    { TLV_TAG_PRINT_TEXTS, dissect_zvt_tlv_subseq },
    { TLV_TAG_PAYMENT_TYPE, dissect_zvt_tlv_subseq },
    { TLV_TAG_PERMITTED_ZVT_CMDS, dissect_zvt_tlv_subseq },
    { TLV_TAG_PERMITTED_ZVT_CMD, dissect_zvt_tlv_permitted_cmd },
    { TLV_TAG_RECEIPT_TYPE, dissect_zvt_tlv_receipt_type },
    { TLV_TAG_RECEIPT_PARAM, dissect_zvt_tlv_receipt_param },
    { TLV_TAG_CHARS_PER_LINE, dissect_zvt_tlv_characters_per_line },
    { TLV_TAG_RECEIPT_INFO, dissect_zvt_tlv_receipt_info }
};

static const value_string tlv_tags[] = {
    { TLV_TAG_TEXT_LINES,         "Text lines" },
    { TLV_TAG_ATTRIBUTE,          "Attribute"},
    { TLV_TAG_CHARS_PER_LINE,
        "Number of characters per line of the printer" },
    { TLV_TAG_DISPLAY_TEXTS,      "Display texts" },
    { TLV_TAG_PRINT_TEXTS,        "Print texts" },
    { TLV_TAG_PERMITTED_ZVT_CMDS, "List of permitted ZVT commands" },
    { TLV_TAG_SUPPORTED_CHARSETS, "List of supported character sets" },
    { TLV_TAG_PAYMENT_TYPE,       "Payment type" },
    { TLV_TAG_EMV_CFG_PARAM,      "EMV config parameter" },
    { TLV_TAG_CARD_TYPE_ID,       "Card type ID" },
    { TLV_TAG_RECEIPT_PARAMETER,  "Receipt parameter (EMV)" },
    { TLV_TAG_APPLICATION,        "Application" },
    { TLV_TAG_RECEIPT_PARAM,      "Receipt parameter" },
    { TLV_TAG_RECEIPT_TYPE,       "Receipt type" },
    { TLV_TAG_CARDHOLDER_AUTH,    "Cardholder authentication" },
    { TLV_TAG_ONLINE_FLAG,        "Online flag" },
    { TLV_TAG_CARD_TYPE,          "Card type" },
    { TLV_TAG_RECEIPT_INFO,       "Receipt information" },
    { 0, NULL }
};
static value_string_ext tlv_tags_ext = VALUE_STRING_EXT_INIT(tlv_tags);

static inline gint dissect_zvt_tlv_text_lines(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info)
{
    proto_tree_add_item(tree, hf_zvt_text_lines_line,
            tvb, offset, len, seq_info->txt_enc | ENC_NA);
    return len;
}


static inline gint dissect_zvt_tlv_subseq(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info)
{
    proto_tree *subseq_tree;

    subseq_tree = proto_tree_add_subtree(tree,
            tvb, offset, len, ett_zvt_tlv_subseq, NULL,
            "Subsequence");

    return dissect_zvt_tlv_seq(tvb, offset, len, pinfo, subseq_tree, seq_info);
}


static inline gint dissect_zvt_tlv_permitted_cmd(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_)
{
    proto_tree_add_item(tree, hf_zvt_permitted_cmd,
            tvb, offset, len, ENC_BIG_ENDIAN);
    return len;
}


static inline gint dissect_zvt_tlv_receipt_type(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_)
{
    proto_tree_add_item(tree, hf_zvt_receipt_type,
            tvb, offset, len, ENC_BIG_ENDIAN);
    return len;
}


static inline gint dissect_zvt_tlv_receipt_param(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_zvt_receipt_parameter, ett_zvt_tlv_receipt, receipt_parameter_flag_fields, ENC_BIG_ENDIAN);
    return len;
}


static inline gint dissect_zvt_tlv_characters_per_line(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info _U_)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 1, NULL, FALSE);
    proto_tree_add_string(tree, hf_zvt_characters_per_line, tvb, offset, 1, str);
    return len;
}


static inline gint dissect_zvt_tlv_receipt_info(
        tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree, tlv_seq_info_t *seq_info _U_)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_zvt_receipt_info,
            ett_zvt_tlv_receipt, receipt_info_fields, ENC_BIG_ENDIAN);
    return len;
}


static gint
dissect_zvt_tlv_tag(tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree, guint32 *tag)
{
    gint offset_start;
    guint8 one_byte;
    guint32 _tag;
    proto_item *tag_ti;
    proto_tree *tag_tree;

    offset_start = offset;

    one_byte = tvb_get_guint8(tvb, offset);
    _tag = one_byte;
    offset++;
    if ((one_byte & 0x1F) == 0x1F) {
        do {
            if ((offset-offset_start)>4) {
                /* we support tags of <= 4 bytes
                   (the specification defines only 1 and 2-byte tags) */
                return -1;
            }
            one_byte = tvb_get_guint8(tvb, offset);
            _tag = _tag << 8 | (one_byte&0x7F);
            offset++;
        } while (one_byte & 0x80);
    }

    tag_ti = proto_tree_add_uint_format(tree, hf_zvt_tlv_tag,
            tvb, offset_start, offset-offset_start, _tag,
            "Tag: %s (0x%x)",
            val_to_str_ext(_tag, &tlv_tags_ext, "unknown"), _tag);

    tag_tree = proto_item_add_subtree(tag_ti, ett_zvt_tlv_tag);
    proto_tree_add_item(tag_tree, hf_zvt_tlv_tag_class,
            tvb, offset_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tag_tree, hf_zvt_tlv_tag_type,
            tvb, offset_start, 1, ENC_BIG_ENDIAN);

    if (tag)
        *tag = _tag;
    return offset-offset_start;
}


static gint
dissect_zvt_tlv_len(tvbuff_t *tvb, gint offset,
        packet_info *pinfo _U_, proto_tree *tree, int hf, guint16 *len)
{
    guint16 _len;
    gint    len_bytes = 1;

    _len = tvb_get_guint8(tvb, offset);
    if (_len & 0x80) {
        if ((_len & 0x03) == 1) {
            len_bytes++;
            _len = tvb_get_guint8(tvb, offset+1);
        }
        else if ((_len & 0x03) == 2) {
            len_bytes += 2;
            _len = tvb_get_ntohs(tvb, offset+1);
        }
        else {
            /* XXX - expert info */
            return -1;
        }
    }

    proto_tree_add_uint(tree, hf, tvb, offset, len_bytes, _len);
    if (len)
        *len = _len;

    return len_bytes;
}


static gint
dissect_zvt_tlv_seq(tvbuff_t *tvb, gint offset, guint16 seq_max_len,
        packet_info *pinfo, proto_tree *tree, tlv_seq_info_t *seq_info)
{
    gint            offset_start;
    proto_item     *dat_obj_it;
    proto_tree     *dat_obj_tree;
    gint            tag_len;
    guint32         tag;
    gint            data_len_bytes;
    guint16         data_len = 0;
    tlv_info_t     *ti;
    gint            ret;

    if (!seq_info) {
        seq_info = wmem_new(pinfo->pool, tlv_seq_info_t);

        /* by default, text lines are using the CP437 charset
           there's an object to change the encoding
           (XXX - does this change apply only to the current message?) */
        seq_info->txt_enc = ENC_CP437;
    }

    offset_start = offset;

    while (offset-offset_start < seq_max_len) {
        dat_obj_tree = proto_tree_add_subtree(tree,
            tvb, offset, -1, ett_zvt_tlv_dat_obj, &dat_obj_it,
            "TLV data object");

        tag_len = dissect_zvt_tlv_tag(tvb, offset, pinfo, dat_obj_tree, &tag);
        if (tag_len <= 0)
            return offset - offset_start;
        offset += tag_len;

        data_len_bytes = dissect_zvt_tlv_len(tvb, offset, pinfo,
                dat_obj_tree,hf_zvt_tlv_len, &data_len);
        if (data_len_bytes > 0)
            offset += data_len_bytes;

        /* set the sequence length now that we know it
           this way, we don't have to put the whole switch statement
           under if (data_len > 0) */
        proto_item_set_len(dat_obj_it, tag_len + data_len_bytes + data_len);
        if (data_len == 0)
            continue;

        ti = (tlv_info_t *)g_hash_table_lookup(
            tlv_table, GUINT_TO_POINTER((guint)tag));
        if (ti && ti->dissect_payload) {
            ret = ti->dissect_payload(
                    tvb, offset, (gint)data_len, pinfo, dat_obj_tree, seq_info);
            if (ret <= 0) {
                /* XXX - expert info */
            }
        }

        offset += data_len;
    }

    return offset - offset_start;
}


static gint
dissect_zvt_tlv_container(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint     offset_start;
    gint     total_len_bytes, seq_len;
    guint16  seq_max_len = 0;

    offset_start = offset;

    total_len_bytes = dissect_zvt_tlv_len(tvb, offset, pinfo,
                tree, hf_zvt_tlv_total_len, &seq_max_len);
    if (total_len_bytes > 0)
        offset += total_len_bytes;

    seq_len = dissect_zvt_tlv_seq(
            tvb, offset, seq_max_len, pinfo, tree, NULL);
    if (seq_len  > 0)
        offset += seq_len;

    return offset - offset_start;
}


static inline gint dissect_zvt_res_code(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_zvt_res_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}


static inline gint dissect_zvt_cc(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_zvt_cc, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}


static inline gint dissect_zvt_card_type(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_zvt_card_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}


static inline gint dissect_zvt_terminal_id(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 4, NULL, FALSE);
    proto_tree_add_string(tree, hf_zvt_terminal_id, tvb, offset, 4, str);
    return 4;
}


static inline gint dissect_zvt_amount(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 6, NULL, FALSE);
    proto_tree_add_uint64(tree, hf_zvt_amount, tvb, offset, 6, g_ascii_strtoll(str,NULL,10));
    return 6;
}


static inline gint dissect_zvt_time(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 3, NULL, FALSE);
    gchar  *fstr = (char *)wmem_alloc(pinfo->pool, 9);
    fstr[0] = str[0];
    fstr[1] = str[1];
    fstr[2] = ':';
    fstr[3] = str[2];
    fstr[4] = str[3];
    fstr[5] = ':';
    fstr[6] = str[4];
    fstr[7] = str[5];
    fstr[8] = 0;
    proto_tree_add_string(tree, hf_zvt_time, tvb, offset, 3, fstr);
    return 3;
}


static inline gint dissect_zvt_date(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 2, NULL, FALSE);
    gchar  *fstr = (char *)wmem_alloc(pinfo->pool, 6);
    fstr[0] = str[0];
    fstr[1] = str[1];
    fstr[2] = '/';
    fstr[3] = str[2];
    fstr[4] = str[3];
    fstr[5] = 0;
    proto_tree_add_string(tree, hf_zvt_date, tvb, offset, 2, fstr);
    return 2;
}


static inline gint dissect_zvt_expiry_date(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 2, NULL, FALSE);
    gchar  *fstr = (char *)wmem_alloc(pinfo->pool, 6);
    fstr[0] = str[0];
    fstr[1] = str[1];
    fstr[2] = '/';
    fstr[3] = str[2];
    fstr[4] = str[3];
    fstr[5] = 0;
    proto_tree_add_string(tree, hf_zvt_expiry_date, tvb, offset, 2, fstr);
    return 2;
}


static inline gint dissect_zvt_trace_number(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset, 3, NULL, FALSE);
    proto_tree_add_string(tree, hf_zvt_trace_number, tvb, offset, 3, str);
    return 3;
}


static inline gint dissect_zvt_card_number(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8 tens = tvb_get_guint8(tvb, offset) & 0x0f;
    guint8 ones = tvb_get_guint8(tvb, offset + 1) & 0x0f;
    guint8 length = tens * 10 + ones;
    const gchar *str = tvb_bcd_dig_to_str_be(pinfo->pool, tvb, offset + 2, length, NULL, FALSE);
    proto_tree_add_string(tree, hf_zvt_card_number, tvb, offset + 2, length, str);
    return 2 + length;
}


static inline gint dissect_zvt_card_name(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8 tens = tvb_get_guint8(tvb, offset) & 0x0f;
    guint8 ones = tvb_get_guint8(tvb, offset + 1) & 0x0f;
    guint8 length = tens * 10 + ones;
    const guint8 * str = NULL;
    proto_tree_add_item_ret_string(tree, hf_zvt_card_name, tvb, offset + 2, length, ENC_ASCII, pinfo->pool, &str);
    return 2 + length;
}


static inline gint dissect_zvt_additional_data(
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8 hundrets = tvb_get_guint8(tvb, offset) & 0x0f;
    guint8 tens = tvb_get_guint8(tvb, offset + 1) & 0x0f;
    guint8 ones = tvb_get_guint8(tvb, offset + 2) & 0x0f;
    guint16 length = hundrets * 100 + tens * 10 + ones;
    const guint8 * str = NULL;
    proto_tree_add_item_ret_string(tree, hf_zvt_additional_data, tvb, offset + 3, length, ENC_ASCII, pinfo->pool, &str);
    return 3 + length;
}


/* dissect one "bitmap", i.e BMP and the corresponding data */
static gint
dissect_zvt_bitmap(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint           offset_start;
    guint8         bmp;
    proto_item    *bitmap_it;
    proto_tree    *bitmap_tree;
    bitmap_info_t *bi;
    gint           ret;

    offset_start = offset;

    bmp = tvb_get_guint8(tvb, offset);
    if (try_val_to_str(bmp, bitmap) == NULL)
        return -1;

    bitmap_tree = proto_tree_add_subtree(tree,
            tvb, offset, -1, ett_zvt_bitmap, &bitmap_it, "Bitmap");

    proto_tree_add_item(bitmap_tree, hf_zvt_bmp,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(bitmap_it, ": %s",
            val_to_str(bmp, bitmap, "unknown"));
    offset++;

    bi = (bitmap_info_t *)g_hash_table_lookup(
            bitmap_table, GUINT_TO_POINTER((guint)bmp));
    if (bi) {
        if (bi->dissect_payload) {
            ret = bi->dissect_payload(tvb, offset, pinfo, bitmap_tree);
            if (ret >= 0)
                offset += ret;
        }
        else if (bi->payload_len != BMP_PLD_LEN_UNKNOWN)
            offset += bi->payload_len;
    }

    proto_item_set_len(bitmap_it, offset - offset_start);
    return offset - offset_start;
}


static void dissect_zvt_int_status(tvbuff_t *tvb, gint offset, guint16 len,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans)
{
    proto_tree_add_item(tree, hf_zvt_int_status,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (len > 1)
        offset++; /* skip "timeout" */

    if (len > 2)
        dissect_zvt_bitmap_seq(tvb, offset, len-2, pinfo, tree, zvt_trans);
}


static void
dissect_zvt_reg(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans)
{
    proto_tree_add_item(tree, hf_zvt_pwd, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_zvt_reg_cfg,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* check for the optional part CC|0x03|service byte|TLV */
    if (tvb_captured_length_remaining(tvb, offset)>=2) {
        offset += dissect_zvt_cc(tvb, offset, pinfo, tree);
    }

    /* it's ok if the remaining len is 0 */
    dissect_zvt_bitmap_seq(tvb, offset,
            tvb_captured_length_remaining(tvb, offset),
            pinfo, tree, zvt_trans);
}


static void dissect_zvt_init(
        tvbuff_t *tvb, gint offset, guint16 len _U_, packet_info *pinfo _U_,
        proto_tree *tree, zvt_transaction_t *zvt_trans _U_)
{
    proto_tree_add_item(tree, hf_zvt_pwd, tvb, offset, 3, ENC_NA);
}


static void
dissect_zvt_abort(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans)
{
    proto_tree_add_item(tree, hf_zvt_res_code, tvb, offset, 1, ENC_NA);
    offset += 1;

    dissect_zvt_bitmap_seq(tvb, offset,
            tvb_captured_length_remaining(tvb, offset),
            pinfo, tree, zvt_trans);
}


static void
dissect_zvt_pass_bitmap_seq(tvbuff_t *tvb, gint offset, guint16 len _U_,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans)
{
    proto_tree_add_item(tree, hf_zvt_pwd, tvb, offset, 3, ENC_NA);
    offset += 3;

    dissect_zvt_bitmap_seq(tvb, offset,
            tvb_captured_length_remaining(tvb, offset),
            pinfo, tree, zvt_trans);
}


/* dissect a sequence of bitmaps
   (which may be the complete APDU payload or a part of it) */
static void
dissect_zvt_bitmap_seq(tvbuff_t *tvb, gint offset, guint16 len,
        packet_info *pinfo, proto_tree *tree, zvt_transaction_t *zvt_trans _U_)
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

    if (zvt_trans->rqst_frame == pinfo->num) {
        dir = ai->direction;
    }
    else if (zvt_trans->resp_frame == pinfo->num) {
        if (ai->direction == DIRECTION_ECR_TO_PT)
            dir = DIRECTION_PT_TO_ECR;
        else
            dir = DIRECTION_ECR_TO_PT;
    }

    if (dir  == DIRECTION_ECR_TO_PT) {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_ECR)+1, ADDR_ECR);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PT)+1, ADDR_PT);
    }
    else if (dir  == DIRECTION_PT_TO_ECR) {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PT)+1, ADDR_PT);
        set_address(&pinfo->dst, AT_STRINGZ,
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
        len = tvb_get_letohs(tvb, offset+3);
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
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                byte == CCRC_POS ? "Positive completion" : "Negative completion");
        offset++;
        proto_tree_add_item(apdu_tree, hf_zvt_aprc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        zvt_trans = (zvt_transaction_t *)wmem_tree_lookup32_le(
                transactions, pinfo->num);
        if (zvt_trans && zvt_trans->resp_frame==0) {
            /* there's a pending request, this packet is the response */
            zvt_trans->resp_frame = pinfo->num;
        }

        if (zvt_trans && zvt_trans->resp_frame == pinfo->num) {
            it = proto_tree_add_uint(apdu_tree, hf_zvt_resp_to,
                    NULL, 0, 0, zvt_trans->rqst_frame);
            proto_item_set_generated(it);
        }
    }
    else {
        ctrl = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(apdu_tree, hf_zvt_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                val_to_str_const(ctrl, ctrl_field, "Unknown 0x%x"));
        offset += 2;

        if (PINFO_FD_VISITED(pinfo)) {
            zvt_trans = (zvt_transaction_t *)wmem_tree_lookup32(
                    transactions, pinfo->num);
            if (zvt_trans && zvt_trans->rqst_frame==pinfo->num &&
                    zvt_trans->resp_frame!=0) {
               it = proto_tree_add_uint(apdu_tree, hf_zvt_resp_in,
                       NULL, 0, 0, zvt_trans->resp_frame);
               proto_item_set_generated(it);
            }
        }
        else {
            zvt_trans = wmem_new(wmem_file_scope(), zvt_transaction_t);
            zvt_trans->rqst_frame = pinfo->num;
            zvt_trans->resp_frame = 0;
            zvt_trans->ctrl = ctrl;
            wmem_tree_insert32(transactions,
                    zvt_trans->rqst_frame, (void *)zvt_trans);
        }
    }

    ai = (apdu_info_t *)g_hash_table_lookup(
            apdu_table, GUINT_TO_POINTER((guint)ctrl));

    it = proto_tree_add_uint(apdu_tree, hf_zvt_len, tvb, offset, len_bytes, len);
    if (ai && ai->min_len_field!=LEN_FIELD_ANY && len<ai->min_len_field) {
        expert_add_info_format(pinfo, it, &ei_invalid_apdu_len,
                "The APDU length is too short. The minimum length is %d",
                ai->min_len_field);
    }
    offset += len_bytes;

    zvt_set_addresses(pinfo, zvt_trans);

    if (len > 0) {
        if (ai && ai->dissect_payload)
            ai->dissect_payload(tvb, offset, len, pinfo, apdu_tree, zvt_trans);
        else
            proto_tree_add_item(apdu_tree, hf_zvt_data,
                    tvb, offset, len, ENC_NA);
    }
    offset += len;

    proto_item_set_len(apdu_it, offset - offset_start);
    return offset - offset_start;
}


static gint
dissect_zvt_serial(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
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

static guint get_zvt_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint len = tvb_get_guint8(tvb, offset+2);
    if (len == 0xFF)
        if (tvb_captured_length_remaining(tvb, offset) >= 5)
            len = tvb_get_letohs(tvb, offset+3) + 5;
        else
            len = 0;
    else
        len += 3;

    return len;
}

static int
dissect_zvt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, ZVT_APDU_MIN_LEN,
                     get_zvt_message_len, dissect_zvt, data);
    return tvb_captured_length(tvb);
}

static void
zvt_shutdown(void)
{
    g_hash_table_destroy(tlv_table);
    g_hash_table_destroy(apdu_table);
    g_hash_table_destroy(bitmap_table);
}

void
proto_register_zvt(void)
{
    guint     i;
    expert_module_t* expert_zvt;

    static gint *ett[] = {
        &ett_zvt,
        &ett_zvt_apdu,
        &ett_zvt_bitmap,
        &ett_zvt_tlv_dat_obj,
        &ett_zvt_tlv_subseq,
        &ett_zvt_tlv_tag,
        &ett_zvt_tlv_receipt
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
        { &hf_zvt_int_status,
            { "Intermediate status", "zvt.int_status",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_pwd,
            { "Password", "zvt.password",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_reg_cfg,
            { "Config byte", "zvt.reg.config_byte",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_res_code,
            { "Result Code", "zvt.result_code",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        /* we don't call the filter zvt.reg.cc, the currency code
           appears in several apdus */
        { &hf_zvt_cc,
            { "Currency Code", "zvt.cc",
                FT_UINT16, BASE_HEX, VALS(zvt_cc), 0, NULL, HFILL } },
        { &hf_zvt_card_type,
            { "Card Type", "zvt.card_type", FT_UINT8,
                BASE_DEC|BASE_EXT_STRING, &card_type_ext, 0, NULL, HFILL } },
        { &hf_zvt_terminal_id,
            { "Terminal ID", "zvt.terminal_id", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_amount,
            { "Amount", "zvt.amount", FT_UINT48,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_zvt_time,
            { "Time", "zvt.time", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_date,
            { "Date", "zvt.date", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_bmp,
            { "BMP", "zvt.bmp", FT_UINT8,
                BASE_HEX|BASE_EXT_STRING, &bitmap_ext, 0, NULL, HFILL } },
        { &hf_zvt_tlv_total_len,
            { "Total length", "zvt.tlv.total_len",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_zvt_tlv_tag,
            { "Tag", "zvt.tlv.tag", FT_UINT32,
                BASE_HEX|BASE_EXT_STRING, &tlv_tags_ext, 0, NULL, HFILL } },
        { &hf_zvt_tlv_tag_class,
            { "Class", "zvt.tlv.tag.class", FT_UINT8,
                BASE_HEX|BASE_EXT_STRING, &tlv_tag_class_ext,
                0xC0, NULL, HFILL } },
        { &hf_zvt_tlv_tag_type,
            { "Type", "zvt.tlv.tag.type", FT_BOOLEAN,
                8, TFS(&tfs_constructed_primitive), 0x20, NULL, HFILL } },
        { &hf_zvt_tlv_len,
            { "Length", "zvt.tlv.len",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_zvt_text_lines_line,
            { "Text line", "zvt.tlv.text_lines.line",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_permitted_cmd,
            { "Permitted command", "zvt.tlv.permitted_command",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_zvt_receipt_type,
            { "Receipt type", "zvt.tlv.receipt_type",
                FT_UINT16, BASE_HEX, VALS(receipt_type), 0, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_positive_customer,
            { "Positive customer receipt", "zvt.tlv.receipt_parameter.positive_customer", FT_BOOLEAN,
                8, TFS(&tfs_required_not_required), 0x80, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_negative_customer,
            { "Negative customer receipt", "zvt.tlv.receipt_parameter.negative_customer", FT_BOOLEAN,
                8, TFS(&tfs_required_not_required), 0x40, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_positive_merchant,
            { "Positive merchant receipt", "zvt.tlv.receipt_parameter.positive_customer", FT_BOOLEAN,
                8, TFS(&tfs_required_not_required), 0x20, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_negative_merchant,
            { "Negative merchant receipt", "zvt.tlv.receipt_parameter.negative_customer", FT_BOOLEAN,
                8, TFS(&tfs_required_not_required), 0x10, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_customer_before_merchant,
            { "Customer receipt should be sent before the merchant receipt", "zvt.tlv.receipt_parameter.customer_first", FT_BOOLEAN,
                8, TFS(&tfs_yes_no), 0x08, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_print_short_receipt,
            { "Print short receipt", "zvt.tlv.receipt_parameter.short_receipt", FT_BOOLEAN,
                8, TFS(&tfs_yes_no), 0x04, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_no_product_data,
            { "Do not print product data (from BMP 3C) on the receipt", "zvt.tlv.receipt_parameter.no_product", FT_BOOLEAN,
                8, TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_zvt_receipt_parameter_ecr_as_printer,
            { "Use ECR as printer", "zvt.tlv.receipt_parameter.ecr_as_printer", FT_BOOLEAN,
                8, TFS(&tfs_yes_no), 0x01, NULL, HFILL } },
        { &hf_zvt_receipt_parameter,
            { "Receipt parameter", "zvt.tlv.receipt_parameter", FT_UINT8,
                BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_zvt_trace_number,
            { "Trace number", "zvt.trace_number", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_expiry_date,
            { "Expiry date", "zvt.expiry_date", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_card_number,
            { "Card number", "zvt.card_number", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_card_name,
            { "Card name", "zvt.card_name", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_additional_data,
            { "Additional data", "zvt.additional_data", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_characters_per_line,
            { "Characters per line", "zvt.characters_per_line", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_zvt_receipt_info,
            { "Receipt information", "zvt.tlv.receipt_info", FT_UINT8,
                BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_zvt_receipt_info_positive,
            { "Positive receipt (authorised)",
                "zvt.tlv.receipt_info.positive", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), 0x01, NULL, HFILL } },
        { &hf_zvt_receipt_info_signature,
            { "Receipt contains a signature",
                "zvt.tlv.receipt_info.signature", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_zvt_receipt_info_negative,
            { "Negative receipt (aborted, rejected)",
                "zvt.tlv.receipt_info.negative", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), 0x04, NULL, HFILL } },
        { &hf_zvt_receipt_info_printing,
            { "Printing is mandatory", "zvt.tlv.receipt_info.printing",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL } }
    };

    static ei_register_info ei[] = {
        { &ei_invalid_apdu_len,
            { "zvt.apdu_len.invalid", PI_PROTOCOL, PI_WARN,
                "The APDU length is too short. The minimum length is %d",
                EXPFILL }}
    };

    apdu_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(apdu_info); i++) {
        g_hash_table_insert(apdu_table,
                            GUINT_TO_POINTER((guint)apdu_info[i].ctrl),
                            (gpointer)(&apdu_info[i]));
    }

    bitmap_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(bitmap_info); i++) {
        g_hash_table_insert(bitmap_table,
                            GUINT_TO_POINTER((guint)bitmap_info[i].bmp),
                            (gpointer)(&bitmap_info[i]));
    }

    tlv_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(tlv_info); i++) {
        g_hash_table_insert(tlv_table,
                            GUINT_TO_POINTER((guint)tlv_info[i].tag),
                            (gpointer)(&tlv_info[i]));
    }

    proto_zvt = proto_register_protocol("ZVT Kassenschnittstelle", "ZVT", "zvt");

    proto_register_field_array(proto_zvt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_zvt = expert_register_protocol(proto_zvt);
    expert_register_field_array(expert_zvt, ei, array_length(ei));

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    /* register by name to allow mapping to a user DLT */
    register_dissector("zvt", dissect_zvt, proto_zvt);

    register_shutdown_routine(zvt_shutdown);
}


void
proto_reg_handoff_zvt(void)
{
    dissector_handle_t  zvt_tcp_handle;

    zvt_tcp_handle = create_dissector_handle(dissect_zvt_tcp, proto_zvt);

    dissector_add_for_decode_as_with_preference("tcp.port", zvt_tcp_handle);
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
