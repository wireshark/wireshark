/* packet-dpaux.c
 * Routines for DisplayPort AUX-Channel dissection
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
* SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <conversation.h>

#include <epan/packet.h>
#include <epan/proto_data.h>

#include "packet-dpaux.h"

void proto_register_dpaux(void);

static int proto_dpaux = -1;

static int hf_dpaux_transaction_type = -1;
static int hf_dpaux_native_req_cmd = -1;
static int hf_dpaux_i2c_req_cmd = -1;
static int hf_dpaux_reply_cmd = -1;
static int hf_dpaux_mot = -1;
static int hf_dpaux_addr = -1;
static int hf_dpaux_len = -1;
static int hf_dpaux_data = -1;

static int hf_dpaux_reg_addr = -1;

static int hf_00000 = -1;
static int hf_00000_MINOR = -1;
static int hf_00000_MAJOR = -1;
static int * const reg00000_fields[] = {
    &hf_00000_MAJOR,
    &hf_00000_MINOR,
    NULL
};

static int hf_00001 = -1;
static int hf_00001_MAX_LINK_RATE = -1;
static int * const reg00001_fields[] = {
    &hf_00001_MAX_LINK_RATE,
    NULL
};

static int hf_00002 = -1;
static int hf_00002_MAX_LANE_COUNT = -1;
static int hf_00002_POST_LT_ADJ_REQ_SUPPORTED = -1;
static int hf_00002_TPS3_SUPPORTED = -1;
static int hf_00002_ENHANCED_FRAME_CAP = -1;
static int * const reg00002_fields[] = {
    &hf_00002_MAX_LANE_COUNT,
    &hf_00002_POST_LT_ADJ_REQ_SUPPORTED,
    &hf_00002_TPS3_SUPPORTED,
    &hf_00002_ENHANCED_FRAME_CAP,
    NULL
};

static int hf_00003 = -1;
static int hf_00003_MAX_DOWNSPREAD = -1;
static int hf_00003_NO_AUX_TRANSACTION_LINK_TRAINING = -1;
static int hf_00003_TPS4_SUPPORTED = -1;
static int * const reg00003_fields[] = {
    &hf_00003_MAX_DOWNSPREAD,
    &hf_00003_NO_AUX_TRANSACTION_LINK_TRAINING,
    &hf_00003_TPS4_SUPPORTED,
    NULL
};

static int hf_00004 = -1;
static int hf_00004_NORP = -1;
static int hf_00004_5V_DP_PWR_CAP = -1;
static int hf_00004_12V_DP_PWR_CAP = -1;
static int hf_00004_18V_DP_PWR_CAP = -1;
static int * const reg00004_fields[] = {
    &hf_00004_NORP,
    &hf_00004_5V_DP_PWR_CAP,
    &hf_00004_12V_DP_PWR_CAP,
    &hf_00004_18V_DP_PWR_CAP,
    NULL
};

/* Initialize the subtree pointers */
static gint ett_dpaux = -1;
static gint ett_register = -1;

struct dpaux_transaction {
    gboolean is_native;
    guint32 addr;
};

enum {
    DPAUX_TRANSACTION_NATIVE,
    DPAUX_TRANSACTION_I2C_OVER_AUX,
    DPAUX_TRANSACTION_N_A,
};

enum {
    DPAUX_REPLY_CODE_ACK =        0x0,
    DPAUX_REPLY_CODE_I2C_ACK =    0x0,
    DPAUX_REPLY_CODE_NACK =       0x1,
    DPAUX_REPLY_CODE_DEFER =      0x2,
    DPAUX_REPLY_CODE_I2C_NACK =   0x4,
    DPAUX_REPLY_CODE_I2C_DEFER =  0x8,
};

enum {
    DPAUX_REGISTER_TYPE_BITFIELD,
};

struct bitfield_data {
    int *hf;
    int * const *fields;
};

struct dpaux_register {
    guint32 addr;
    guint8 type;
    union {
        struct bitfield_data bitfield;
    } data;
};

static struct dpaux_register registers[] = {
    { 0x0, DPAUX_REGISTER_TYPE_BITFIELD, .data.bitfield = { &hf_00000, reg00000_fields } },
    { 0x1, DPAUX_REGISTER_TYPE_BITFIELD, .data.bitfield = { &hf_00001, reg00001_fields } },
    { 0x2, DPAUX_REGISTER_TYPE_BITFIELD, .data.bitfield = { &hf_00002, reg00002_fields } },
    { 0x3, DPAUX_REGISTER_TYPE_BITFIELD, .data.bitfield = { &hf_00003, reg00003_fields } },
    { 0x4, DPAUX_REGISTER_TYPE_BITFIELD, .data.bitfield = { &hf_00004, reg00004_fields } },
};

static int
dissect_dpaux_register(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    unsigned int offset, unsigned int register_addr)
{
    unsigned int k;
    struct dpaux_register *reg = NULL;

    for (k = 0; k < G_N_ELEMENTS(registers); ++k) {
        if (registers[k].addr == register_addr) {
            reg = &registers[k];
            break;
        }
    }

    if (!reg)
        return -1;

    switch (reg->type) {
    case DPAUX_REGISTER_TYPE_BITFIELD:
        proto_tree_add_bitmask_with_flags(tree, tvb, offset,
                                          *reg->data.bitfield.hf, 0,
                                          reg->data.bitfield.fields,
                                          ENC_BIG_ENDIAN, BMT_NO_FLAGS);
        break;
    }

    return 1;
}

static int
dissect_dpaux_from_source(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 type = tvb_get_bits8(tvb, 0, 1);
    guint8 mot = tvb_get_bits8(tvb, 1, 1);
    guint8 cmd = tvb_get_bits8(tvb, 2, 2);
    guint32 addr = tvb_get_bits32(tvb, 4, 20, ENC_BIG_ENDIAN);
    guint8 len = tvb_get_guint8(tvb, 3) + 1;
    gboolean is_read = cmd & 0x1;

    conversation_t *conversation = NULL;
    struct dpaux_transaction *transaction = NULL;

    conversation = conversation_new(pinfo->num,  &pinfo->src, &pinfo->dst,
        CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);

    transaction = wmem_new(wmem_file_scope(), struct dpaux_transaction);
    transaction->is_native = type;
    transaction->addr = addr;

    conversation_add_proto_data(conversation, proto_dpaux, (void *)transaction);

    proto_tree_add_uint(tree, hf_dpaux_transaction_type, tvb, 0, 0,
        type ? DPAUX_TRANSACTION_NATIVE : DPAUX_TRANSACTION_I2C_OVER_AUX);

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                transaction->is_native ? "Native" : "I2C-over-AUX");
    col_set_str(pinfo->cinfo, COL_INFO, is_read ? "RD" : "WR");
    col_append_fstr(pinfo->cinfo, COL_INFO, " %u byte%s %s 0x%05x",
        len, len > 1 ? "s" : "", is_read ? "FROM" : "TO", addr);

    if (transaction->is_native) {
        proto_tree_add_uint(tree, hf_dpaux_native_req_cmd, tvb, 0, 1, cmd);
    } else {
        proto_tree_add_uint(tree, hf_dpaux_i2c_req_cmd, tvb, 0, 1, cmd);
        proto_tree_add_boolean(tree, hf_dpaux_mot, tvb, 0, 1, mot);
    }
    proto_tree_add_uint(tree, hf_dpaux_addr, tvb, 0, 3, addr);
    proto_tree_add_uint(tree, hf_dpaux_len, tvb, 3, 1, len);


    if (!is_read)
        proto_tree_add_item(tree, hf_dpaux_data, tvb, 4, len, ENC_NA);

    return 0;
}

static int
dissect_dpaux_from_sink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 cmd = tvb_get_bits8(tvb, 2, 2);
    guint8 len = (tvb_reported_length(tvb) > 1) ? tvb_reported_length(tvb) -1 : 0;
    conversation_t *conversation = NULL;
    struct dpaux_transaction *transaction = NULL;
    proto_item *ti;

    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
            CONVERSATION_NONE, pinfo->srcport, pinfo->destport, 0);
    if (conversation)
        transaction = (struct dpaux_transaction*)conversation_get_proto_data(
            conversation, proto_dpaux);

    if (transaction) {
        proto_tree_add_uint(tree, hf_dpaux_transaction_type, tvb, 0, 0,
                            transaction->is_native ? DPAUX_TRANSACTION_NATIVE :
                            DPAUX_TRANSACTION_I2C_OVER_AUX);
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    transaction->is_native ? "Native" : "I2C-over-AUX");
    } else {
        proto_tree_add_uint(tree, hf_dpaux_transaction_type, tvb, 0, 0, DPAUX_TRANSACTION_N_A);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "N/A");
    }

    switch (cmd) {
    case DPAUX_REPLY_CODE_ACK:
        col_set_str(pinfo->cinfo, COL_INFO, "ACK");
        break;
    case DPAUX_REPLY_CODE_NACK:
    case DPAUX_REPLY_CODE_I2C_NACK:
        col_set_str(pinfo->cinfo, COL_INFO, "NACK");
        break;
    case DPAUX_REPLY_CODE_DEFER:
    case DPAUX_REPLY_CODE_I2C_DEFER:
        col_set_str(pinfo->cinfo, COL_INFO, "DEFER");
        break;
    };

    proto_tree_add_uint(tree, hf_dpaux_reply_cmd, tvb, 0, 1, cmd);

    if (len) {
        if (transaction) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " with %u byte%s FROM 0x%05x",
                            len, len > 1 ? "s" : "", transaction->addr);
            proto_tree_add_uint(tree, hf_dpaux_addr, tvb, 0, 3, transaction->addr);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " with %u byte%s", len,
                            len > 1 ? "s" : "");
        }
        proto_tree_add_uint(tree, hf_dpaux_len, tvb, 3, 1, len);
        proto_tree_add_item(tree, hf_dpaux_data, tvb, 1, len, ENC_NA);

        if (transaction && transaction->is_native) {
            unsigned int k;

            for (k = 0; k < len;) {
                proto_tree *register_tree;
                int res;

                ti = proto_tree_add_uint_format(tree, hf_dpaux_reg_addr,
                                                tvb, k + 1, 1,
                                                transaction->addr + k,
                                                "DPCD 0x%05x: 0x%02x",
                                                transaction->addr + k,
                                                tvb_get_guint8(tvb, k + 1));
                register_tree = proto_item_add_subtree(ti, ett_register);

                res = dissect_dpaux_register(tvb, pinfo, register_tree, k + 1,
                                             transaction->addr + k);

                k += (res > 0) ? res : 1;
            }
        }
    }

    return 0;
}

static int
dissect_dpaux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *dpaux_tree;
    gboolean from_source = FALSE;
    struct dpaux_info *dpaux_info = (struct dpaux_info*)data;

    if (dpaux_info != NULL)
        from_source = dpaux_info->from_source;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "dpaux");
    col_set_str(pinfo->cinfo, COL_INFO, "DisplayPort AUX channel");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");

    if (from_source)
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DP-Source");
    else
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DP-Sink");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dpaux, tvb, 0, -1, ENC_NA);
    dpaux_tree = proto_item_add_subtree(ti, ett_dpaux);

    if (from_source)
        dissect_dpaux_from_source(tvb, pinfo, dpaux_tree);
    else
        dissect_dpaux_from_sink(tvb, pinfo, dpaux_tree);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_dpaux(void)
{
    static const value_string convert_transaction_type[] = {
        { DPAUX_TRANSACTION_NATIVE, "Native" },
        { DPAUX_TRANSACTION_I2C_OVER_AUX, "I2C-over-AUX" },
        { DPAUX_TRANSACTION_N_A, "N/A," },
        { 0, NULL }
    };

    static const value_string convert_native_req_cmd[] = {
        { 0, "Write" },
        { 1, "Read" },
        { 0, NULL }
    };

    static const value_string convert_i2c_req_cmd[] = {
        { 0, "Write" },
        { 1, "Read" },
        { 2, "Write_Status_Update_Request" },
        { 0, NULL }
    };

    static const value_string convert_reply_cmd[] = {
        { 0, "AUX ACK" },
        { 1, "AUX NACK" },
        { 2, "AUX DEFER" },
        { 1 << 2, "I2C NACK" },
        { 2 << 2, "I2C DEFER" },
        { 0, NULL }
    };

    static const value_string convert_link_rate[] = {
        { 0x06, "1.62Gbps/lane" },
        { 0x0a, "2.7Gbps/lane" },
        { 0x14, "5.4Gbps/lane" },
        { 0x1e, "8.1Gbps/lane" },
        { 0, NULL }
    };

    static const value_string convert_downspread[] = {
        { 0x00, "none" },
        { 0x01, "up to 0.5%" },
        { 0, NULL }
    };

    static const value_string convert_norp[] = {
        { 0x00, "One receiver port" },
        { 0x01, "Two or more receiver ports" },
        { 0, NULL }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dpaux,
        &ett_register,
    };

    static hf_register_info hf[] = {
        { &hf_dpaux_transaction_type, { "Transaction type", "dpaux.transaction_type", FT_UINT8, BASE_DEC, VALS(convert_transaction_type), 0, NULL, HFILL } },
        { &hf_dpaux_native_req_cmd, { "Native Request Command", "dpaux.native_req_cmd", FT_UINT8, BASE_DEC, VALS(convert_native_req_cmd), 0, NULL, HFILL } },
        { &hf_dpaux_i2c_req_cmd, { "I2C over AUX Request Command", "dpaux.native_i2c_req_cmd", FT_UINT8, BASE_DEC, VALS(convert_i2c_req_cmd), 0, NULL, HFILL } },
        { &hf_dpaux_reply_cmd, { "Reply Command", "dpaux.reply_cmd", FT_UINT8, BASE_DEC, VALS(convert_reply_cmd), 0, NULL, HFILL } },
        { &hf_dpaux_mot, { "MOT (Middle-of-Transaction)", "dpaux.mot", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dpaux_addr, { "Address", "dpaux.addr", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dpaux_len, { "Data Length", "dpaux.len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dpaux_data, { "Data", "dpaux.data", FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
        { &hf_dpaux_reg_addr, { "DPCD", "dpaux.reg", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_00000, { "DPCD_REV", "dpaux." "00000", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_00000_MINOR, { "MINOR", "dpaux." "00000" "_" "MINOR", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL } },
        { &hf_00000_MAJOR, { "MAJOR", "dpaux." "00000" "_" "MAJOR", FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL } },

        { &hf_00001, { "MAX_LINK_RATE", "dpaux." "00001", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_00001_MAX_LINK_RATE, { "MAX_LINK_RATE", "dpaux." "00001" "_" "MAX_LINK_RATE", FT_UINT8, BASE_HEX, VALS(convert_link_rate), 0xff, NULL, HFILL } },

        { &hf_00002, { "MAX_LANE_COUNT", "dpaux." "00002", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_00002_MAX_LANE_COUNT, { "MAX_LANE_COUNT", "dpaux." "00002" "_" "MAX_LANE_COUNT", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
        { &hf_00002_POST_LT_ADJ_REQ_SUPPORTED, { "POST_LT_ADJ_REQ_SUPPORTED", "dpaux." "00002" "_" "POST_LT_ADJ_REQ_SUPPORTED", FT_BOOLEAN, 8, NULL, 1<<5, NULL, HFILL } },
        { &hf_00002_TPS3_SUPPORTED, { "TPS3_SUPPORTED", "dpaux." "00002" "_" "TPS3_SUPPORTED", FT_BOOLEAN, 8, NULL, 1<<6, NULL, HFILL } },
        { &hf_00002_ENHANCED_FRAME_CAP, { "ENHANCED_FRAME_CAP", "dpaux." "00002" "_" "ENHANCED_FRAME_CAP", FT_BOOLEAN, 8, NULL, 1<<7, NULL, HFILL } },

        { &hf_00003, { "MAX_DOWNSPREAD", "dpaux." "00003", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_00003_MAX_DOWNSPREAD, { "MAX_DOWNSPREAD", "dpaux." "00003" "_" "MAX_DOWNSPREAD", FT_UINT8, BASE_DEC, VALS(convert_downspread), 0x01, NULL, HFILL } },
        { &hf_00003_NO_AUX_TRANSACTION_LINK_TRAINING, { "NO_AUX_TRANSACTION_LINK_TRAINING", "dpaux." "00003" "_" "NO_AUX_TRANSACTION_LINK_TRAINING", FT_BOOLEAN, 8, NULL, 1<<6, NULL, HFILL } },
        { &hf_00003_TPS4_SUPPORTED, { "TPS4_SUPPORTED", "dpaux." "00003" "_" "TPS4_SUPPORTED", FT_BOOLEAN, 8, NULL, 1<<7, NULL, HFILL } },

        { &hf_00004, { "NORP & DP_PWR_VOLTAGE_CAP", "dpaux." "00004", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_00004_NORP, { "NORP", "dpaux." "00004" "_" "NORP", FT_UINT8, BASE_DEC, convert_norp, 0x01, NULL, HFILL } },
        { &hf_00004_5V_DP_PWR_CAP, { "5V_DP_PWR_CAP", "dpaux." "00004" "_" "5V_DP_PWR_CAP", FT_BOOLEAN, 8, NULL, 1<<5, NULL, HFILL } },
        { &hf_00004_12V_DP_PWR_CAP, { "12V_DP_PWR_CAP", "dpaux." "00004" "_" "12V_DP_PWR_CAP", FT_BOOLEAN, 8, NULL, 1<<6, NULL, HFILL } },
        { &hf_00004_18V_DP_PWR_CAP, { "18V_DP_PWR_CAP", "dpaux." "00004" "_" "18V_DP_PWR_CAP", FT_BOOLEAN, 8, NULL, 1<<7, NULL, HFILL } },
    };

    /* Register the protocol name and description */
    proto_dpaux = proto_register_protocol("DisplayPort AUX-Channel", "DPAUX", "dpaux");
    register_dissector("dpaux", dissect_dpaux, proto_dpaux);

    proto_register_field_array(proto_dpaux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
